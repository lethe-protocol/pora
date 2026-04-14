use anyhow::{bail, Context, Result};
use serde_json::{json, Value};

use crate::abi;
use crate::output;

/// Sapphire RPC limit for eth_getLogs block range.
const MAX_LOG_RANGE: u64 = 100;

/// Split a block range into chunks respecting the RPC limit.
// checks: from <= to
// effects: none
// returns: Vec of (from, to) pairs, each spanning <= MAX_LOG_RANGE blocks
pub fn chunk_block_range(from: u64, to: u64) -> Vec<(u64, u64)> {
    let mut chunks = Vec::new();
    let mut start = from;
    while start <= to {
        let end = (start + MAX_LOG_RANGE - 1).min(to);
        chunks.push((start, end));
        start = end + 1;
    }
    chunks
}

/// JSON-RPC client for Ethereum/Sapphire read operations (getLogs, call, blockNumber).
// WHY: separate from contract.rs which handles write-path (tx signing).
//      This module serves the read-only streaming commands (watch, performer start).
pub struct RpcClient {
    url: String,
    client: reqwest::Client,
}

impl RpcClient {
    pub fn new(url: &str) -> Self {
        Self {
            url: url.to_string(),
            client: reqwest::Client::new(),
        }
    }

    async fn call(&self, method: &str, params: Value) -> Result<Value> {
        let body = json!({
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
            "id": 1
        });
        let resp = self
            .client
            .post(&self.url)
            .json(&body)
            .send()
            .await
            .context("RPC transport error")?;
        let json: Value = resp.json().await.context("RPC response parse error")?;
        if let Some(err) = json.get("error") {
            bail!("RPC node error: {}", err);
        }
        json.get("result")
            .cloned()
            .context("missing result field in RPC response")
    }

    /// Execute a read-only contract call.
    pub async fn eth_call(&self, to: &str, data: &str) -> Result<String> {
        let result = self
            .call("eth_call", json!([{"to": to, "data": data}, "latest"]))
            .await?;
        result
            .as_str()
            .map(|s| s.to_string())
            .context("eth_call returned non-string")
    }

    /// Fetch event logs matching a filter.
    pub async fn eth_get_logs(
        &self,
        address: &str,
        topics: &[Option<&str>],
        from_block: &str,
        to_block: &str,
    ) -> Result<Vec<Value>> {
        let topics_json: Vec<Value> = topics
            .iter()
            .map(|t| match t {
                Some(s) => Value::String((*s).to_string()),
                None => Value::Null,
            })
            .collect();
        let filter = json!({
            "address": address,
            "topics": topics_json,
            "fromBlock": from_block,
            "toBlock": to_block,
        });
        let result = self.call("eth_getLogs", json!([filter])).await?;
        result
            .as_array()
            .cloned()
            .context("eth_getLogs returned non-array")
    }

    /// Fetch logs across a large block range by chunking into MAX_LOG_RANGE batches.
    /// Returns all logs combined from all chunks.
    // checks: from_block <= to_block
    // effects: none (read-only RPC calls)
    // returns: combined Vec of log entries from all chunks
    // WHY: Sapphire limits eth_getLogs to 100 rounds (blocks) per request.
    //      --once mode looks back 50k blocks, which would always fail without chunking.
    pub async fn eth_get_logs_chunked(
        &self,
        address: &str,
        topics: &[Option<&str>],
        from_block: u64,
        to_block: u64,
    ) -> Result<Vec<Value>> {
        let mut all_logs = Vec::new();
        for (chunk_from, chunk_to) in chunk_block_range(from_block, to_block) {
            let from_hex = format!("0x{:x}", chunk_from);
            let to_hex = format!("0x{:x}", chunk_to);
            let logs = self.eth_get_logs(address, topics, &from_hex, &to_hex).await?;
            all_logs.extend(logs);
        }
        Ok(all_logs)
    }

    /// Get the latest block number.
    pub async fn eth_block_number(&self) -> Result<u64> {
        let result = self.call("eth_blockNumber", json!([])).await?;
        let hex = result.as_str().context("blockNumber non-string")?;
        u64::from_str_radix(hex.trim_start_matches("0x"), 16)
            .context("invalid blockNumber hex")
    }

    /// Fetch logs, decode each with abi::decode_event, and emit as NDJSON.
    // checks: address is a valid 0x-prefixed hex address
    // effects: writes NDJSON events to stdout for each decoded log; emits error event on failure
    // returns: number of events successfully emitted, or 0 on RPC error
    // WHY: returning usize lets --once callers distinguish "no events found" (legitimate empty
    //      range) from "RPC failed" without propagating errors that would break continuous polling.
    //      Continuous polling callers discard the count; --once callers sum it to detect all-fail.
    pub async fn fetch_and_emit_logs(
        &self,
        address: &str,
        topics: &[Option<&str>],
        from_block: u64,
        to_block: u64,
        event_name: &str,
    ) -> usize {
        match self.eth_get_logs_chunked(address, topics, from_block, to_block).await {
            Ok(logs) => {
                for log in &logs {
                    output::ndjson_event(abi::decode_event(event_name, log));
                }
                logs.len()
            }
            Err(e) => {
                output::ndjson_event(json!({
                    "event": "error",
                    "message": format!("getLogs({}): {}", event_name, e),
                }));
                0
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chunk_block_range() {
        assert_eq!(chunk_block_range(0, 250), vec![(0, 99), (100, 199), (200, 250)]);
        assert_eq!(chunk_block_range(100, 150), vec![(100, 150)]);
        assert_eq!(chunk_block_range(0, 99), vec![(0, 99)]);
        assert_eq!(chunk_block_range(5, 5), vec![(5, 5)]);
    }
}
