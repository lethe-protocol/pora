/// MCP resource definitions.
// WHY: resources provide read-only data entities that agents can reference
//      without invoking tools. Config and market overview are always useful context.

use serde_json::{json, Value};

pub fn list_resources() -> Value {
    json!({
        "resources": [
            {
                "uri": "pora://config",
                "name": "pora config",
                "description": "Current pora configuration: RPC endpoint, contract address, wallet status",
                "mimeType": "application/json"
            },
            {
                "uri": "pora://market/overview",
                "name": "market overview",
                "description": "Aggregate market state: active bounty count, total pool size, audit count",
                "mimeType": "application/json"
            }
        ]
    })
}

/// Read a specific resource by URI.
// checks: uri is a known resource
// effects: may make RPC calls for market data
// returns: resource content
pub async fn read_resource(params: &Value) -> anyhow::Result<Value> {
    let uri = params.get("uri").and_then(|u| u.as_str()).unwrap_or("");

    match uri {
        "pora://config" => read_config(),
        "pora://market/overview" => read_market_overview().await,
        _ => Err(anyhow::anyhow!("Unknown resource: {}", uri)),
    }
}

fn read_config() -> anyhow::Result<Value> {
    let cfg = crate::config::load_config();
    let wallet_status = if crate::config::get_private_key().is_ok() {
        "configured"
    } else {
        "missing"
    };
    let wallet_address = crate::config::get_private_key()
        .ok()
        .and_then(|k| crate::crypto::private_key_to_address(&k).ok());

    Ok(json!({
        "contents": [{
            "uri": "pora://config",
            "mimeType": "application/json",
            "text": serde_json::to_string_pretty(&json!({
                "rpc_url": cfg.rpc_url,
                "contract": cfg.contract,
                "wallet": {
                    "status": wallet_status,
                    "address": wallet_address,
                },
                "reputation_registry": cfg.reputation_registry,
                "gateway_url": cfg.gateway_url,
            }))?
        }]
    }))
}

async fn read_market_overview() -> anyhow::Result<Value> {
    let market = crate::contract::get_market_status().await
        .map_err(|e| anyhow::anyhow!("Failed to fetch market status: {}", e))?;

    // Also get the bounty list for total pool calculation
    let bounties = crate::contract::list_bounties(true).await.unwrap_or_default();
    let total_pool: u128 = bounties.iter()
        .filter_map(|b| b.amount_wei.parse::<u128>().ok())
        .sum();
    let total_rose = total_pool as f64 / 1e18;

    Ok(json!({
        "contents": [{
            "uri": "pora://market/overview",
            "mimeType": "application/json",
            "text": serde_json::to_string_pretty(&json!({
                "bounty_count": market.bounty_count,
                "audit_count": market.audit_count,
                "active_bounties": bounties.len(),
                "total_pool_wei": total_pool.to_string(),
                "total_pool_rose": format!("{:.4}", total_rose),
                "network": "Sapphire Testnet",
            }))?
        }]
    }))
}
