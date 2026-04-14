/// MCP (Model Context Protocol) server — stdio JSON-RPC transport.
// checks: stdin provides valid JSON-RPC messages
// effects: reads from stdin, writes JSON-RPC responses to stdout
// returns: runs until stdin EOF or shutdown request
//
// WHY: MCP over stdio lets AI agents (Claude Code, Claude Desktop, Cursor)
//      use pora CLI commands as tools without subprocess orchestration.
// SECURITY: inherits CLI config (wallet, RPC) — no additional auth surface.

use std::io::{self, BufRead, Write};
use serde_json::{json, Value};

mod tools;
mod resources;

/// Run the MCP stdio server loop.
// checks: none
// effects: reads stdin line-by-line, writes JSON-RPC responses to stdout
// returns: Ok(()) on EOF or shutdown
pub async fn run_server() -> anyhow::Result<()> {
    let stdin = io::stdin();
    let stdout = io::stdout();

    for line in stdin.lock().lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }

        let request: Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(_) => {
                write_response(&stdout, &json!({
                    "jsonrpc": "2.0",
                    "id": null,
                    "error": {
                        "code": -32700,
                        "message": "Parse error"
                    }
                }));
                continue;
            }
        };

        let id = request.get("id").cloned();
        let method = request.get("method").and_then(|m| m.as_str()).unwrap_or("");
        let params = request.get("params").cloned().unwrap_or(json!({}));

        // WHY: notifications (no id) don't get responses per JSON-RPC spec
        let is_notification = id.is_none();

        let result = handle_method(method, &params).await;

        if !is_notification {
            let response = match result {
                Ok(data) => json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": data
                }),
                Err((code, message)) => json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "error": {
                        "code": code,
                        "message": message
                    }
                }),
            };
            write_response(&stdout, &response);
        }
    }

    Ok(())
}

fn write_response(stdout: &io::Stdout, response: &Value) {
    let mut handle = stdout.lock();
    let _ = serde_json::to_writer(&mut handle, response);
    let _ = writeln!(handle);
    let _ = handle.flush();
}

// WHY: returns (error_code, message) tuple so the server loop doesn't
//      need fragile string matching to distinguish error types.
async fn handle_method(method: &str, params: &Value) -> Result<Value, (i32, String)> {
    match method {
        "initialize" => handle_initialize(params).map_err(|e| (-32603, format!("{}", e))),
        "notifications/initialized" => Ok(json!(null)),
        "tools/list" => Ok(tools::list_tools()),
        "tools/call" => tools::call_tool(params).await.map_err(|e| (-32603, format!("{}", e))),
        "resources/list" => Ok(resources::list_resources()),
        "resources/read" => resources::read_resource(params).await.map_err(|e| (-32603, format!("{}", e))),
        _ => Err((-32601, format!("Method not found: {}", method))),
    }
}

// checks: client sends protocol version
// effects: none
// returns: server capabilities (tools, resources)
fn handle_initialize(_params: &Value) -> anyhow::Result<Value> {
    Ok(json!({
        "protocolVersion": "2024-11-05",
        "capabilities": {
            "tools": {},
            "resources": {}
        },
        "serverInfo": {
            "name": "pora",
            "version": env!("CARGO_PKG_VERSION")
        }
    }))
}
