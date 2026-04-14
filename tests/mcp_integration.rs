/// MCP server integration test — end-to-end via stdin/stdout pipe.
// checks: pora binary is built, Sapphire testnet reachable
// effects: spawns pora mcp subprocess, sends JSON-RPC messages
// returns: verifies response structure and real bounty data

use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};

fn pora_binary() -> String {
    let path = std::env::var("PORA_BIN")
        .unwrap_or_else(|_| "target/release/pora".to_string());
    path
}

fn send_and_read(
    stdin: &mut std::process::ChildStdin,
    stdout: &mut BufReader<std::process::ChildStdout>,
    request: &str,
) -> serde_json::Value {
    writeln!(stdin, "{}", request).expect("write to stdin");
    stdin.flush().expect("flush stdin");
    let mut line = String::new();
    stdout.read_line(&mut line).expect("read from stdout");
    serde_json::from_str(&line).expect("parse JSON response")
}

#[test]
fn test_mcp_initialize_and_tools_list() {
    let mut child = Command::new(pora_binary())
        .arg("mcp")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("failed to start pora mcp");

    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());

    // Step 1: initialize
    let resp = send_and_read(
        &mut stdin,
        &mut stdout,
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05"}}"#,
    );
    assert_eq!(resp["jsonrpc"], "2.0");
    assert_eq!(resp["id"], 1);
    assert!(resp["result"]["protocolVersion"].is_string());
    assert!(resp["result"]["capabilities"]["tools"].is_object());
    assert!(resp["result"]["capabilities"]["resources"].is_object());
    assert_eq!(resp["result"]["serverInfo"]["name"], "pora");

    // Step 2: tools/list
    let resp = send_and_read(
        &mut stdin,
        &mut stdout,
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}"#,
    );
    assert_eq!(resp["id"], 2);
    let tools = resp["result"]["tools"].as_array().expect("tools is array");
    assert_eq!(tools.len(), 15);

    // Verify tool names
    let names: Vec<&str> = tools.iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    assert!(names.contains(&"pora_request_list"));
    assert!(names.contains(&"pora_request_submit"));
    assert!(names.contains(&"pora_system_doctor"));
    assert!(names.contains(&"pora_performer_status"));

    // Step 3: resources/list
    let resp = send_and_read(
        &mut stdin,
        &mut stdout,
        r#"{"jsonrpc":"2.0","id":3,"method":"resources/list","params":{}}"#,
    );
    let resources = resp["result"]["resources"].as_array().expect("resources is array");
    assert_eq!(resources.len(), 2);

    drop(stdin);
    let _ = child.wait();
}

#[test]
#[ignore] // requires network access to Sapphire testnet
fn test_mcp_tools_call_request_list() {
    let mut child = Command::new(pora_binary())
        .arg("mcp")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("failed to start pora mcp");

    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());

    // Initialize
    let _ = send_and_read(
        &mut stdin,
        &mut stdout,
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#,
    );

    // tools/call pora_request_list
    let resp = send_and_read(
        &mut stdin,
        &mut stdout,
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"pora_request_list","arguments":{}}}"#,
    );
    assert_eq!(resp["id"], 2);
    let content = resp["result"]["content"].as_array().expect("content array");
    assert!(!content.is_empty());
    assert_eq!(content[0]["type"], "text");

    // Parse the text content as JSON and verify bounty data
    let text = content[0]["text"].as_str().unwrap();
    let data: serde_json::Value = serde_json::from_str(text).expect("parse tool result");
    assert!(data["bounties"].is_array());
    assert!(data["count"].is_number());

    drop(stdin);
    let _ = child.wait();
}
