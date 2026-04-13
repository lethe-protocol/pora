"""pora MCP server — market interface for AI agents.

Exposes pora SDK functions as HTTP endpoints that AI agents can call.
Run with: pora mcp --port 8900

# WHY: AI agents (Hermes, OpenClaw) need a standard interface to interact
#      with the security audit market. HTTP is universally supported and
#      requires no special client libraries beyond basic HTTP support.
# SECURITY: the server binds to localhost only by default. For remote access,
#           use --host 0.0.0.0 with appropriate network security.
# TRUST: no authentication on this server — caller is assumed to be a local
#        agent. If exposed remotely, add auth at the network layer.
"""

from __future__ import annotations

import json
import traceback
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any

from pora.client import PoraClient

# ── Tool registry ──

TOOLS = [
    {
        "name": "market_status",
        "description": "Get current market statistics: bounty count, audit count, and payout policy.",
        "parameters": {},
    },
    {
        "name": "list_open_bounties",
        "description": "List all open bounties available for audit.",
        "parameters": {},
    },
    {
        "name": "get_bounty",
        "description": "Get details of a specific bounty by ID.",
        "parameters": {
            "bounty_id": {"type": "integer", "required": True, "description": "On-chain bounty ID"},
        },
    },
    {
        "name": "get_audit",
        "description": "Get details of a specific audit result by ID.",
        "parameters": {
            "audit_id": {"type": "integer", "required": True, "description": "On-chain audit ID"},
        },
    },
    {
        "name": "create_bounty",
        "description": (
            "Create a new security audit bounty for a GitHub repository. "
            "Combines createBounty + setRepoInfo + setAuditConfig in one call."
        ),
        "parameters": {
            "repo": {"type": "string", "required": True, "description": "GitHub repo in owner/repo format"},
            "amount_rose": {"type": "number", "default": 1.0, "description": "ROSE to deposit"},
            "duration_days": {"type": "integer", "default": 7, "description": "Bounty duration in days"},
            "standing": {"type": "boolean", "default": True, "description": "Repeating bounty"},
            "installation_id": {"type": "integer", "required": True, "description": "GitHub App installation ID"},
            "trigger": {"type": "string", "default": "on-change", "description": "Trigger mode: on-change, periodic, both"},
            "period_days": {"type": "integer", "default": 0, "description": "Days between periodic audits"},
        },
    },
    {
        "name": "fund_bounty",
        "description": "Top up a standing bounty with additional ROSE.",
        "parameters": {
            "bounty_id": {"type": "integer", "required": True, "description": "Bounty to fund"},
            "amount_rose": {"type": "number", "required": True, "description": "ROSE amount to add"},
        },
    },
    {
        "name": "cancel_bounty",
        "description": "Cancel a bounty and reclaim remaining funds.",
        "parameters": {
            "bounty_id": {"type": "integer", "required": True, "description": "Bounty to cancel"},
        },
    },
    {
        "name": "claim_payout",
        "description": "Claim unlocked bonus payout for an audit after the challenge window.",
        "parameters": {
            "audit_id": {"type": "integer", "required": True, "description": "Audit ID to claim payout for"},
        },
    },
    {
        "name": "generate_keypair",
        "description": "Generate an X25519 delivery keypair for receiving encrypted audit reports.",
        "parameters": {
            "output_dir": {"type": "string", "default": ".", "description": "Directory to write key files"},
        },
    },
]


# ── Serialisation helpers ──

def _bounty_dict(client: PoraClient, b) -> dict:
    """Convert Bounty dataclass to JSON-serialisable dict.

    # WHY: bytes fields need hex encoding; amounts should be human-readable ROSE
    """
    states = {0: "Open", 1: "Completed", 2: "Cancelled"}
    return {
        "id": b.id,
        "requester": b.requester,
        "amount_rose": float(client.w3.from_wei(b.amount, "ether")),
        "amount_wei": b.amount,
        "repo_hash": "0x" + b.repo_hash.hex(),
        "created_at": b.created_at,
        "deadline": b.deadline,
        "standing": b.standing,
        "state": states.get(b.state, str(b.state)),
        "audit_count": b.audit_count,
    }


def _audit_dict(client: PoraClient, a) -> dict:
    """Convert Audit dataclass to JSON-serialisable dict."""
    states = {0: "Pending", 1: "Verified", 2: "Disputed"}
    results = {0: "FindingsFound", 1: "NoFindings"}
    return {
        "id": a.id,
        "bounty_id": a.bounty_id,
        "commit_hash": "0x" + a.commit_hash.hex(),
        "poe_hash": "0x" + a.poe_hash.hex(),
        "payout_rose": float(client.w3.from_wei(a.payout, "ether")),
        "payout_wei": a.payout,
        "completed_at": a.completed_at,
        "state": states.get(a.state, str(a.state)),
        "result": results.get(a.result, str(a.result)),
        "finding_count": a.finding_count,
    }


# ── Request handler ──

class McpHandler(BaseHTTPRequestHandler):
    """HTTP handler for the pora MCP server.

    # WHY: BaseHTTPRequestHandler is stdlib — zero extra dependencies.
    #      The class attribute pattern allows injecting the client from start_server.
    """

    client: PoraClient = None  # set by start_server before first request

    def log_message(self, fmt: str, *args: Any) -> None:
        # Use standard print so output goes to the console running `pora mcp`
        print(f"[pora mcp] {self.address_string()} {fmt % args}")

    def _json_response(self, data: Any, status: int = 200) -> None:
        body = json.dumps(data, indent=2).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _error(self, message: str, status: int = 400) -> None:
        self._json_response({"error": message}, status)

    def _read_body(self) -> dict:
        length = int(self.headers.get("Content-Length", 0))
        if length == 0:
            return {}
        return json.loads(self.rfile.read(length))

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/tools":
            self._json_response(TOOLS)
        elif self.path == "/health":
            self._json_response({"status": "ok"})
        else:
            self._error(f"Unknown path: {self.path}", 404)

    def do_POST(self) -> None:  # noqa: N802
        if not self.path.startswith("/tools/"):
            self._error(f"Unknown path: {self.path}", 404)
            return

        tool_name = self.path[len("/tools/"):]

        try:
            body = self._read_body()
        except (json.JSONDecodeError, ValueError) as exc:
            self._error(f"Invalid JSON body: {exc}")
            return

        try:
            result = self._dispatch(tool_name, body)
            self._json_response(result)
        except KeyError as exc:
            self._error(f"Missing required parameter: {exc}")
        except ValueError as exc:
            self._error(str(exc))
        except Exception as exc:  # noqa: BLE001
            traceback.print_exc()
            self._error(str(exc), 500)

    def _dispatch(self, tool: str, params: dict) -> Any:
        """Route a tool call to the appropriate SDK method.

        # effects: may send blockchain transactions for write operations
        # returns: JSON-serialisable result dict
        """
        client = McpHandler.client

        if tool == "market_status":
            bc = client.bounty_count()
            ac = client.audit_count()
            pp = client.payout_policy()
            return {
                "bounty_count": bc,
                "audit_count": ac,
                "contract": client.contract_address,
                "network": client.rpc_url,
                "policy": {
                    "standing_percent_bps": pp.standing_percent_bps,
                    "minimum_payout_rose": float(client.w3.from_wei(pp.minimum_payout, "ether")),
                    "execution_fee_bps": pp.execution_fee_bps,
                    "finding_bonus_bps": pp.finding_bonus_bps,
                    "patch_bonus_bps": pp.patch_bonus_bps,
                    "regression_bonus_bps": pp.regression_bonus_bps,
                },
            }

        elif tool == "list_open_bounties":
            bounties = client.list_bounties(only_open=True)
            return [_bounty_dict(client, b) for b in bounties]

        elif tool == "get_bounty":
            bounty_id = int(params["bounty_id"])
            b = client.get_bounty(bounty_id)
            return _bounty_dict(client, b)

        elif tool == "get_audit":
            audit_id = int(params["audit_id"])
            a = client.get_audit(audit_id)
            d = client.get_delivery(audit_id)
            s = client.get_settlement(audit_id)
            result = _audit_dict(client, a)
            delivery_statuses = {0: "None", 1: "Ready", 2: "Retrieved", 3: "Failed"}
            result["delivery_status"] = delivery_statuses.get(d.delivery_status, str(d.delivery_status))
            result["settlement"] = {
                "performer": s["performer"],
                "execution_fee_rose": float(client.w3.from_wei(s["execution_fee"], "ether")),
                "finding_bonus_rose": float(client.w3.from_wei(s["finding_bonus"], "ether")),
                "patch_bonus_rose": float(client.w3.from_wei(s["patch_bonus"], "ether")),
                "regression_bonus_rose": float(client.w3.from_wei(s["regression_bonus"], "ether")),
                "claimed_rose": float(client.w3.from_wei(s["claimed_amount"], "ether")),
                "locked_until": s["locked_until"],
                "dispute_status": s["dispute_status"],
            }
            return result

        elif tool == "create_bounty":
            repo = params["repo"]
            amount_rose = float(params.get("amount_rose", 1.0))
            duration_days = int(params.get("duration_days", 7))
            standing = bool(params.get("standing", True))
            installation_id = int(params["installation_id"])
            trigger = str(params.get("trigger", "on-change"))
            period_days = int(params.get("period_days", 0))

            bounty_id = client.create_bounty(
                repo,
                amount_rose=amount_rose,
                duration_days=duration_days,
                standing=standing,
            )
            tx_repo = client.set_repo_info(bounty_id, repo=repo, installation_id=installation_id)
            tx_cfg = client.set_audit_config(bounty_id, trigger=trigger, period_days=period_days)
            return {
                "bounty_id": bounty_id,
                "tx_repo_info": tx_repo,
                "tx_audit_config": tx_cfg,
            }

        elif tool == "fund_bounty":
            bounty_id = int(params["bounty_id"])
            amount_rose = float(params["amount_rose"])
            tx = client.fund_bounty(bounty_id, amount_rose=amount_rose)
            return {"tx_hash": tx, "bounty_id": bounty_id}

        elif tool == "cancel_bounty":
            bounty_id = int(params["bounty_id"])
            tx = client.cancel_bounty(bounty_id)
            return {"tx_hash": tx, "bounty_id": bounty_id}

        elif tool == "claim_payout":
            audit_id = int(params["audit_id"])
            tx = client.claim_payout(audit_id)
            return {"tx_hash": tx, "audit_id": audit_id}

        elif tool == "generate_keypair":
            output_dir = str(params.get("output_dir", "."))
            priv_path, pub_hex = PoraClient.generate_keypair(output_dir)
            return {"private_key_path": priv_path, "public_key_hex": pub_hex}

        else:
            raise ValueError(f"Unknown tool: {tool!r}. Call GET /tools for the list.")


# ── Entry point ──

def start_server(
    *,
    host: str = "127.0.0.1",
    port: int = 8900,
    private_key: str = "",
    rpc_url: str = "",
    contract_address: str = "",
    gateway_url: str = "",
) -> None:
    """Start the pora MCP HTTP server and block until interrupted.

    # checks: host and port must be valid for HTTPServer to bind
    # effects: binds TCP socket, prints startup banner, serves requests forever
    # returns: never (blocks until KeyboardInterrupt or process kill)
    #
    # WHY: a single shared PoraClient is injected via class attribute so each
    #      request handler doesn't pay the Web3 connection cost.
    """
    McpHandler.client = PoraClient(
        private_key=private_key,
        rpc_url=rpc_url,
        contract_address=contract_address,
        gateway_url=gateway_url,
    )

    server = HTTPServer((host, port), McpHandler)
    print(f"[pora mcp] listening on http://{host}:{port}")
    print(f"[pora mcp] GET  http://{host}:{port}/tools         — list tools")
    print(f"[pora mcp] GET  http://{host}:{port}/health        — health check")
    print(f"[pora mcp] POST http://{host}:{port}/tools/<name>  — call a tool")
    print(f"[pora mcp] Contract: {McpHandler.client.contract_address}")
    print(f"[pora mcp] Network:  {McpHandler.client.rpc_url}")
    print("[pora mcp] Press Ctrl+C to stop.")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[pora mcp] shutting down.")
        server.server_close()
