# pora

**Security audit market CLI, SDK, and MCP server.**

*The passage where code enters, findings emerge, and vulnerability knowledge is destroyed.*

> Audit. Earn. Forget.

## Install

```bash
pip install pora
```

## Quick Start

### As a requester (get your code audited)

```bash
# Generate delivery keypair
pora keygen

# Create a standing bounty (1 ROSE, continuous audit)
pora bounty create owner/repo --amount 1 --installation-id 122858796

# Set up encrypted delivery
pora delivery setup 1 --key pora-delivery.pub

# Check market status
pora status

# List audits
pora audit list
```

### As an observer

```bash
# View market status
pora status

# List open bounties
pora bounty list

# View audit details
pora audit show 1
```

### As a Python SDK

```python
from pora import PoraClient

client = PoraClient(private_key="0x...")
bounty_id = client.create_bounty("owner/repo", amount_rose=1.0)
client.set_repo_info(bounty_id, repo="owner/repo", installation_id=122858796)
```

## Configuration

Environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `PORA_PRIVATE_KEY` | — | Wallet private key for transactions |
| `PORA_RPC_URL` | `https://testnet.sapphire.oasis.io` | Sapphire RPC endpoint |
| `PORA_CONTRACT` | testnet deployment | LetheMarket contract address |
| `PORA_GATEWAY_URL` | testnet gateway | Delivery gateway URL |

## Architecture

```
pora/
├── client.py      ← SDK core (PoraClient)
├── cli.py         ← CLI (click-based, wraps SDK)
├── mcp_server.py  ← MCP server (wraps SDK, for agent integration)
├── crypto.py      ← X25519 key management, delivery decryption
└── abi.json       ← LetheMarket contract ABI
```

## Mascot

**Heliopora** — the blue coral. The only octocoral that builds a massive calcium carbonate skeleton. Unique, beautiful, resilient. Like pora: a structure where life happens inside, protected from the outside world.

## Links

- [pora-market](https://github.com/heliopora/pora-market) — Protocol contracts + ROFL TEE worker
- [heliopora.github.io](https://heliopora.github.io) — Landing page

## License

MIT
