# percall-mcp

**One-line install. Your AI agent gets Arc (chainId 5042) block data — and pays per call in USDC. No API key.**

[percall](https://percallio.github.io/) is a pay-per-call JSON-RPC endpoint for AI agents on early chains. `percall-mcp` wraps it as a zero-dependency MCP (Model Context Protocol) server: drop it into Claude Desktop, Cursor, or any MCP client and the agent gets on-chain tools that bill themselves.

```
your agent  →  percall-mcp  →  https://api.percall.io/arc/  (x402 402 → USDC payment → 200 + data)
```

## Install

Requires Python 3.8+ (stdlib only, no pip). You need a wallet with a little **Arc USDC** for the free tier + first calls, and prepaid credits for steady use.

**Claude Desktop** (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "percall": {
      "command": "python3",
      "args": ["/path/to/percall_mcp.py"],
      "env": {
        "X402_MCP_URL": "https://api.percall.io/arc/",
        "X402_MCP_KEY": "0xyour_wallet_private_key"
      }
    }
  }
}
```

**Any MCP client** (stdio transport): same command/args/env. The key only ever sees the x402 payment requests this server makes — it is never sent anywhere else.

## Tools

| Tool | What it does | Cost (USDC) |
|---|---|---|
| `chain_id` | Arc chain ID (5042) | free |
| `block_number` | latest block | 0.002 |
| `eth_call` | call a contract / read state | 0.003 |
| `get_transaction_receipt` | tx receipt + status | 0.003 |
| `get_logs` | event logs by address/topics/block range | 0.005 |
| `balance` | native (USDC-gas) + ERC-20 balance | 0.002 |
| `rpc_raw` | any JSON-RPC method | 0.002–0.005 by tier |

Payment is automatic: the server receives the `402 Payment Required` challenge, signs the `transferWithAuthorization` (EIP-3009) with your key, and retries. You (or the agent) never touch payment plumbing.

## Pricing & free tier

- **Free**: 50 calls/day per wallet (identify with `X-From` — the MCP server sets it from the key's address).
- **Per call**: light `0.002` · standard `0.003` · heavy (getlogs/trace) `0.005` USDC.
- **Prepaid credits** (`POST /topup`): one USDC authorization per week instead of one on-chain tx per call — settlement gas per call drops ~92%. Top up via the site or curl:

```bash
curl -X POST https://api.percall.io/topup \
  -H "X-From: 0xYOUR" \
  -d '{"amount_units": 5000000}'   # 5.0 USDC → 2,500,000 standard calls
```

## How it pays (x402)

percall is a **self-facilitated x402 endpoint**: the 402 response carries an exact-amount USDC authorization spec; the buyer signs it; the server verifies (ecrecover) and settles to a public vault on Arc — native USDC as gas, no bridging, no middleman custody. Full docs: [x402](https://github.com/coinbase/x402).

## Status

- ✅ **Arc** (chainId 5042) live
- 🔜 **MegaETH** (chainId 4326) — same server, different `X402_MCP_URL`
- 🔜 data endpoints: `/alerts` (new deployments), `/early` (first-token context), `/audit-lite` (bytecode quick-check)

## Links

- Site: https://percallio.github.io/
- Live stats: `GET /stats` on the API host
- GitHub: https://github.com/percallio · X: https://x.com/percalliox402

## License

MIT
