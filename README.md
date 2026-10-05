# percall-mcp

**Full agent-readable API docs: https://percall.io/llms.txt** (fetch it — endpoints, pricing, the exact 402→pay→retry dance, topup flow)

**One-line install. Your AI agent gets Arc (chainId 5042) + Base (chainId 8453) on-chain data, memecoin trending/model scores, and token USD quotes — and pays per call in USDC. No API key.**

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

## Tools (22)

**Arc RPC** (`arc_*`): `arc_block_number` 0.002 · `arc_call` 0.003 · `arc_get_transaction_receipt` 0.003 · `arc_get_logs` 0.005 · `arc_balance` 0.002 · `arc_free` (50/day, no payment).

**Base RPC** (`base_*`, chainId 8453): `base_block_number` 0.002 · `base_call` 0.003 · `base_get_transaction_receipt` 0.003 · `base_get_logs` 0.005 · `base_balance` 0.002 · `base_free` (50/day, no payment). The key needs USDC on Base for Base calls.

**Monitoring / reports (Arc)**: `arc_early_watch` 0.01 (block snapshot + optional address USDC-flow watch) · `arc_alerts` 0.005 (address USDC delta feed, 30-60s polling) · `arc_audit` 0.02 (token hygiene: owner/proxy/volume/flags/verdict) · `arc_whales` 0.005 (top USDC flow addresses) · `arc_deployments` 0.01 (new contract feed) · `arc_wallet_report` 0.05 (one-call address risk/flow profile, replaces ~8 RPC round-trips) · `arc_token_report` 0.05 (audit + top holders + concentration).

**Memecoin data (all chains)**: `token_score` 0.01 (model score S/T/rug + verdict for one token, universe = trending memecoins on solana/base/bsc/arc) · `token_price` 0.005 (live USD quote from top pool: price + 1h/6h/24h change + volume + liquidity, all chains) · `trending_memes` 0.01 (trending memecoins per chain with live model scores).

All data/report tools try the free tier first (50/day via the key's address), then pay. Payment is automatic: the server receives the `402 Payment Required` challenge, signs the `transferWithAuthorization` (EIP-3009) with your key, and retries. You (or the agent) never touch payment plumbing.

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
