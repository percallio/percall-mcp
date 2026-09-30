---
name: percall
description: Keyless pay-per-call data on Arc mainnet (chainId 5042) for agents — JSON-RPC, USDC flows, token audits, wallet reports, whale & deployment feeds. No API key; the agent pays per call in USDC via x402. Use when you need Arc on-chain data and don't want to manage RPC keys, rate limits, or accounts.
---

# percall — pay-per-call Arc mainnet data for agents

percall (`https://api.percall.io`) is a keyless x402 gateway to Arc mainnet (chainId 5042, Circle's stablecoin chain, USDC = native gas, 1s blocks). The agent pays per call in USDC with a wallet — no API key, no account, no approval. Every call is self-settled on-chain (EIP-3009 TWA, gasless for both sides).

## When to use

- You need Arc mainnet JSON-RPC (`eth_*`) and want to avoid RPC key/rate-limit management.
- You're monitoring wallets or tokens on Arc (USDC flows, new contract deployments, top flow addresses).
- You need a one-call token hygiene report or an address risk/flow profile instead of assembling 8+ RPC round-trips.
- Free alternatives exist but require keys, projects, approvals, or are flaky on this new chain.

Do NOT use for other chains (it's Arc-only), or when you already hold a cheap dedicated Arc RPC key for very high volume (the prepaid pack is still the better deal then — see below).

## Setup (MCP, recommended)

percall ships a stdio MCP server (13 tools) that handles the x402 payment dance automatically. The only requirement: an EOA wallet holding USDC on Arc (gasless — USDC is the native gas token).

1. Create/import an EOA (any tool: cast, web3, etc.). Fund it with USDC on Arc (chainId 5042).
2. Register the MCP server with your agent host (Claude Desktop / Claude Code / any MCP client):

```json
{
  "mcpServers": {
    "percall": {
      "command": "python3",
      "args": ["/path/to/percall_mcp.py"],
      "env": {
        "X402_MCP_KEY": "0x<wallet private key>",
        "X402_MCP_URL": "https://api.percall.io"
      }
    }
  }
}
```

3. Tools available: `arc_block_number`, `arc_call`, `arc_get_logs`, `arc_get_balance`, `arc_get_receipt`, `arc_get_block`, `arc_early_watch`, `arc_alerts`, `arc_audit`, `arc_whales`, `arc_deployments`, `arc_wallet_report`, `arc_token_report`.

## Paying

- Each tool call: the server sends the request, receives an HTTP 402 challenge, signs a USDC `transferWithAuthorization` (EIP-712), and retries with the payment header. You (the agent) don't see the dance; the tool returns the result.
- **Free tier**: 50 free calls/day per wallet (`X-From` header, handled by the MCP server). No wallet needed to start testing.
- **Prepaid**: one `POST /topup` TWA of $1–$100 buys perpetual off-chain credits; the **weekly pack is $5 = 1,666 standard calls** (7-day TTL, stackable) — best margin for steady usage.
- Machine-readable price list: `GET https://api.percall.io/plans`. Discovery manifest: `GET https://api.percall.io/x402.json`.

## Endpoints & pricing (USDC per call)

| Endpoint | Price | What you get |
|---|---|---|
| `POST /arc` (JSON-RPC) | 0.002–0.005 by method; batch per-item capped 0.05 | raw Arc RPC |
| `GET /early?address=&window=` | 0.01 | latest block + txs; optional window watch |
| `GET /alerts?address=&window=` | 0.005 | address USDC in/out flows + balance (sub-second, polling-friendly) |
| `GET /audit?address=` | 0.02 | token hygiene: metadata, owner, proxy, 1h volume, flags, verdict |
| `GET /whales?window=` | 0.005 | top 20 USDC flow addresses (bridge/DEX/whale detection) |
| `GET /deployments?window=` | 0.01 | new contract deployments in window (early token discovery) |
| `GET /wallet-report?address=&window=` | 0.05 | address risk/flow profile: balance + flows + top-5 counterparties (contract-checked) + flags — one call replaces ~8 RPC round-trips |
| `GET /token-report?address=` | 0.05 | full token report: audit + top-10 recipients + flow concentration |

## Pitfalls

- Budget caps: default x402 client caps are ~$0.05/call — every percall endpoint fits under it.
- Payment failures are machine-readable: 402 bodies carry `invalid_payment_*` error codes (`expired`, `signature`, `amount`, `payto`, `format`, ...) — switch on them to self-heal (re-sign, refresh window, top up).
- Data endpoints served from rolling buffers have a few seconds of lag by design (sub-second responses); `/stats` exposes buffer state (`flowbuf`, `deploybuf`).
- Arc specifics: USDC precompile `0x3600...0000`, baseFee pinned 20 Gwei (USDC gas), 1s blocks, empty mempool (use `/deployments` for new-contract signals).
- Key hygiene: the wallet only signs TWA transfers of the exact per-call amount — it never authorizes unlimited spend.

## Links

- Site: https://percall.io · llms.txt: https://percall.io/llms.txt
- OpenAPI: https://api.percall.io/openapi.json · Plans: https://api.percall.io/plans · Manifest: https://api.percall.io/x402.json
- MCP repo: https://github.com/percallio/percall-mcp · X: @percalliox402
