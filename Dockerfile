FROM python:3.12-slim

# Zero-dependency stdio MCP server (stdlib + local pure-python crypto modules)
WORKDIR /app
COPY percall_mcp.py cctp_transfer.py keccak.py ./

# X402_MCP_KEY: wallet private key holding Arc USDC (0x...)
# X402_MCP_URL: optional endpoint override (default https://api.percall.io)
ENV PYTHONUNBUFFERED=1
ENTRYPOINT ["python", "-u", "percall_mcp.py"]
