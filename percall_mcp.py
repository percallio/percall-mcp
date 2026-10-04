"""x402 MCP server — Arc RPC 工具, x402 自动付款 (stdio JSON-RPC)

Agent 接入 (Claude Desktop mcp.json):
  "x402-arc": {"command": "python3", "args": ["/root/x402_mcp.py"]}
环境变量:
  X402_MCP_KEY   付款钱包私钥 (默认 keys/tapeout_hot.json)
  X402_MCP_URL   服务端点 (默认 https://api.percall.io)
"""
import sys, json, os, time, base64

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)
try:
    import cctp_transfer as CT
except ImportError:
    try:
        sys.path.append('/root/crypto-bugs/scripts')
        import cctp_transfer as CT
    except ImportError:
        CT = None

ENDPOINT = os.environ.get('X402_MCP_URL', 'https://api.percall.io').rstrip('/')

def _load_key():
    k = os.environ.get('X402_MCP_KEY')
    if k:
        return k
    for p in (os.path.join(_HERE, 'keys', 'tapeout_hot.json'),
              '/root/crypto-bugs/data/keys/tapeout_hot.json'):
        try:
            d = json.load(open(p))
            kk = (d.get('privateKey') or d.get('private_key') or d.get('pk') or d.get('key'))
            if kk:
                return kk
        except Exception:
            pass
    return None

PK = _load_key()
PAYER = None
if PK:
    try:
        PAYER = _addr(PK)
    except Exception:
        PAYER = None

def _addr(pk_hex):
    pk = int(pk_hex.replace('0x', ''), 16)
    Q = CT._pt_mul(pk, (CT.Gx, CT.Gy))
    import hashlib
    k = CT.keccak256(Q[0].to_bytes(32, 'big') + Q[1].to_bytes(32, 'big'))
    return '0x' + k[-20:].hex()

PAYER = _addr(PK)

# EIP-712 (与 proxy 完全一致)
_EIP712_DOMAIN = CT.keccak256(
    CT.keccak256(b'EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)')
    + CT.keccak256(b'USDC') + CT.keccak256(b'2')
    + (5042).to_bytes(32, 'big') + bytes(12) + bytes.fromhex('3600000000000000000000000000000000000000'))
_TWH = CT.keccak256(b'TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)')

def _auth_hash(auth):
    b = _TWH
    for a in (auth['from'], auth['to']):
        b += bytes(12) + bytes.fromhex(a[2:].lower())
    for k in ('value', 'validAfter', 'validBefore'):
        b += int(str(auth.get(k, '0')), 10).to_bytes(32, 'big')
    nonce = auth['nonce']
    b += bytes.fromhex(nonce[2:] if nonce.startswith('0x') else nonce)
    return CT.keccak256(b'\x19\x01' + _EIP712_DOMAIN + CT.keccak256(b))

def _rpc(method, params, pay):
    import urllib.request
    body = json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params}).encode()
    headers = {'Content-Type': 'application/json', 'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) percall-mcp/1.0'}
    if pay:
        c = json.loads(urllib.request.urlopen(urllib.request.Request(ENDPOINT + '/arc/', data=body, headers=headers), timeout=20).read())
    else:
        rq = urllib.request.Request(ENDPOINT + '/arc/', data=body, headers=headers)
        try:
            r = urllib.request.urlopen(rq, timeout=25)
            return json.loads(r.read().decode())
        except Exception as e:
            return {'error': str(e)}
    rq = urllib.request.Request(ENDPOINT + '/arc/', data=body, headers=headers)
    r = urllib.request.urlopen(rq, timeout=25)
    return json.loads(r.read().decode())

def _call_x402(method, params, free=False):
    import urllib.request, urllib.error
    body = json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params}).encode()
    headers = {'Content-Type': 'application/json', 'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) percall-mcp/1.0'}
    if free and PAYER:
        headers['X-From'] = PAYER
    try:
        r = urllib.request.urlopen(urllib.request.Request(ENDPOINT + '/arc/', data=body, headers=headers), timeout=30)
        return json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        if e.code != 402 or free:
            return {'error': 'http %s: %s' % (e.code, e.read().decode()[:200])}
        j = json.loads(e.read().decode())
        ac = j['accepts'][0]
        if not PK or CT is None:
            return {'error': 'X402_MCP_KEY not set (wallet private key needed to pay per call via x402)'}
        auth = {'from': PAYER, 'to': ac['payTo'], 'value': ac['maxAmountRequired'],
                'validAfter': '0', 'validBefore': str(int(time.time()) + 600),
                'nonce': '0x' + os.urandom(32).hex()}
        r_, s_, v = CT.ec_sign(_auth_hash(auth), int(PK.replace('0x', ''), 16))
        pay = {'x402Version': 2, 'scheme': ac['scheme'], 'network': ac['network'],
               'payload': dict(auth, r=hex(r_), s=hex(s_), v=27 + int(v))}
        headers['X-PAYMENT'] = base64.urlsafe_b64encode(json.dumps(pay).encode()).decode()
        r = urllib.request.urlopen(urllib.request.Request(ENDPOINT + '/arc/', data=body, headers=headers), timeout=30)
        return json.loads(r.read().decode())

def _data_call(path, params, free=False):
    """数据端点 (/early /alerts /audit): 非 JSON-RPC, 同样 x402 舞蹈"""
    import urllib.request, urllib.error
    body = json.dumps(params or {}).encode()
    headers = {'Content-Type': 'application/json', 'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) percall-mcp/1.0'}
    if free and PAYER:
        headers['X-From'] = PAYER
    rq = urllib.request.Request(ENDPOINT + path, data=body, headers=headers)
    try:
        r = urllib.request.urlopen(rq, timeout=60)
        return json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        if e.code != 402 or free:
            return {'error': 'http %s: %s' % (e.code, e.read().decode()[:200])}
        j = json.loads(e.read().decode())
        ac = j['accepts'][0]
        if not PK or CT is None:
            return {'error': 'X402_MCP_KEY not set (wallet private key needed to pay per call via x402)'}
        auth = {'from': PAYER, 'to': ac['payTo'], 'value': ac['maxAmountRequired'],
                'validAfter': '0', 'validBefore': str(int(time.time()) + 600),
                'nonce': '0x' + os.urandom(32).hex()}
        r_, s_, v = CT.ec_sign(_auth_hash(auth), int(PK.replace('0x', ''), 16))
        pay = {'x402Version': 2, 'scheme': ac['scheme'], 'network': ac['network'],
               'payload': dict(auth, r=hex(r_), s=hex(s_), v=27 + int(v))}
        headers['X-PAYMENT'] = base64.urlsafe_b64encode(json.dumps(pay).encode()).decode()
        rq = urllib.request.Request(ENDPOINT + path, data=body, headers=headers)
        r = urllib.request.urlopen(rq, timeout=90)
        return json.loads(r.read().decode())

TOOLS = [
    {'name': 'arc_block_number', 'description': 'Latest Arc mainnet block number (chainId 5042, ~1s blocks, USDC gas). $0.002 USDC.',
     'inputSchema': {'type': 'object', 'properties': {}}},
    {'name': 'arc_call', 'description': 'eth_call on Arc (simulate contract read). $0.003 USDC.',
     'inputSchema': {'type': 'object', 'properties': {'to': {'type': 'string'}, 'data': {'type': 'string'}}, 'required': ['to']}},
    {'name': 'arc_get_transaction_receipt', 'description': 'Transaction receipt (status/logs/gas). $0.003 USDC.',
     'inputSchema': {'type': 'object', 'properties': {'hash': {'type': 'string'}}, 'required': ['hash']}},
    {'name': 'arc_get_logs', 'description': 'eth_getLogs (filter by address/topics/block range). $0.005 USDC.',
     'inputSchema': {'type': 'object', 'properties': {'fromBlock': {'type': ['string', 'integer']}, 'toBlock': {'type': ['string', 'integer']}, 'address': {'type': 'string'}, 'topics': {'type': 'array'}}, 'required': ['fromBlock', 'toBlock']}},
    {'name': 'arc_balance', 'description': 'Native USDC balance (18 decimals) of an Arc address. $0.002 USDC.',
     'inputSchema': {'type': 'object', 'properties': {'address': {'type': 'string'}}, 'required': ['address']}},
    {'name': 'arc_free', 'description': 'Free-tier call (50/day, no payment). method+params = raw JSON-RPC.',
     'inputSchema': {'type': 'object', 'properties': {'method': {'type': 'string'}, 'params': {'type': 'array'}}, 'required': ['method']}},
    {'name': 'arc_early_watch', 'description': 'Monitoring snapshot. $0.01 USDC (free tier first): latest Arc block + its transactions; optional `address` + `window` (10-300s) to list USDC flows touching that address in the window. Use for activity watching.',
     'inputSchema': {'type': 'object', 'properties': {'address': {'type': 'string', 'description': '0x address to watch'}, 'window': {'type': 'integer', 'description': 'watch window seconds (10-300)'}}}},
    {'name': 'arc_alerts', 'description': 'Address USDC delta feed. $0.005 USDC (free tier first): USDC in/out transfers + live balance over a window. Built for 30-60s polling to watch a wallet.',
     'inputSchema': {'type': 'object', 'properties': {'address': {'type': 'string', 'description': '0x address to watch'}, 'window': {'type': 'integer', 'description': 'window seconds (10-3600, default 60)'}}}},
    {'name': 'arc_audit', 'description': 'Token hygiene check. $0.02 USDC (free tier first): name/symbol/decimals/supply, owner + renounced, proxy/upgradeable, 1h volume, risk flags, verdict pass/warn/fail.',
     'inputSchema': {'type': 'object', 'properties': {'address': {'type': 'string', 'description': 'token contract 0x..'}}, 'required': ['address']}},
    {'name': 'arc_whales', 'description': 'Top 20 USDC flow addresses on Arc in a window (1h default, max 24h). Bridge/DEX/whale detection. $0.005 USDC (free tier first). Served from a rolling buffer, sub-second.',
     'inputSchema': {'type': 'object', 'properties': {'window': {'type': 'integer', 'description': 'window seconds (60-86400, default 3600)'}}}},
    {'name': 'arc_deployments', 'description': 'New smart contract deployments on Arc in a window (1h default). Early-stage token/contract discovery feed. $0.01 USDC (free tier first).',
     'inputSchema': {'type': 'object', 'properties': {'window': {'type': 'integer', 'description': 'window seconds (60-86400, default 3600)'}}}},
    {'name': 'arc_wallet_report', 'description': 'Address risk/flow profile report. $0.05 USDC (free tier first): USDC balance + window in/out flows + top 5 counterparties (with contract check) + risk flags (dormant/high-volume/large-balance/contract-counterparties). One call replaces ~8 RPC round-trips.',
     'inputSchema': {'type': 'object', 'properties': {'address': {'type': 'string', 'description': '0x address'}, 'window': {'type': 'integer', 'description': 'window seconds (60-86400, default 86400)'}}, 'required': ['address']}},
    {'name': 'arc_token_report', 'description': 'Full token report. $0.05 USDC (free tier first): everything in arc_audit plus top-10 recipient holders and flow concentration (top10 share).',
     'inputSchema': {'type': 'object', 'properties': {'address': {'type': 'string', 'description': 'token contract 0x..'}}, 'required': ['address']}},
]

def tool_call(name, args):
    args = args or {}
    try:
        if name == 'arc_block_number':
            r = _call_x402('eth_blockNumber', [])
        elif name == 'arc_call':
            p = {'to': args['to'], 'data': args.get('data', '0x')}
            r = _call_x402('eth_call', [p, 'latest'])
        elif name == 'arc_get_transaction_receipt':
            r = _call_x402('eth_getTransactionReceipt', [args['hash']])
        elif name == 'arc_get_logs':
            q = {'fromBlock': str(args['fromBlock']), 'toBlock': str(args['toBlock'])}
            if args.get('address'):
                q['address'] = args['address']
            if args.get('topics') is not None:
                q['topics'] = args['topics']
            r = _call_x402('eth_getLogs', [q])
        elif name == 'arc_balance':
            r = _call_x402('eth_getBalance', [args['address'], 'latest'])
        elif name == 'arc_free':
            r = _call_x402(args['method'], args.get('params', []), free=True)
        elif name == 'arc_early_watch':
            p = {}
            if args.get('address'):
                p['address'] = args['address']
            if args.get('window'):
                p['window'] = int(args['window'])
            r = _data_call('/early', p)
        elif name == 'arc_alerts':
            p = {'address': args['address']}
            if args.get('window'):
                p['window'] = int(args['window'])
            r = _data_call('/alerts', p)
        elif name == 'arc_audit':
            r = _data_call('/audit', {'address': args['address']})
        elif name == 'arc_whales':
            p = {}
            if args.get('window'):
                p['window'] = int(args['window'])
            r = _data_call('/whales', p)
        elif name == 'arc_deployments':
            p = {}
            if args.get('window'):
                p['window'] = int(args['window'])
            r = _data_call('/deployments', p)
        elif name == 'arc_wallet_report':
            p = {'address': args['address']}
            if args.get('window'):
                p['window'] = int(args['window'])
            r = _data_call('/wallet-report', p)
        elif name == 'arc_token_report':
            r = _data_call('/token-report', {'address': args['address']})
        else:
            r = {'error': 'unknown tool ' + name}
        return [{'type': 'text', 'text': json.dumps(r)[:8000]}]
    except Exception as e:
        return [{'type': 'text', 'text': json.dumps({'error': str(e)[:500]})}]

def handle(msg):
    m = msg.get('method')
    mid = msg.get('id')
    if m == 'initialize':
        return {'jsonrpc': '2.0', 'id': mid, 'result': {
            'protocolVersion': '2024-11-05',
            'capabilities': {'tools': {}},
            'serverInfo': {'name': 'x402-arc-rpc', 'version': '1.0.0'}}}
    if m == 'notifications/initialized':
        return None
    if m == 'tools/list':
        return {'jsonrpc': '2.0', 'id': mid, 'result': {'tools': TOOLS}}
    if m == 'tools/call':
        a = msg.get('params', {})
        return {'jsonrpc': '2.0', 'id': mid, 'result': {'content': tool_call(a.get('name'), a.get('arguments')), 'isError': False}}
    if m == 'ping':
        return {'jsonrpc': '2.0', 'id': mid, 'result': {}}
    return None

def main():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
            out = handle(msg)
            if out is not None:
                sys.stdout.write(json.dumps(out) + '\n')
                sys.stdout.flush()
        except Exception as e:
            err = {'jsonrpc': '2.0', 'id': None, 'error': {'code': -32603, 'message': str(e)[:200]}}
            sys.stdout.write(json.dumps(err) + '\n')
            sys.stdout.flush()

if __name__ == '__main__':
    main()
