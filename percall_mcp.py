"""x402 MCP server — Arc RPC 工具, x402 自动付款 (stdio JSON-RPC)

Agent 接入 (Claude Desktop mcp.json):
  "x402-arc": {"command": "python3", "args": ["/root/x402_mcp.py"]}
环境变量:
  X402_MCP_KEY   付款钱包私钥 (默认 keys/tapeout_hot.json)
  X402_MCP_URL   服务端点 (默认读 /root/x402_tunnel_url.txt)
"""
import sys, json, os, time, base64

sys.path.insert(0, '/root/crypto-bugs/scripts')
import cctp_transfer as CT

ENDPOINT = os.environ.get('X402_MCP_URL', open('/root/x402_tunnel_url.txt').read().strip()).rstrip('/')

def _load_key():
    k = os.environ.get('X402_MCP_KEY')
    if k:
        return k
    d = json.load(open('/root/crypto-bugs/data/keys/tapeout_hot.json'))
    return (d.get('privateKey') or d.get('private_key') or d.get('pk') or d.get('key'))

PK = _load_key()

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
    headers = {'Content-Type': 'application/json'}
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
    headers = {'Content-Type': 'application/json'}
    if free:
        headers['X-From'] = PAYER
    try:
        r = urllib.request.urlopen(urllib.request.Request(ENDPOINT + '/arc/', data=body, headers=headers), timeout=30)
        return json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        if e.code != 402 or free:
            return {'error': 'http %s: %s' % (e.code, e.read().decode()[:200])}
        j = json.loads(e.read().decode())
        ac = j['accepts'][0]
        auth = {'from': PAYER, 'to': ac['payTo'], 'value': ac['maxAmountRequired'],
                'validAfter': '0', 'validBefore': str(int(time.time()) + 600),
                'nonce': '0x' + os.urandom(32).hex()}
        r_, s_, v = CT.ec_sign(_auth_hash(auth), int(PK.replace('0x', ''), 16))
        pay = {'x402Version': 2, 'scheme': ac['scheme'], 'network': ac['network'],
               'payload': dict(auth, r=hex(r_), s=hex(s_), v=27 + int(v))}
        headers['X-PAYMENT'] = base64.urlsafe_b64encode(json.dumps(pay).encode()).decode()
        r = urllib.request.urlopen(urllib.request.Request(ENDPOINT + '/arc/', data=body, headers=headers), timeout=30)
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
