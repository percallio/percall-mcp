"""CCTP 主网转账: Base(6) -> Arc(26)
USDC: 标准 CCTP V2 depositForBurnWithHook + Forwarding Service (Circle 代付 Arc gas)
EURC: CCTP-X crossChainTransfer + FORWARD 请求 (Circle 代付; Arc 侧 CCTP-X 待部署验证)
零依赖 (纯 python keccak/secp256k1/RLP + 公开 RPC + Iris API)
用法: python3 cctp_transfer.py usdc 500 | eurc 500 | poll
GO=1 实际执行 (默认 DRY)
"""
import json, sys, time, urllib.request, os

# ---------- keccak (复用同目录已验证实现) ----------
import sys as _sys, os as _os
_sys.path.insert(0, _os.path.dirname(_os.path.abspath(__file__)))
from keccak import keccak256, selector as _selector
assert keccak256(b'').hex() == 'c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470'
def sel(sig):
    return _selector(sig)  # 返回 '0x....'

# ---------- secp256k1 ----------
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
def _inv(a, m): return pow(a, m - 2, m)
def _pt_add(p1, p2):
    if p1 is None: return p2
    if p2 is None: return p1
    if p1[0] == p2[0] and (p1[1] + p2[1]) % P == 0: return None
    if p1 == p2:
        lam = (3 * p1[0] * p1[0]) * _inv(2 * p1[1], P) % P
    else:
        lam = (p2[1] - p1[1]) * _inv((p2[0] - p1[0]) % P, P) % P
    x3 = (lam * lam - p1[0] - p2[0]) % P
    return (x3, (lam * (p1[0] - x3) - p1[1]) % P)
def _pt_mul(k, pt):
    r = None; a = pt
    while k:
        if k & 1: r = _pt_add(r, a)
        a = _pt_add(a, a); k >>= 1
    return r
def ec_sign(msg_hash, priv):
    if isinstance(priv, str):
        priv = int(priv, 16)
    z = int.from_bytes(msg_hash, 'big')
    seed = (z ^ int.from_bytes(keccak256(str(priv).encode()), 'big')) % N
    for attempt in range(128):
        k = (seed + attempt * 0x9E3779B97F4A7C15) % N
        if k == 0: continue
        R = _pt_mul(k, (Gx, Gy))
        r = R[0] % N
        if r == 0: continue
        s = (_inv(k, N) * (z + r * priv)) % N
        if s == 0: continue
        if s > N // 2:
            s = N - s
            R = (R[0], R[1] ^ 1)
        return r, s, R[1] & 1
    raise RuntimeError('sign fail')

# ---------- RLP ----------
def rlp(v):
    if isinstance(v, int):
        v = v.to_bytes((v.bit_length() + 7) // 8, 'big') if v else b''
    if isinstance(v, bytes):
        if len(v) == 1 and v[0] < 0x80:
            return v
        if len(v) < 56:
            return bytes([0x80 + len(v)]) + v
        lb = len(v).to_bytes((len(v).bit_length() + 7) // 8, 'big')
        return bytes([0xb7 + len(lb)]) + lb + v
    out = b''.join(rlp(x) for x in v)
    if len(out) < 56:
        return bytes([0xc0 + len(out)]) + out
    lb = len(out).to_bytes((len(out).bit_length() + 7) // 8, 'big')
    return bytes([0xf7 + len(lb)]) + lb + out

# ---------- RPC / API ----------
BASE_RPCS = ['https://base.drpc.org', 'https://base-rpc.publicnode.com', 'https://1rpc.io/base']
ARC_GW = 'http://127.0.0.1:9600/arc/'
def _post(url, method, params, t=20):
    p = json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params}).encode()
    req = urllib.request.Request(url, data=p, headers={'Content-Type': 'application/json', 'User-Agent': 'Mozilla/5.0'})
    return json.loads(urllib.request.urlopen(req, timeout=t).read().decode())
def base_call(method, params, tries=6):
    last = ''
    for i in range(tries):
        try:
            r = _post(BASE_RPCS[i % len(BASE_RPCS)], method, params)
            if 'result' in r:
                return r['result']
            last = str(r.get('error', ''))[:80]
        except Exception as e:
            last = str(e)[:80]
        time.sleep(1)
    raise RuntimeError('base rpc fail: ' + last)
ARC_DIRECT = [ARC_GW, 'https://api.zan.top/arc-mainnet', 'https://rpc.arc-scan.org']
def arc_call(method, params, t=20):
    last = ''
    for u in ARC_DIRECT + [ARC_GW]:
        try:
            r = _post(u, method, params, t)
            if 'result' in r:
                if method == 'eth_sendRawTransaction' and r['result'] is None:
                    last = 'null-result(sendRaw 全端点拒?)'
                    continue
                return r['result']
            last = str(r.get('error', ''))[:80]
        except Exception as e:
            last = str(e)[:60]
        time.sleep(0.5)
    raise RuntimeError('arc fail: ' + last)
def _iris_req(path, t=18, tries=6, data=None):
    nodes = ['http://37.59.125.131:8888', 'http://123.113.156.113:8888', 'http://127.0.0.1:8079']
    last = ''
    for i in range(tries):
        try:
            px = nodes[i % len(nodes)]
            direct = (px == 'http://127.0.0.1:8079')
            op = urllib.request.build_opener(urllib.request.ProxyHandler({'http': px, 'https': px})) if not direct else urllib.request.build_opener(urllib.request.ProxyHandler({}))
            body = json.dumps(data).encode() if data is not None else None
            req = urllib.request.Request('https://iris-api.circle.com' + path, data=body,
                                         headers={'User-Agent': 'Mozilla/5.0', 'Content-Type': 'application/json'},
                                         method='POST' if data is not None else 'GET')
            return json.loads(op.open(req, timeout=t).read().decode())
        except Exception as e:
            last = str(e)[:60]; time.sleep(1.5)
    raise RuntimeError('iris fail: ' + last)
def iris_get(path): return _iris_req(path)
def iris_post(path, data): return _iris_req(path, data=data)

# ---------- 常量 ----------
WALLET_FILE = '/root/crypto-bugs/data/keys/arc_wallet.json'
CHAIN_BASE = 8453
TM_BASE = '0x28b5a0e9C621a5BadaA536219b3a228C8168cf5d'
USDC_BASE = '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913'
EURC_BASE = '0x60a3e35cc302bfa44cb288bc5a4f316fdb1adb42'
CCTS_BASE = '0x63753E722bd2C2A5DF6EE19C5106662208B81077'
TM_MGR_BASE = '0x8c27579e24f9f19d96724e19fc059dacd1469e10'
ARC_WALLET = '0xC887a6Ee6AFe389337837d106d22635bdcA36557'
HOOK_V0 = '0x636374702d666f72776172640000000000000000000000000000000000000000'
EURC_TOKEN_ID = '6ca9e29fa53becc29becaf4a90b9ca7a995ad4d2234880da13ca38c657fb241c'
DOMAIN_BASE, DOMAIN_ARC = 6, 26
USDC_ARC = '0x3600000000000000000000000000000000000000'
EURC_ARC = '0xbeF5f6d51CB62b58e6A8f77868681825C6fe21c1'
STATE = '/root/crypto-bugs/data/cctp_transfer_state.json'

def load_priv():
    d = json.load(open(WALLET_FILE))
    pk = d.get('privateKey') or d.get('private_key') or d.get('pk') or d.get('key')
    if pk.startswith('0x'): pk = pk[2:]
    return int(pk, 16)
def enc_uint(v): return v.to_bytes(32, 'big')
def enc_addr20(a):
    return bytes.fromhex(a[2:].lower())

def enc_addr(a): return b'\x00' * 12 + bytes.fromhex(a[2:].lower())
def pad32(a): return b'\x00' * 12 + bytes.fromhex(a[2:].lower())
def enc_dyn(data):
    out = enc_uint(len(data))
    return out + data + b'\x00' * ((-len(data)) % 32)
def b(hexs): return bytes.fromhex(hexs[2:] if hexs.startswith('0x') else hexs)

def send_base(priv, to, data, go, gas=None, value=0):
    nonce = int(base_call('eth_getTransactionCount', [ARC_WALLET, 'pending']), 16)
    blk = base_call('eth_getBlockByNumber', ['latest', False])
    base_fee = int(blk['baseFeePerGas'], 16)
    tip = 0x3B9ACA00
    max_fee = base_fee * 2 + tip
    if gas is None:
        est = int(base_call('eth_estimateGas', [{'from': ARC_WALLET, 'to': to, 'data': '0x' + data.hex()}]), 16)
        gas = int(est * 1.25) + 5000
    raw = [CHAIN_BASE, nonce, tip, max_fee, gas, enc_addr20(to), value, data, []]
    body = b'\x01' + rlp(raw)
    r, s, v = ec_sign(keccak256(body), priv)
    tx = b'\x01' + rlp(raw + [v, r, s])
    txh = keccak256(tx).hex()
    if not go:
        print('[DRY] to=%s gas=%d nonce=%d datalen=%d txhash=%s' % (to[:14], gas, nonce, len(data), txh[:20]))
        return '0x' + txh
    base_call('eth_sendRawTransaction', ['0x' + tx.hex()])
    print('SENT 0x%s' % txh, flush=True)
    for i in range(40):
        time.sleep(3)
        rc = base_call('eth_getTransactionReceipt', ['0x' + txh])
        if rc:
            rcd = json.loads(rc) if isinstance(rc, str) else rc
            print('receipt status=%s gasUsed=%s' % (rcd.get('status'), rcd.get('gasUsed')), flush=True)
            return '0x' + txh
    print('pending (receipt 稍后查)')
    return '0x' + txh

def bal_of(url_kind, token, chain_w):
    d = '0x' + sel('balanceOf(address)') + enc_addr(chain_w).hex()
    fn = base_call if url_kind == 'base' else arc_call
    r = fn('eth_call', [{'to': token, 'data': d}, 'latest'])
    try:
        return int(r, 16)
    except Exception:
        return None

def save_state(d):
    json.dump(d, open(STATE, 'w'), indent=1)

def usdc_flow(amount_usd, go):
    priv = load_priv()
    amt6 = int(amount_usd * 10**6)
    print('== USDC %s Base->Arc (forward) ==' % amount_usd)
    ub = bal_of('base', USDC_BASE, ARC_WALLET)
    print('Base USDC: %s' % (ub / 1e6 if ub is not None else '?'))
    if ub is not None and ub < amt6:
        print('! 余额不足 (需要 >= %s USDC + fee)' % amount_usd); return
    fees = iris_get('/v2/burn/USDC/fees/%d/%d?forward=true' % (DOMAIN_BASE, DOMAIN_ARC))
    f = fees[0]
    min_bps = float(f['minimumFee'])
    fwd = int(f['forwardFee']['med'])
    proto = int(amt6 * min_bps / 10000) + 1
    max_fee = fwd + proto
    total = amt6 + max_fee
    print('fees: min_bps=%s forward=%s proto=%s => maxFee=%s total=%s' % (min_bps, fwd, proto, max_fee, total))
    # approve
    data = b(sel('approve(address,uint256)')) + enc_addr(TM_BASE) + enc_uint(total)
    h1 = send_base(priv, TM_BASE, data, go)
    if not go: return
    time.sleep(2)
    # depositForBurnWithHook
    sig = 'depositForBurnWithHook(uint256,uint32,bytes32,address,bytes32,uint256,uint32,bytes)'
    data = (b(sel(sig)) + enc_uint(total) + enc_uint(DOMAIN_ARC) + pad32(ARC_WALLET)
            + enc_addr(USDC_BASE) + b'\x00' * 32 + enc_uint(max_fee) + enc_uint(1000) + enc_dyn(b(HOOK_V0)))
    burn = send_base(priv, TM_BASE, data, go)
    save_state({'usdc_burn': burn})
    if burn:
        poll_usdc(burn)

def poll_usdc(burn):
    for i in range(120):
        time.sleep(10)
        try:
            d = iris_get('/v2/messages/%d?transactionHash=%s' % (DOMAIN_BASE, burn))
            msgs = d.get('messages') or []
            if msgs and msgs[0].get('forwardTxHash'):
                print('*** ARC MINTED (Circle forward):', msgs[0]['forwardTxHash'])
                time.sleep(20)
                au = bal_of('arc', USDC_ARC, ARC_WALLET)
                na = arc_call('eth_getBalance', [ARC_WALLET, 'latest'])
                print('Arc USDC: %s | native: %s USDC' % (None if au is None else au / 1e6, int(na, 16) / 1e12 if na else '?'))
                return True
            if i % 6 == 0:
                print('... waiting attestation/forward (status=%s)' % ((msgs[0].get('status') if msgs else '?')))
        except Exception as e:
            print('poll err:', str(e)[:60])
    print('timeout — 之后: python3 cctp_transfer.py pollusdc')
    return False

def eurc_flow(amount, go):
    priv = load_priv()
    amt6 = int(amount * 10**6)
    print('== EURC %s Base->Arc (CCTP-X forward) ==' % amount)
    eb = bal_of('base', EURC_BASE, ARC_WALLET)
    print('Base EURC: %s' % (eb / 1e6 if eb is not None else '?'))
    if eb is not None and eb < amt6:
        print('! 余额不足'); return
    # 1. quote (POST)
    q = iris_post('/v2/quote/cctpx/%s/%d/%d' % (EURC_TOKEN_ID, DOMAIN_BASE, DOMAIN_ARC), {
        'amount': str(amt6), 'feeToken': '0x' + '0' * 40,
        'requests': [{'type': 'PRE_FINALITY'},
                     {'type': 'FORWARD', 'params': {'msgType': 'TransferMessage',
                        'destinationAddress': ARC_WALLET}}]})
    print('quote: feeTotal=%s signedQuote=%s...' % (q.get('feeTotalAmount'), str(q.get('signedQuote'))[:30]))
    fee = int(q.get('feeTotalAmount', 0))
    total = amt6 + fee
    # 2. allowance (fast)
    try:
        al = iris_get('/v2/cctpx/allowances')
        row = [a for a in al.get('allowances', []) if a.get('tokenId', '').lower() == EURC_TOKEN_ID]
        print('fast allowance:', row[0].get('allowance') if row else '?')
    except Exception as e:
        print('allowance err:', str(e)[:60])
    if not go:
        print('[DRY done — GO=1 执行]'); return
    # 3. approve EURC -> tokenManager
    data = b(sel('approve(address,uint256)')) + enc_addr(TM_MGR_BASE) + enc_uint(total)
    send_base(priv, EURC_BASE, data, go)
    time.sleep(2)
    # 4. crossChainTransfer
    sig = 'crossChainTransfer(bytes32,uint256,uint32,bytes,bytes32,uint32,(bytes,address),bool,bytes)'
    claim = enc_dyn(b(q['signedQuote'])) + enc_addr(ARC_WALLET)
    data = (b(sel(sig)) + bytes.fromhex(EURC_TOKEN_ID) + enc_uint(total) + enc_uint(DOMAIN_ARC)
            + enc_dyn(pad32(ARC_WALLET)) + b'\x00' * 32 + enc_uint(1000)
            + enc_dyn(claim) + b'\x00' * 31 + b'\x01' + b'\x00' * 32)
    h = send_base(priv, CCTS_BASE, data, go)
    save_state({'eurc_burn': h})
    print('EURC transfer tx:', h)
    print('poll: 等 Arc EURC 余额 (Circle forward 需 Arc 侧 CCTP-X 就绪)')

def send_arc(priv, to, data, go, gas=None, value=0, tip_gwei=None, gas_mult=1.10):
    import time as _t
    nonce = int(arc_call('eth_getTransactionCount', [ARC_WALLET, 'latest']), 16)
    blk = None
    for _u in ARC_DIRECT:
        try:
            _r = _post(_u, 'eth_getBlockByNumber', ['latest', False], 12)
            if isinstance(_r, dict) and _r.get('result'):
                blk = _r['result']
                break
        except Exception:
            continue
    if not blk:
        raise RuntimeError('no block from any arc rpc')
    base_fee = int(blk['baseFeePerGas'], 16)
    if tip_gwei is not None:
        tip = tip_gwei * 10**9
        max_fee = base_fee + tip    # 实际费 = base + tip 精确控制
    else:
        tip = base_fee          # 20 Gwei tip (默认)
        max_fee = base_fee * 2    # 40 Gwei
        tip = base_fee          # 20 Gwei tip = 链上中位数 (9/20 实测 egp median 40 Gwei), 否则 mempool 垫底不打包
        max_fee = base_fee * 2    # 40 Gwei
    max_fee = base_fee * 2    # 40 Gwei
    if gas is None:
        est = int(arc_call('eth_estimateGas', [{'from': ARC_WALLET, 'to': to, 'data': '0x' + data.hex(), 'maxFeePerGas': hex(max_fee)}]), 16)
        gas = int(est * 1.15) + 5000
    raw = [5042, nonce, tip, max_fee, gas, enc_addr20(to), value, data, []]
    body = b'\x02' + rlp(raw)  # Arc: type-2=9字段1559布局 (probe6实证)
    r, s_, v = ec_sign(keccak256(body), priv)
    tx = b'\x02' + rlp(raw + [v, r, s_])
    txh = keccak256(tx).hex()
    if not go:
        print('[DRY-ARC] to=%s gas=%d nonce=%d fee~%.2f USDC' % (to[:14], gas, nonce, gas * max_fee / 1e18))
        return '0x' + txh
    arc_call('eth_sendRawTransaction', ['0x' + tx.hex()])
    print('SENT(arc) 0x%s (est fee %.2f USDC)' % (txh, gas * max_fee / 1e18), flush=True)
    for i in range(40):
        _t.sleep(3)
        rc = arc_call('eth_getTransactionReceipt', ['0x' + txh])
        if rc:
            rcd = json.loads(rc) if isinstance(rc, str) else rc
            print('arc receipt status=%s gasUsed=%s' % (rcd.get('status'), rcd.get('gasUsed')), flush=True)
            return '0x' + txh
    print('arc pending')
    return '0x' + txh

POOL = '0x5Eb309a76C6E993293CD756d938BBb35F3bFd35f'

def lendora(usd_amt, eur_amt, go):
    import time as _t
    priv = load_priv()
    au = bal_of('arc', USDC_ARC, ARC_WALLET)
    ae = bal_of('arc', EURC_ARC, ARC_WALLET)
    na = arc_call('eth_getBalance', [ARC_WALLET, 'latest'])
    print('Arc: USDC=%s EURC=%s native=%s USDC' % (
        None if au is None else au / 1e6, None if ae is None else ae / 1e6,
        int(na, 16) / 1e12 if na else 0))
    if au is None or ae is None:
        print('! 等待 CCTP 到账 (先跑 usdc/eurc 模式)'); return
    need_usd, need_eur = int(usd_amt * 1e6), int(eur_amt * 1e6)
    if au < need_usd or ae < need_eur:
        print('! 余额不足 (需 USDC %s / EURC %s)' % (usd_amt, eur_amt)); return
    # 1. approve USDC (precompile)
    data = b(sel('approve(address,uint256)')) + enc_addr(POOL) + enc_uint(need_usd)
    send_arc(priv, USDC_ARC, data, go)
    if not go: print('[DRY done — GO=1 执行]'); return
    _t.sleep(5)
    # 2. approve EURC
    data = b(sel('approve(address,uint256)')) + enc_addr(POOL) + enc_uint(need_eur)
    send_arc(priv, EURC_ARC, data, go)
    _t.sleep(5)
    # 3. addLiquidity (minLP = 98%)
    minlp = (need_usd + need_eur) // 2 * 98 // 100
    data = (b(sel('addLiquidity(uint256,uint256,uint256)')) + enc_uint(need_usd)
            + enc_uint(need_eur) + enc_uint(minlp))
    h = send_arc(priv, POOL, data, go)
    save_state({'lendora_tx': h, 'lp_usd': usd_amt, 'lp_eur': eur_amt})
    _t.sleep(10)
    # 4. 验证: 池 reserves + 我们 LP
    for slot in (7, 8):
        r = arc_call('eth_getStorageAt', [POOL, hex(slot), 'latest'])
        print('pool slot%d = %s' % (slot, int(r, 16) / 1e6))
    lp_bal = bal_of('arc', POOL, ARC_WALLET)
    print('our LP tokens: %s' % (None if lp_bal is None else lp_bal / 1e6))
    print('*** 首 LP 完成' if (lp_bal or 0) > 0 else '!!! LP=0 检查 tx')

def check():
    au = bal_of('arc', USDC_ARC, ARC_WALLET)
    ae = bal_of('arc', EURC_ARC, ARC_WALLET)
    na = arc_call('eth_getBalance', [ARC_WALLET, 'latest'])
    print('Arc: USDC=%s EURC=%s native=%s USDC nonce=%s' % (
        None if au is None else au / 1e6, None if ae is None else ae / 1e6,
        int(na, 16) / 1e12 if na else '?', int(arc_call('eth_getTransactionCount', [ARC_WALLET, 'latest']), 16) if na else '?'))
    bu = bal_of('base', USDC_BASE, ARC_WALLET)
    be = bal_of('base', EURC_BASE, ARC_WALLET)
    nb = base_call('eth_getBalance', [ARC_WALLET, 'latest'])
    print('Base: USDC=%s EURC=%s native=%f ETH' % (
        None if bu is None else bu / 1e6, None if be is None else be / 1e6, int(nb, 16) / 1e18))

if __name__ == '__main__':
    mode = sys.argv[1] if len(sys.argv) > 1 else 'check'
    go = os.environ.get('GO') == '1'
    if mode == 'usdc':
        usdc_flow(float(sys.argv[2]) if len(sys.argv) > 2 else 500.0, go)
    elif mode == 'eurc':
        eurc_flow(float(sys.argv[2]) if len(sys.argv) > 2 else 500.0, go)
    elif mode == 'lendora':
        lendora(float(sys.argv[2]) if len(sys.argv) > 2 else 500.0,
                float(sys.argv[3]) if len(sys.argv) > 3 else 500.0, go)
    elif mode == 'pollusdc':
        st = json.load(open(STATE)) if os.path.exists(STATE) else {}
        if st.get('usdc_burn'):
            poll_usdc(st['usdc_burn'])
        else:
            print('no usdc_burn in state')
    elif mode == 'check':
        check()
    else:
        print(__doc__)
