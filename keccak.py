"""纯 Python keccak256（无依赖）。验证向量：
keccak256(b'') = c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470
keccak256(b'transfer(address,uint256)') = a9059cbb... (selector a9059cbb)
"""
from __future__ import annotations

_RC = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
]
_ROT = [
    [0, 36, 3, 41, 18],
    [1, 44, 10, 45, 2],
    [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39, 8, 14],
]


def _rol(x: int, n: int) -> int:
    return ((x << n) | (x >> (64 - n))) & 0xFFFFFFFFFFFFFFFF


def _keccak_f(state: list) -> None:
    for r in range(24):
        C = [state[x][0] ^ state[x][1] ^ state[x][2] ^ state[x][3] ^ state[x][4] for x in range(5)]
        D = [C[(x - 1) % 5] ^ _rol(C[(x + 1) % 5], 1) for x in range(5)]
        for x in range(5):
            for y in range(5):
                state[x][y] ^= D[x]
        B = [[0] * 5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                B[y][(2 * x + 3 * y) % 5] = _rol(state[x][y], _ROT[x][y])
        for x in range(5):
            for y in range(5):
                state[x][y] = B[x][y] ^ ((~B[(x + 1) % 5][y]) & B[(x + 2) % 5][y])
        state[0][0] ^= _RC[r]


def keccak256(data: bytes) -> bytes:
    rate = 136
    block = bytearray(data)
    block.append(0x01)
    while len(block) % rate != 0:
        block.append(0x00)
    block[-1] |= 0x80
    state = [[0] * 5 for _ in range(5)]
    for off in range(0, len(block), rate):
        for i in range(rate // 8):
            lane = int.from_bytes(block[off + i * 8: off + i * 8 + 8], "little")
            state[i % 5][i // 5] ^= lane
        _keccak_f(state)
    out = b""
    for i in range(4):
        out += state[i % 5][i // 5].to_bytes(8, "little")
    return out


def selector(sig: str) -> str:
    return "0x" + keccak256(sig.encode()).hex()[:8]


def topic(sig: str) -> str:
    return "0x" + keccak256(sig.encode()).hex()


if __name__ == "__main__":
    assert keccak256(b"").hex() == "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
    assert selector("transfer(address,uint256)") == "0xa9059cbb"
    # 9/17 修正：用 pycryptodome + 4byte.directory 交叉验证过的正确向量
    # （旧断言 0x0d025085/0x0087ef4e 是凭记忆写错的，导致 self-test 假失败）
    assert selector("asset()") == "0x38d52e0f"
    assert selector("totalAssets()") == "0x01e1d114"
    assert selector("convertToShares(uint256)") == "0xc6e6f592"
    print("keccak256 验证通过")
