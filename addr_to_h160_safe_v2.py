#!/usr/bin/env python3
# addr_to_h160_safe_v2.py
# Dekoduje legacy / p2sh (Base58Check) i bech32 (bc1/tb1).
# Zapisuje: ADDRESS<TAB>TYPE<TAB>HEX
# HEX = hash160 (20 bytes) dla P2PKH/P2SH/P2WPKH, lub witness-program hex dla innych.

import sys, hashlib, binascii
from typing import Tuple, Optional

# --- Base58 ---
BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
B58_MAP = {c:i for i,c in enumerate(BASE58)}

def b58decode(s: str) -> bytes:
    num = 0
    for ch in s:
        if ch not in B58_MAP:
            raise ValueError(f"Invalid Base58 char: {ch}")
        num = num * 58 + B58_MAP[ch]
    full = num.to_bytes((num.bit_length() + 7)//8, 'big') if num != 0 else b'\x00'
    n_leading = len(s) - len(s.lstrip('1'))
    return b'\x00' * n_leading + full

def base58check_decode(addr: str) -> Tuple[int, bytes]:
    data = b58decode(addr)
    if len(data) < 5:
        raise ValueError("Decoded data too short")
    payload, checksum = data[:-4], data[-4:]
    calc = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    if calc != checksum:
        raise ValueError("Bad checksum")
    version = payload[0]
    hash160 = payload[1:]
    return version, hash160

# --- Bech32 (BIP173) reference implementation (decode only) ---
CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
CHARSET_MAP = {c:i for i,c in enumerate(CHARSET)}

def bech32_polymod(values):
    GENERATORS = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for v in values:
        b = (chk >> 25)
        chk = ((chk & 0x1ffffff) << 5) ^ v
        for i in range(5):
            if (b >> i) & 1:
                chk ^= GENERATORS[i]
    return chk

def bech32_hrp_expand(hrp):
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]

def bech32_verify_checksum(hrp, data):
    return bech32_polymod(bech32_hrp_expand(hrp) + data) == 1

def bech32_decode(bech: str) -> Tuple[Optional[str], Optional[list]]:
    if (any(ord(x) < 33 or ord(x) > 126 for x in bech)) or (bech.lower() != bech and bech.upper() != bech):
        return None, None
    bech = bech.lower()
    pos = bech.rfind('1')
    if pos < 1 or pos + 7 > len(bech):  # at least 6 char checksum
        return None, None
    hrp = bech[:pos]
    data_part = bech[pos+1:]
    try:
        data = [CHARSET_MAP[c] for c in data_part]
    except KeyError:
        return None, None
    if not bech32_verify_checksum(hrp, data):
        return None, None
    return hrp, data[:-6]  # drop checksum

def convertbits(data, frombits, tobits, pad=True):
    acc = 0
    bits = 0
    out = []
    maxv = (1 << tobits) - 1
    for value in data:
        if value < 0 or (value >> frombits):
            return None
        acc = (acc << frombits) | value
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            out.append((acc >> bits) & maxv)
    if pad:
        if bits:
            out.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        return None
    return out

# --- Helpers / type mapping ---
def detect_base58_type(version_byte: int) -> str:
    # mainnet: 0x00 -> P2PKH (legacy), 0x05 -> P2SH
    # testnet: 0x6f -> P2PKH, 0xc4 -> P2SH
    if version_byte == 0x00:
        return "P2PKH(legacy)"
    if version_byte == 0x05:
        return "P2SH"
    if version_byte == 0x6f:
        return "TESTNET-P2PKH"
    if version_byte == 0xc4:
        return "TESTNET-P2SH"
    return f"unknown_ver_{hex(version_byte)}"

def process(infile, outfile):
    ok = 0
    bad = 0
    with open(infile, 'r', encoding='utf-8') as fin, open(outfile, 'w', encoding='utf-8') as fout:
        for i, line in enumerate(fin, 1):
            a = line.strip()
            if not a:
                continue
            try:
                low = a.lower()
                # Bech32 (bc1 / tb1)
                if low.startswith('bc1') or low.startswith('tb1'):
                    hrp, data = bech32_decode(a)
                    if hrp is None:
                        raise ValueError("Bech32 decode failed / bad checksum")
                    if len(data) == 0:
                        raise ValueError("Empty bech32 data")
                    # first 5-bit is witness version
                    witver = data[0]
                    prog = convertbits(data[1:], 5, 8, False)
                    if prog is None:
                        raise ValueError("convertbits failed")
                    prog_bytes = bytes(prog)
                    # classify
                    if witver == 0:
                        if len(prog_bytes) == 20:
                            typ = "P2WPKH(v0)"
                            fout.write(f"{a}\t{typ}\t{prog_bytes.hex()}\n")
                            ok += 1
                        elif len(prog_bytes) == 32:
                            typ = "P2WSH(v0)"
                            fout.write(f"{a}\t{typ}\t{prog_bytes.hex()}\n")
                            ok += 1
                        else:
                            typ = f"WIT_v0_len{len(prog_bytes)}"
                            fout.write(f"{a}\t{typ}\t{prog_bytes.hex()}\n")
                            ok += 1
                    elif witver == 1:
                        # v1 = taproot (BIP341) typically 32 bytes
                        typ = f"TAPROOT(v1) len{len(prog_bytes)}"
                        fout.write(f"{a}\t{typ}\t{prog_bytes.hex()}\n")
                        ok += 1
                    else:
                        typ = f"WIT_v{witver} len{len(prog_bytes)}"
                        fout.write(f"{a}\t{typ}\t{prog_bytes.hex()}\n")
                        ok += 1
                    continue

                # Otherwise: try Base58Check (legacy / p2sh)
                ver, h160 = base58check_decode(a)
                if len(h160) != 20:
                    # some coins / variants may give different lengths; treat as error
                    raise ValueError(f"payload len != 20 ({len(h160)})")
                typ = detect_base58_type(ver)
                fout.write(f"{a}\t{typ}\t{h160.hex()}\n")
                ok += 1
            except Exception as e:
                fout.write(f"{a}\tERROR\t{e}\n")
                bad += 1
    print(f"Done. ok={ok}, bad={bad}")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python3 addr_to_h160_safe_v2.py input.txt output.txt")
        sys.exit(1)
    process(sys.argv[1], sys.argv[2])
