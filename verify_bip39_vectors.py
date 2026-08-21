#!/usr/bin/env python3
"""
Verify the bip39() test vectors for bip-xxxx.md from first principles.
"""
import re, hashlib, hmac, unicodedata

# ============================ Base58check ============================
B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

def base58_encode(data: bytes) -> str:
    n = int.from_bytes(data, 'big')
    out = ''
    while n > 0:
        n, rem = divmod(n, 58)
        out = B58[rem] + out
    for b in data:           # preserve leading zero bytes as '1'
        if b == 0: out = '1' + out
        else: break
    return out

# ============================ BIP 39 seed ============================
def bip39_seed(mnemonic: str, passphrase: str) -> bytes:
    """PBKDF2-HMAC-SHA512, 2048 iters, both inputs NFKD-normalized (BIP 39)."""
    mn = unicodedata.normalize('NFKD', mnemonic)
    pp = unicodedata.normalize('NFKD', passphrase)
    return hashlib.pbkdf2_hmac('sha512', mn.encode('utf-8'),
                               b"mnemonic" + pp.encode('utf-8'), 2048, dklen=64)

# ====================== BIP 32 master xprv ==========================
def bip32_master_xprv(seed: bytes) -> str:
    I  = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
    IL, IR = I[:32], I[32:]               # secret key, chain code
    payload = (bytes.fromhex('0488ade4')  # mainnet xprv version
               + b'\x00'                  # depth 0
               + b'\x00\x00\x00\x00'      # parent fingerprint
               + b'\x00\x00\x00\x00'      # child number
               + IR                       # chain code (32)
               + b'\x00' + IL)            # 0x00 marker + private key (32) -> 78 bytes
    chk = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    return base58_encode(payload + chk)

# ===================== BIP 380 descriptor checksum ===================
# Copied verbatim from bip-0380.mediawiki — no modifications
INPUT_CHARSET = "0123456789()[],'/*abcdefgh@:$%{}IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~ijklmnopqrstuvwxyzABCDEFGH`#\"\\ "
CHECKSUM_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
GENERATOR = [0xf5dee51989, 0xa9fdca3312, 0x1bab10e32d, 0x3706b1677a, 0x644d626ffd]

def descsum_polymod(symbols):
    """Internal function that computes the descriptor checksum."""
    chk = 1
    for value in symbols:
        top = chk >> 35
        chk = (chk & 0x7ffffffff) << 5 ^ value
        for i in range(5):
            chk ^= GENERATOR[i] if ((top >> i) & 1) else 0
    return chk

def descsum_expand(s):
    """Internal function that does the character to symbol expansion"""
    groups = []
    symbols = []
    for c in s:
        if not c in INPUT_CHARSET:
            return None
        v = INPUT_CHARSET.find(c)
        symbols.append(v & 31)
        groups.append(v >> 5)
        if len(groups) == 3:
            symbols.append(groups[0] * 9 + groups[1] * 3 + groups[2])
            groups = []
    if len(groups) == 1:
        symbols.append(groups[0])
    elif len(groups) == 2:
        symbols.append(groups[0] * 3 + groups[1])
    return symbols

def descsum_check(s):
    """Verify that the checksum is correct in a descriptor"""
    if s[-9] != '#':
        return False
    if not all(x in CHECKSUM_CHARSET for x in s[-8:]):
        return False
    symbols = descsum_expand(s[:-9]) + [CHECKSUM_CHARSET.find(x) for x in s[-8:]]
    return descsum_polymod(symbols) == 1

def descsum_create(s):
    """Add a checksum to a descriptor without"""
    symbols = descsum_expand(s) + [0, 0, 0, 0, 0, 0, 0, 0]
    checksum = descsum_polymod(symbols) ^ 1
    return s + '#' + ''.join(CHECKSUM_CHARSET[(checksum >> (5 * (7 - i))) & 31] for i in range(8))

# ================== passphrase escape decoder =========================
def decode_passphrase(enc: str) -> str:
    out, i = [], 0
    while i < len(enc):
        if enc[i] == '\\' and i+1 < len(enc):
            nc = enc[i+1]
            if nc == '"':   out.append('"');  i += 2
            elif nc == '\\': out.append('\\'); i += 2
            elif nc == 'u' and i+2 < len(enc) and enc[i+2] == '{':
                end = enc.index('}', i+3)
                cp = int(enc[i+3:end], 16)
                if 0xD800 <= cp <= 0xDFFF or cp > 0x10FFFF:
                    raise ValueError(f"bad code point U+{cp:04X}")
                out.append(chr(cp)); i = end + 1
            else: raise ValueError(f"bad escape \\{nc}")
        else:
            out.append(enc[i]); i += 1
    return ''.join(out)


def extract_mnemonic(desc_body: str):
    """Extract the space-joined mnemonic words from a bip39([words], ...) descriptor.
    Returns None when no bip39([...]) clause is present."""
    m = re.search(r'bip39\(\[([^\]]*)\]', desc_body)
    if m is None:
        return None
    words = [w.strip() for w in m.group(1).split(',')]
    return ' '.join(words)


# ======================== Hardcoded test vectors ========================
# Each tuple: (label, bip39() descriptor + checksum, xprv descriptor + checksum,
#              decoded passphrase).  These mirror bip-xxxx.md.
vectors = [
    ("# in passphrase",
     r'wpkh(bip39([legal, winner, thank, year, wave, sausage, worth, useful, legal, winner, thank, yellow], "foo#bar"))#fxq7mnpw',
     'wpkh(xprv9s21ZrQH143K4c2XhdpLFYp3ffuRPaopHxjwe5pWgXH6kAqX2dPiQdPGgAkrbfz2VhZMeTUdTYmmkevozwiNMvRth1Aw5pcNsRix8aSeKAi)#8satut7x',
     'foo#bar'),

    (", in passphrase",
     r'wpkh(bip39([legal, winner, thank, year, wave, sausage, worth, useful, legal, winner, thank, yellow], "foo,bar"))#3m4n50xq',
     'wpkh(xprv9s21ZrQH143K4FTherUTM5tBT6GmTB3Q9VG3an2VDXrxpWgQZb79H89dbSQPbpMQ2oosghFxJJvc1fLZJnC7MLxi7Ux4X96LLfXrWJj7VBT)#xxdnkpa7',
     'foo,bar'),

    (") in passphrase",
     r'wpkh(bip39([legal, winner, thank, year, wave, sausage, worth, useful, legal, winner, thank, yellow], "foo)bar"))#6hvdzscj',
     'wpkh(xprv9s21ZrQH143K3Qog5MR5QYGzTTPaxxFahyH1qTUEbbT9CZoPfE2rYS9Pu1t4q4dbKQ5vMsZif7BMmv2q21ZcHDpjvG5RpnCZ9sNs2t5ujev)#f6applf5',
     'foo)bar'),

    ("leading/trailing spaces",
     r'wpkh(bip39([legal, winner, thank, year, wave, sausage, worth, useful, legal, winner, thank, yellow], " leading and trailing spaces "))#z875r050',
     'wpkh(xprv9s21ZrQH143K4PPHRLkW85PkEY2n59XoLeS9UhE6G6jBqwz8aDchx9AGhTnMPVxsyuE5QBiTfNoLV7Xv1Qa6sLT9XVWcrBYhW459TXGhRkz)#4r68mrmk',
     ' leading and trailing spaces '),

    ('escaped double quote',
     r'wpkh(bip39([legal, winner, thank, year, wave, sausage, worth, useful, legal, winner, thank, yellow], "say \"hello\""))#473jhpxe',
     'wpkh(xprv9s21ZrQH143K4RAeSJzjATJVxWUDkjRTNHXDma4BXNWQhnip7sRjuYpngBTHxb4zKQPLJsvDDGzg1aaFxn3exkLqLYPUop2nEAHUvDMzFNG)#g2lt5shn',
     'say "hello"'),

    ('escaped backslash',
     r'wpkh(bip39([legal, winner, thank, year, wave, sausage, worth, useful, legal, winner, thank, yellow], "C:\\wallet"))#j6mt75rr',
     'wpkh(xprv9s21ZrQH143K3MWGZi36HpsEZ3SC7J9tPBjUmQYQ5sJqh8qyzuGgE3f1WgzDzHo47SneixuX9oVeqB5k2kdVUuQMVc1QiUGdq22gaBAbfuC)#5z32wesl',
     'C:\\wallet'),

    (r'unicode escape \u{e9}',
     r'wpkh(bip39([legal, winner, thank, year, wave, sausage, worth, useful, legal, winner, thank, yellow], "caf\u{e9}"))#05l5g328',
     'wpkh(xprv9s21ZrQH143K3786ZFxLXMxdQo5V5RrSrDWXwG8UppFnDipsxycLdR22K5eCJfaBEzRGgjtAJQvyQGreTULTSMPNWh25yVuknrJLu4VKm3s)#9a0vxmzx',
     'café'),
]

# ---- Verify every vector ------------------------------------------------
print(f"\n=== Verifying {len(vectors)} test vectors ===\n")
all_ok = True
for label, bip39_desc, xprv_desc, expected_passphrase in vectors:
    # The bip39() descriptor has a valid BIP 380 checksum.
    bip39_cs = descsum_check(bip39_desc)
    # The xprv   descriptor has a valid BIP 380 checksum.
    xprv_cs  = descsum_check(xprv_desc)

    # The passphrase decoded from inside the bip39() descriptor matches the expected decoded passphrase.
    body     = bip39_desc[:-9]
    mnemonic = extract_mnemonic(body)                                # None if no bip39([...])
    pp_m     = re.search(r'"((?:\\.|[^"\\])*)"', body)               # None if no quoted passphrase
    dec_pp   = decode_passphrase(pp_m.group(1)) if pp_m else None    # Convert the passphrase from bip380 compliant to normal utf-8 values
    passphrase_ok    = dec_pp is not None and dec_pp == expected_passphrase

    # Re-deriving the xprv from (mnemonic extracted from the descriptor, decoded passphrase) reproduces the xprv embedded in the xprv
    # descriptor (proves key equivalence from scratch).
    if mnemonic is not None and dec_pp is not None:
        derived = bip32_master_xprv(bip39_seed(mnemonic, dec_pp))
    else:
        derived = None
    xprv_m       = re.search(r'xprv[1-9A-HJ-NP-Za-km-z]+', xprv_desc)
    xprv_in_desc = xprv_m.group(0) if xprv_m else None
    key_ok       = (derived is not None and xprv_in_desc is not None
                    and derived == xprv_in_desc)

    ok = bip39_cs and xprv_cs and passphrase_ok and key_ok
    all_ok &= ok
    print(f"  [{'OK  ' if ok else 'FAIL'}] {label:24s} pp={expected_passphrase!r}")
    if not ok:
        if not bip39_cs: print(f"         bip39 descriptor checksum INVALID")
        if not xprv_cs:  print(f"         xprv  descriptor checksum INVALID")
        if not passphrase_ok:
            if pp_m is None: print(f"         no quoted passphrase found in bip39 descriptor")
            else:            print(f"         decoded={dec_pp!r}  expected={expected_passphrase!r}")
        if not key_ok:
            if xprv_m is None:     print(f"         no xprv found in xprv descriptor")
            elif mnemonic is None: print(f"         no bip39([...]) mnemonic found in descriptor")
            else:                  print(f"         derived={derived}\n         in desc={xprv_in_desc}")

print(f"\n{'=== ALL VERIFIED ===' if all_ok else '=== FAILURES PRESENT ==='}")