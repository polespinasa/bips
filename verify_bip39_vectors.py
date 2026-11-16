#!/usr/bin/env python3
"""
Verify the bip39() test vectors for bip-xxxx.md from first principles.
This checks the published values and focused encoding cases, not full descriptor syntax.
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
# From bip-0380.mediawiki, with input checks added to descsum_check.
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
    if len(s) < 9 or s[-9] != '#':
        return False
    if not all(x in CHECKSUM_CHARSET for x in s[-8:]):
        return False
    symbols = descsum_expand(s[:-9])
    if symbols is None:
        return False
    symbols += [CHECKSUM_CHARSET.find(x) for x in s[-8:]]
    return descsum_polymod(symbols) == 1

def descsum_create(s):
    """Add a checksum to a descriptor without"""
    symbols = descsum_expand(s) + [0, 0, 0, 0, 0, 0, 0, 0]
    checksum = descsum_polymod(symbols) ^ 1
    return s + '#' + ''.join(CHECKSUM_CHARSET[(checksum >> (5 * (7 - i))) & 31] for i in range(8))


def descriptor_body(desc: str) -> str:
    """Remove and verify an optional checksum, ignoring '#' inside quotes."""
    quoted, escaped = False, False
    for i, char in enumerate(desc):
        if escaped:
            escaped = False
        elif quoted and char == '\\':
            escaped = True
        elif char == '"':
            quoted = not quoted
        elif char == '#' and not quoted:
            if len(desc) - i != 9 or not descsum_check(desc):
                raise ValueError('invalid descriptor checksum')
            return desc[:i]
    if quoted:
        raise ValueError('unterminated quoted string')
    return desc

# ================== passphrase escape decoder =========================
def decode_passphrase(enc: str) -> str:
    out, i = [], 0
    while i < len(enc):
        if enc[i] == '\\':
            if i+1 == len(enc):
                raise ValueError('incomplete escape sequence')
            nc = enc[i+1]
            if nc == '"':   out.append('"');  i += 2
            elif nc == '\\': out.append('\\'); i += 2
            elif nc == 'u' and i+2 < len(enc) and enc[i+2] == '{':
                end = enc.index('}', i+3)
                digits = enc[i+3:end]
                if re.fullmatch(r'[0-9a-fA-F]{1,6}', digits) is None:
                    raise ValueError('expected 1 to 6 hexadecimal digits')
                cp = int(digits, 16)
                if 0xD800 <= cp <= 0xDFFF or cp > 0x10FFFF:
                    raise ValueError(f"bad code point U+{cp:04X}")
                out.append(chr(cp)); i = end + 1
            else: raise ValueError(f"bad escape \\{nc}")
        else:
            if enc[i] not in INPUT_CHARSET or enc[i] == '"':
                raise ValueError(f'unescaped character {enc[i]!r}')
            out.append(enc[i]); i += 1
    return ''.join(out)


def extract_bip39(desc_body: str):
    """Extract the mnemonic and optional passphrase from these simple test vectors."""
    m = re.search(r'bip39\(\[([^\]]*)\](?:, *"((?:\\.|[^"\\])*)")?\)', desc_body)
    if m is None:
        raise ValueError('missing or malformed bip39() expression')
    words = [w.strip(' ') for w in m.group(1).split(',')]
    return ' '.join(words), decode_passphrase(m.group(2) or '')


# ======================== Hardcoded test vectors ========================
# Each tuple: (label, bip39() descriptor + checksum, xprv descriptor + checksum,
#              decoded passphrase). The first seven mirror bip-xxxx.md's Test Vectors.
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

    ('omitted passphrase',
     'tr(bip39([fancy, behave, cement, feel, gas, super, dutch, juice, cream, tape, bronze, increase, minor, meadow, rescue, someone, banana, recipe, orient, copy, blossom, team, chase, initial]))#dyx7lg72',
     'tr(xprv9s21ZrQH143K2RYd6U3ZPwZokU39ePUpH4Rnqdsob4kFY8S24EGW6beNSnTxEThEfsfsLftit9AvN5zWKhVx9hrX4wqEqfJfNPVgN1QAhN6)#wsvljep4',
     ''),

    ('empty passphrase',
     'tr(bip39([fancy, behave, cement, feel, gas, super, dutch, juice, cream, tape, bronze, increase, minor, meadow, rescue, someone, banana, recipe, orient, copy, blossom, team, chase, initial], ""))#yrtaedsd',
     'tr(xprv9s21ZrQH143K2RYd6U3ZPwZokU39ePUpH4Rnqdsob4kFY8S24EGW6beNSnTxEThEfsfsLftit9AvN5zWKhVx9hrX4wqEqfJfNPVgN1QAhN6)#wsvljep4',
     ''),

    ('decomposed unicode',
     r'wpkh(bip39([legal, winner, thank, year, wave, sausage, worth, useful, legal, winner, thank, yellow], "cafe\u{301}"))#km870w3t',
     'wpkh(xprv9s21ZrQH143K3786ZFxLXMxdQo5V5RrSrDWXwG8UppFnDipsxycLdR22K5eCJfaBEzRGgjtAJQvyQGreTULTSMPNWh25yVuknrJLu4VKm3s)#9a0vxmzx',
     'cafe\u0301'),
]

# ---- Verify every vector ------------------------------------------------
print(f"\n=== Verifying {len(vectors)} vectors with and without checksums ===\n")
all_ok = True
for label, bip39_desc, xprv_desc, expected_passphrase in vectors:
    for with_checksum in (True, False):
        # All stored vectors have checksums; remove them only to construct the second case.
        desc = bip39_desc if with_checksum else bip39_desc[:-9]
        expected_desc = xprv_desc if with_checksum else xprv_desc[:-9]
        case = f'{label} ({"with" if with_checksum else "without"} checksum)'
        try:
            body = descriptor_body(desc)
            expected_body = descriptor_body(expected_desc)
            mnemonic, passphrase = extract_bip39(body)
            if passphrase != expected_passphrase:
                raise ValueError(f'decoded={passphrase!r}, expected={expected_passphrase!r}')
            derived = bip32_master_xprv(bip39_seed(mnemonic, passphrase))
            xprv_m = re.search(r'xprv[1-9A-HJ-NP-Za-km-z]+', expected_body)
            if xprv_m is None or derived != xprv_m.group(0):
                raise ValueError(f'derived xprv does not match: {derived}')
        except ValueError as error:
            all_ok = False
            print(f'  [FAIL] {case}: {error}')
        else:
            print(f'  [OK  ] {case}')

# Each malformed checksum still has a literal '#' in its quoted passphrase.
hash_desc = vectors[0][1]
invalid_checksums = [
    ('incorrect checksum', hash_desc[:-1] + 'q'),
    ('empty checksum', hash_desc[:-8]),
    ('short checksum', hash_desc[:-1]),
    ('long checksum', hash_desc + 'q'),
    ('invalid checksum character', hash_desc[:-1] + 'b'),
    ('extra checksum separator', hash_desc + '#'),
]
for label, desc in invalid_checksums:
    try:
        descriptor_body(desc)
    except ValueError:
        print(f'  [OK  ] reject {label}')
    else:
        all_ok = False
        print(f'  [FAIL] accepted {label}')

invalid_passphrases = [
    ('unknown escape', r'\x'),
    ('newline escape', r'\n'),
    ('empty unicode escape', r'\u{}'),
    ('seven hex digits', r'\u{0000041}'),
    ('non-hex digit', r'\u{g}'),
    ('hex prefix', r'\u{0x41}'),
    ('sign', r'\u{+41}'),
    ('underscore', r'\u{4_1}'),
    ('whitespace in escape', r'\u{ 41}'),
    ('surrogate', r'\u{D800}'),
    ('out-of-range code point', r'\u{110000}'),
    ('missing closing brace', r'\u{41'),
    ('incomplete unicode escape', r'\u'),
    ('trailing backslash', 'abc\\'),
    ('raw unicode', 'café'),
    ('raw newline', '\n'),
    ('unescaped quote', 'say "hello"'),
]
for label, encoded in invalid_passphrases:
    try:
        decode_passphrase(encoded)
    except ValueError:
        print(f'  [OK  ] reject {label}')
    else:
        all_ok = False
        print(f'  [FAIL] accepted {label}')

print(f"\n{'=== ALL VERIFIED ===' if all_ok else '=== FAILURES PRESENT ==='}")
raise SystemExit(0 if all_ok else 1)
