"""
AES (Advanced Encryption Standard) - Full implementation from scratch.
Supports AES-128 (10 rounds), AES-192 (12 rounds), AES-256 (14 rounds).
"""

import os

#  AES CONSTANTS

SBOX = [
    0x63,0x7C,0x77,0x7B,0xF2,0x6B,0x6F,0xC5,0x30,0x01,0x67,0x2B,0xFE,0xD7,0xAB,0x76,
    0xCA,0x82,0xC9,0x7D,0xFA,0x59,0x47,0xF0,0xAD,0xD4,0xA2,0xAF,0x9C,0xA4,0x72,0xC0,
    0xB7,0xFD,0x93,0x26,0x36,0x3F,0xF7,0xCC,0x34,0xA5,0xE5,0xF1,0x71,0xD8,0x31,0x15,
    0x04,0xC7,0x23,0xC3,0x18,0x96,0x05,0x9A,0x07,0x12,0x80,0xE2,0xEB,0x27,0xB2,0x75,
    0x09,0x83,0x2C,0x1A,0x1B,0x6E,0x5A,0xA0,0x52,0x3B,0xD6,0xB3,0x29,0xE3,0x2F,0x84,
    0x53,0xD1,0x00,0xED,0x20,0xFC,0xB1,0x5B,0x6A,0xCB,0xBE,0x39,0x4A,0x4C,0x58,0xCF,
    0xD0,0xEF,0xAA,0xFB,0x43,0x4D,0x33,0x85,0x45,0xF9,0x02,0x7F,0x50,0x3C,0x9F,0xA8,
    0x51,0xA3,0x40,0x8F,0x92,0x9D,0x38,0xF5,0xBC,0xB6,0xDA,0x21,0x10,0xFF,0xF3,0xD2,
    0xCD,0x0C,0x13,0xEC,0x5F,0x97,0x44,0x17,0xC4,0xA7,0x7E,0x3D,0x64,0x5D,0x19,0x73,
    0x60,0x81,0x4F,0xDC,0x22,0x2A,0x90,0x88,0x46,0xEE,0xB8,0x14,0xDE,0x5E,0x0B,0xDB,
    0xE0,0x32,0x3A,0x0A,0x49,0x06,0x24,0x5C,0xC2,0xD3,0xAC,0x62,0x91,0x95,0xE4,0x79,
    0xE7,0xC8,0x37,0x6D,0x8D,0xD5,0x4E,0xA9,0x6C,0x56,0xF4,0xEA,0x65,0x7A,0xAE,0x08,
    0xBA,0x78,0x25,0x2E,0x1C,0xA6,0xB4,0xC6,0xE8,0xDD,0x74,0x1F,0x4B,0xBD,0x8B,0x8A,
    0x70,0x3E,0xB5,0x66,0x48,0x03,0xF6,0x0E,0x61,0x35,0x57,0xB9,0x86,0xC1,0x1D,0x9E,
    0xE1,0xF8,0x98,0x11,0x69,0xD9,0x8E,0x94,0x9B,0x1E,0x87,0xE9,0xCE,0x55,0x28,0xDF,
    0x8C,0xA1,0x89,0x0D,0xBF,0xE6,0x42,0x68,0x41,0x99,0x2D,0x0F,0xB0,0x54,0xBB,0x16,
]

INV_SBOX = [0] * 256
for i, v in enumerate(SBOX):
    INV_SBOX[v] = i

RCON = [0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1B,0x36,
        0x6C,0xD8,0xAB,0x4D,0x9A,0x2F,0x5E,0xBC,0x63,0xC6,
        0x97,0x35,0x6A,0xD4,0xB3,0x7D,0xFA,0xEF,0xC5,0x91]

#  GF(2^8) ARITHMETIC

def gmul(a: int, b: int) -> int:
    """Multiply two bytes in GF(2^8) with AES irreducible polynomial."""
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1B
        b >>= 1
    return p

#  KEY EXPANSION

def key_expansion(key: bytes) -> list[list[int]]:
    """Expand key into round keys. Returns list of 4-byte words."""
    key_len = len(key)
    if key_len == 16:
        nk, nr = 4, 10
    elif key_len == 24:
        nk, nr = 6, 12
    elif key_len == 32:
        nk, nr = 8, 14
    else:
        raise ValueError("Key must be 16, 24, or 32 bytes.")

    w = [list(key[i*4:(i+1)*4]) for i in range(nk)]
    for i in range(nk, 4 * (nr + 1)):
        temp = list(w[i-1])
        if i % nk == 0:
            temp = temp[1:] + temp[:1]
            temp = [SBOX[b] for b in temp]
            temp[0] ^= RCON[(i // nk) - 1]
        elif nk > 6 and i % nk == 4:
            temp = [SBOX[b] for b in temp]
        w.append([a ^ b for a, b in zip(w[i-nk], temp)])
    return w

def get_round_key(w: list[list[int]], round_num: int) -> list[list[int]]:
    """Get 4x4 state matrix for a given round."""
    start = round_num * 4
    words = w[start:start+4]
    state = [[0]*4 for _ in range(4)]
    for c in range(4):
        for r in range(4):
            state[r][c] = words[c][r]
    return state

#  AES OPERATIONS

def bytes_to_state(data: bytes) -> list[list[int]]:
    state = [[0]*4 for _ in range(4)]
    for r in range(4):
        for c in range(4):
            state[r][c] = data[r + 4*c]
    return state

def state_to_bytes(state: list[list[int]]) -> bytes:
    out = []
    for c in range(4):
        for r in range(4):
            out.append(state[r][c])
    return bytes(out)

def add_round_key(state: list[list[int]], rk: list[list[int]]) -> list[list[int]]:
    return [[state[r][c] ^ rk[r][c] for c in range(4)] for r in range(4)]

def sub_bytes(state: list[list[int]]) -> list[list[int]]:
    return [[SBOX[state[r][c]] for c in range(4)] for r in range(4)]

def inv_sub_bytes(state: list[list[int]]) -> list[list[int]]:
    return [[INV_SBOX[state[r][c]] for c in range(4)] for r in range(4)]

def shift_rows(state: list[list[int]]) -> list[list[int]]:
    return [state[r][r:] + state[r][:r] for r in range(4)]

def inv_shift_rows(state: list[list[int]]) -> list[list[int]]:
    return [state[r][-r:] + state[r][:-r] if r else state[r] for r in range(4)]

def mix_columns(state: list[list[int]]) -> list[list[int]]:
    new_state = [[0]*4 for _ in range(4)]
    for c in range(4):
        col = [state[r][c] for r in range(4)]
        new_state[0][c] = gmul(col[0],2)^gmul(col[1],3)^col[2]^col[3]
        new_state[1][c] = col[0]^gmul(col[1],2)^gmul(col[2],3)^col[3]
        new_state[2][c] = col[0]^col[1]^gmul(col[2],2)^gmul(col[3],3)
        new_state[3][c] = gmul(col[0],3)^col[1]^col[2]^gmul(col[3],2)
    return new_state

def inv_mix_columns(state: list[list[int]]) -> list[list[int]]:
    new_state = [[0]*4 for _ in range(4)]
    for c in range(4):
        col = [state[r][c] for r in range(4)]
        new_state[0][c] = gmul(col[0],0x0e)^gmul(col[1],0x0b)^gmul(col[2],0x0d)^gmul(col[3],0x09)
        new_state[1][c] = gmul(col[0],0x09)^gmul(col[1],0x0e)^gmul(col[2],0x0b)^gmul(col[3],0x0d)
        new_state[2][c] = gmul(col[0],0x0d)^gmul(col[1],0x09)^gmul(col[2],0x0e)^gmul(col[3],0x0b)
        new_state[3][c] = gmul(col[0],0x0b)^gmul(col[1],0x0d)^gmul(col[2],0x09)^gmul(col[3],0x0e)
    return new_state

#  AES BLOCK ENCRYPT / DECRYPT

def aes_encrypt_block(block: bytes, w: list[list[int]], nr: int) -> bytes:
    state = bytes_to_state(block)
    state = add_round_key(state, get_round_key(w, 0))
    for rnd in range(1, nr):
        state = sub_bytes(state)
        state = shift_rows(state)
        state = mix_columns(state)
        state = add_round_key(state, get_round_key(w, rnd))
    state = sub_bytes(state)
    state = shift_rows(state)
    state = add_round_key(state, get_round_key(w, nr))
    return state_to_bytes(state)

def aes_decrypt_block(block: bytes, w: list[list[int]], nr: int) -> bytes:
    state = bytes_to_state(block)
    state = add_round_key(state, get_round_key(w, nr))
    for rnd in range(nr-1, 0, -1):
        state = inv_shift_rows(state)
        state = inv_sub_bytes(state)
        state = add_round_key(state, get_round_key(w, rnd))
        state = inv_mix_columns(state)
    state = inv_shift_rows(state)
    state = inv_sub_bytes(state)
    state = add_round_key(state, get_round_key(w, 0))
    return state_to_bytes(state)

#  PADDING & FULL ENCRYPT/DECRYPT

def pad(data: bytes) -> bytes:
    pad_len = 16 - (len(data) % 16)
    return data + bytes([pad_len] * pad_len)

def unpad(data: bytes) -> bytes:
    return data[:-data[-1]]

def get_nr(key: bytes) -> int:
    return {16: 10, 24: 12, 32: 14}[len(key)]

def aes_encrypt(plaintext: bytes, key: bytes) -> bytes:
    w = key_expansion(key)
    nr = get_nr(key)
    padded = pad(plaintext)
    ct = b''
    for i in range(0, len(padded), 16):
        ct += aes_encrypt_block(padded[i:i+16], w, nr)
    return ct

def aes_decrypt(ciphertext: bytes, key: bytes) -> bytes:
    w = key_expansion(key)
    nr = get_nr(key)
    pt = b''
    for i in range(0, len(ciphertext), 16):
        pt += aes_decrypt_block(ciphertext[i:i+16], w, nr)
    return unpad(pt)

def generate_key(bits: int = 128) -> bytes:
    return os.urandom(bits // 8)

#  CLI

def _print_round_keys(key: bytes):
    w = key_expansion(key)
    nr = get_nr(key)
    bits = len(key) * 8
    print(f"\n  Output (Key): All Round Keys — AES-{bits} ({nr+1} total)")
    print("  " + "-"*50)
    for rnd in range(nr + 1):
        rk = get_round_key(w, rnd)
        rk_hex = ''.join(f'{rk[r][c]:02X}' for c in range(4) for r in range(4))
        print(f"  RK[{rnd:2d}]: {rk_hex}")
    print("  " + "-"*50)

def _get_key(bits: int) -> bytes:
    """Prompt user for a key or auto-generate one."""
    expected_hex_len = (bits // 8) * 2
    key_input = input(f"  Input 2: Key in hex ({expected_hex_len} chars), or press Enter to auto-generate\n  > ").strip()
    if not key_input:
        key = generate_key(bits)
        print(f"  [Auto-generated key]: {key.hex().upper()}")
        return key
    try:
        key_bytes = bytes.fromhex(key_input)
        if len(key_bytes) != bits // 8:
            print(f"  [ERROR] AES-{bits} key must be {bits//8} bytes ({expected_hex_len} hex chars). Auto-generating instead.")
            key = generate_key(bits)
            print(f"  [Auto-generated key]: {key.hex().upper()}")
            return key
        return key_bytes
    except ValueError:
        print("  [ERROR] Invalid hex. Auto-generating instead.")
        key = generate_key(bits)
        print(f"  [Auto-generated key]: {key.hex().upper()}")
        return key

def run():
    """Interactive CLI for AES."""
    print("\n" + "="*60)
    print("       AES (Advanced Encryption Standard)")
    print("="*60)

    while True:
        print("\n  [1] Encrypt")
        print("  [2] Decrypt")
        print("  [0] Back to Main Menu")
        choice = input("\n  Select option: ").strip()

        if choice == '0':
            break

        elif choice == '1':
            plaintext = input("\n  Input 1: Plaintext\n  > ").strip()
            print("  Select key size:")
            print("  [1] AES-128  [2] AES-192  [3] AES-256")
            ks = input("  Choice [default 1]: ").strip()
            bits = {'': 128, '1': 128, '2': 192, '3': 256}.get(ks, 128)
            key = _get_key(bits)
            pt_bytes = plaintext.encode('utf-8')
            ct_bytes = aes_encrypt(pt_bytes, key)
            print(f"\n  Output (Encryption): {ct_bytes.hex().upper()}")
            _print_round_keys(key)

        elif choice == '2':
            ct_input = input("\n  Input 1: Ciphertext (hex)\n  > ").strip()
            key_input_size = input("  Key size — [1] AES-128  [2] AES-192  [3] AES-256 [default 1]: ").strip()
            bits = {'': 128, '1': 128, '2': 192, '3': 256}.get(key_input_size, 128)
            key = _get_key(bits)
            try:
                ct_bytes = bytes.fromhex(ct_input)
                pt_bytes = aes_decrypt(ct_bytes, key)
                print(f"\n  Output (Decryption): {pt_bytes.decode('utf-8')}")
                _print_round_keys(key)
            except Exception as e:
                print(f"  [ERROR] {e}")

        else:
            print("  [ERROR] Invalid option.")
