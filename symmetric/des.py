"""
DES (Data Encryption Standard) - Full implementation from scratch.
56-bit key, 64-bit block cipher, 16 rounds of Feistel network.
"""

import os
import random

# ─────────────────────────────────────────────
#  DES TABLES
# ─────────────────────────────────────────────

# Initial Permutation (IP)
IP = [
    58,50,42,34,26,18,10, 2,
    60,52,44,36,28,20,12, 4,
    62,54,46,38,30,22,14, 6,
    64,56,48,40,32,24,16, 8,
    57,49,41,33,25,17, 9, 1,
    59,51,43,35,27,19,11, 3,
    61,53,45,37,29,21,13, 5,
    63,55,47,39,31,23,15, 7,
]

# Final Permutation (IP^-1)
IP_INV = [
    40, 8,48,16,56,24,64,32,
    39, 7,47,15,55,23,63,31,
    38, 6,46,14,54,22,62,30,
    37, 5,45,13,53,21,61,29,
    36, 4,44,12,52,20,60,28,
    35, 3,43,11,51,19,59,27,
    34, 2,42,10,50,18,58,26,
    33, 1,41, 9,49,17,57,25,
]

# Expansion (E)
E = [
    32, 1, 2, 3, 4, 5,
     4, 5, 6, 7, 8, 9,
     8, 9,10,11,12,13,
    12,13,14,15,16,17,
    16,17,18,19,20,21,
    20,21,22,23,24,25,
    24,25,26,27,28,29,
    28,29,30,31,32, 1,
]

# Permutation P
P = [
    16, 7,20,21,29,12,28,17,
     1,15,23,26, 5,18,31,10,
     2, 8,24,14,32,27, 3, 9,
    19,13,30, 6,22,11, 4,25,
]

# PC-1: 64-bit key → 56-bit (drops parity bits)
PC1 = [
    57,49,41,33,25,17, 9,
     1,58,50,42,34,26,18,
    10, 2,59,51,43,35,27,
    19,11, 3,60,52,44,36,
    63,55,47,39,31,23,15,
     7,62,54,46,38,30,22,
    14, 6,61,53,45,37,29,
    21,13, 5,28,20,12, 4,
]

# PC-2: 56-bit → 48-bit subkey
PC2 = [
    14,17,11,24, 1, 5,
     3,28,15, 6,21,10,
    23,19,12, 4,26, 8,
    16, 7,27,20,13, 2,
    41,52,31,37,47,55,
    30,40,51,45,33,48,
    44,49,39,56,34,53,
    46,42,50,36,29,32,
]

# Rotation schedule for key schedule
SHIFTS = [1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1]

# S-Boxes (8 boxes, each 4×16)
S_BOXES = [
    # S1
    [[14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7],
     [0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8],
     [4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0],
     [15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13]],
    # S2
    [[15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10],
     [3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5],
     [0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15],
     [13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9]],
    # S3
    [[10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8],
     [13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1],
     [13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7],
     [1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12]],
    # S4
    [[7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15],
     [13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9],
     [10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4],
     [3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14]],
    # S5
    [[2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9],
     [14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6],
     [4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14],
     [11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3]],
    # S6
    [[12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11],
     [10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8],
     [9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6],
     [4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13]],
    # S7
    [[4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1],
     [13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6],
     [1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2],
     [6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12]],
    # S8
    [[13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7],
     [1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2],
     [7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8],
     [2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11]],
]


# ─────────────────────────────────────────────
#  BIT MANIPULATION HELPERS
# ─────────────────────────────────────────────

def bytes_to_bits(data: bytes) -> list[int]:
    bits = []
    for byte in data:
        for i in range(7, -1, -1):
            bits.append((byte >> i) & 1)
    return bits


def bits_to_bytes(bits: list[int]) -> bytes:
    result = []
    for i in range(0, len(bits), 8):
        byte = 0
        for bit in bits[i:i+8]:
            byte = (byte << 1) | bit
        result.append(byte)
    return bytes(result)


def permute(bits: list[int], table: list[int]) -> list[int]:
    return [bits[t - 1] for t in table]


def xor_bits(a: list[int], b: list[int]) -> list[int]:
    return [x ^ y for x, y in zip(a, b)]


def left_rotate(bits: list[int], n: int) -> list[int]:
    return bits[n:] + bits[:n]


# ─────────────────────────────────────────────
#  KEY SCHEDULE
# ─────────────────────────────────────────────

def generate_key() -> bytes:
    """Generate a random 8-byte (64-bit) DES key."""
    return os.urandom(8)


def key_schedule(key_bytes: bytes) -> list[list[int]]:
    """Generate 16 round subkeys from 64-bit key."""
    key_bits = bytes_to_bits(key_bytes)
    key_56 = permute(key_bits, PC1)
    C, D = key_56[:28], key_56[28:]
    subkeys = []
    for i in range(16):
        C = left_rotate(C, SHIFTS[i])
        D = left_rotate(D, SHIFTS[i])
        subkey = permute(C + D, PC2)
        subkeys.append(subkey)
    return subkeys


# ─────────────────────────────────────────────
#  FEISTEL FUNCTION
# ─────────────────────────────────────────────

def f_function(R: list[int], subkey: list[int]) -> list[int]:
    """DES Feistel (F) function."""
    # Expansion
    expanded = permute(R, E)
    # XOR with subkey
    xored = xor_bits(expanded, subkey)
    # S-box substitution
    s_out = []
    for i in range(8):
        block = xored[i*6:(i+1)*6]
        row = (block[0] << 1) | block[5]
        col = (block[1] << 3) | (block[2] << 2) | (block[3] << 1) | block[4]
        val = S_BOXES[i][row][col]
        s_out += [(val >> (3 - j)) & 1 for j in range(4)]
    # Permutation P
    return permute(s_out, P)


# ─────────────────────────────────────────────
#  DES BLOCK CIPHER
# ─────────────────────────────────────────────

def des_block(block: bytes, subkeys: list[list[int]], encrypt: bool = True) -> bytes:
    """Encrypt or decrypt a single 8-byte block."""
    bits = bytes_to_bits(block)
    permuted = permute(bits, IP)
    L, R = permuted[:32], permuted[32:]

    keys = subkeys if encrypt else list(reversed(subkeys))
    for i in range(16):
        f_out = f_function(R, keys[i])
        new_R = xor_bits(L, f_out)
        L = R
        R = new_R

    combined = permute(R + L, IP_INV)
    return bits_to_bytes(combined)


# ─────────────────────────────────────────────
#  PADDING (PKCS#5)
# ─────────────────────────────────────────────

def pad(data: bytes) -> bytes:
    pad_len = 8 - (len(data) % 8)
    return data + bytes([pad_len] * pad_len)


def unpad(data: bytes) -> bytes:
    pad_len = data[-1]
    return data[:-pad_len]


# ─────────────────────────────────────────────
#  DES ECB MODE
# ─────────────────────────────────────────────

def des_encrypt(plaintext: bytes, key: bytes) -> bytes:
    subkeys = key_schedule(key)
    padded = pad(plaintext)
    ciphertext = b''
    for i in range(0, len(padded), 8):
        block = padded[i:i+8]
        ciphertext += des_block(block, subkeys, encrypt=True)
    return ciphertext


def des_decrypt(ciphertext: bytes, key: bytes) -> bytes:
    subkeys = key_schedule(key)
    plaintext = b''
    for i in range(0, len(ciphertext), 8):
        block = ciphertext[i:i+8]
        plaintext += des_block(block, subkeys, encrypt=False)
    return unpad(plaintext)


# ─────────────────────────────────────────────
#  CLI
# ─────────────────────────────────────────────

def _print_round_keys(key: bytes):
    subkeys = key_schedule(key)
    print(f"\n  Output (Key): All Round Keys (48 bits each)")
    print("  " + "-"*50)
    for i, sk in enumerate(subkeys, 1):
        sk_bytes = bits_to_bytes(sk + [0]*16)
        sk_hex = ''.join(f'{b:02X}' for b in sk_bytes[:6])
        print(f"  Round {i:2d}: {sk_hex}")
    print("  " + "-"*50)


def _get_key() -> bytes:
    """Prompt user for a key or auto-generate one."""
    key_input = input("  Input 2: Key in hex (16 chars), or press Enter to auto-generate\n  > ").strip()
    if not key_input:
        key = generate_key()
        print(f"  [Auto-generated key]: {key.hex().upper()}")
        return key
    try:
        key_bytes = bytes.fromhex(key_input)
        if len(key_bytes) != 8:
            print("  [ERROR] DES key must be exactly 8 bytes (16 hex chars). Auto-generating instead.")
            key = generate_key()
            print(f"  [Auto-generated key]: {key.hex().upper()}")
            return key
        return key_bytes
    except ValueError:
        print("  [ERROR] Invalid hex. Auto-generating instead.")
        key = generate_key()
        print(f"  [Auto-generated key]: {key.hex().upper()}")
        return key


def run():
    """Interactive CLI for DES."""
    print("\n" + "="*60)
    print("       DES (Data Encryption Standard)")
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
            key = _get_key()
            pt_bytes = plaintext.encode('utf-8')
            ct_bytes = des_encrypt(pt_bytes, key)
            print(f"\n  Output (Encryption): {ct_bytes.hex().upper()}")
            _print_round_keys(key)

        elif choice == '2':
            ct_input = input("\n  Input 1: Ciphertext (hex)\n  > ").strip()
            key = _get_key()
            try:
                ct_bytes = bytes.fromhex(ct_input)
                pt_bytes = des_decrypt(ct_bytes, key)
                print(f"\n  Output (Decryption): {pt_bytes.decode('utf-8')}")
                _print_round_keys(key)
            except Exception as e:
                print(f"  [ERROR] {e}")

        else:
            print("  [ERROR] Invalid option.")
