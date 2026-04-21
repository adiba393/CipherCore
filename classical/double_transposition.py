"""
Double Transposition Cipher: Encryption and Decryption.

How it works:
- Key1 (length r) = row permutation  → determines number of rows
- Key2 (length c) = column permutation → determines number of columns
- Matrix size = r × c
- Fill plaintext row by row, pad with '#' if needed
- Apply column permutation (Key2) first
- Apply row permutation (Key1) second
- Read result row by row as ciphertext
"""

import string
from collections import Counter

PAD = ' '


def parse_key(key_str: str) -> list:
    parts = [int(x.strip()) for x in key_str.strip().split(',')]
    return [p - 1 for p in parts]


def apply_col_permutation(matrix, key2):
    n_rows = len(matrix)
    n_cols = len(key2)
    result = []
    for r in range(n_rows):
        new_row = [matrix[r][key2[c]] for c in range(n_cols)]
        result.append(new_row)
    return result


def apply_row_permutation(matrix, key1):
    return [matrix[key1[r]] for r in range(len(key1))]


def invert_permutation(key):
    inv = [0] * len(key)
    for i, k in enumerate(key):
        inv[k] = i
    return inv


def print_matrix(matrix, label):
    print(f"\n  {label}:")
    n_cols = len(matrix[0])
    print("  +" + "---+" * n_cols)
    for row in matrix:
        print("  | " + " | ".join(str(c) for c in row) + " |")
    print("  +" + "---+" * n_cols)


def encrypt(plaintext, key1, key2):
    n_rows = len(key1)
    n_cols = len(key2)
    total = n_rows * n_cols
    padded = plaintext + PAD * (total - len(plaintext))

    matrix = [list(padded[r * n_cols:(r + 1) * n_cols]) for r in range(n_rows)]
    print_matrix(matrix, "Step 1: Original matrix (filled row by row)")

    matrix = apply_col_permutation(matrix, key2)
    print_matrix(matrix, f"Step 2: After column permutation {[k+1 for k in key2]}")

    matrix = apply_row_permutation(matrix, key1)
    print_matrix(matrix, f"Step 3: After row permutation {[k+1 for k in key1]}")

    return ''.join(cell for row in matrix for cell in row)


def decrypt(ciphertext, key1, key2):
    n_rows = len(key1)
    n_cols = len(key2)
    matrix = [list(ciphertext[r * n_cols:(r + 1) * n_cols]) for r in range(n_rows)]

    inv_key1 = invert_permutation(key1)
    matrix = apply_row_permutation(matrix, inv_key1)

    inv_key2 = invert_permutation(key2)
    matrix = apply_col_permutation(matrix, inv_key2)

    return ''.join(cell for row in matrix for cell in row)


def frequency_analysis(text):
    letters = [ch.upper() for ch in text if ch.upper() in string.ascii_uppercase]
    total = len(letters)
    if total == 0:
        return {}
    counts = Counter(letters)
    return {ch: round((counts.get(ch, 0) / total) * 100, 2)
            for ch in string.ascii_uppercase}


def print_freq_output(text):
    freq = frequency_analysis(text)
    sorted_freq = sorted(freq.items(), key=lambda x: x[1], reverse=True)
    print("\n  Output (Result of the frequency analysis):")
    print("  " + "-" * 44)
    for letter, pct in sorted_freq:
        if pct > 0:
            bar = '█' * int(pct / 0.5)
            print(f"  {letter}: {pct:5.2f}%  {bar}")
    print("  " + "-" * 44)


def run():
    print("\n" + "="*60)
    print("       DOUBLE TRANSPOSITION CIPHER")
    print("="*60)

    while True:
        print("\n  [1] Encrypt")
        print("  [2] Decrypt")
        print("  [0] Back to Main Menu")
        choice = input("\n  Select option: ").strip()

        if choice == '0':
            break

        elif choice == '1':
            plaintext = input("\n  Input 1: Plaintext\n  > ").rstrip('\n')
            k1_str = input("  Input 2: Key 1 - row permutation (e.g. 3,5,1,4,2)\n  > ").strip()
            k2_str = input("  Input 3: Key 2 - column permutation (e.g. 1,3,2)\n  > ").strip()

            try:
                key1 = parse_key(k1_str)
                key2 = parse_key(k2_str)
            except ValueError:
                print("  [ERROR] Keys must be comma-separated integers e.g. 3,1,4,2")
                continue

            n_rows, n_cols = len(key1), len(key2)
            total = n_rows * n_cols
            pad_count = total - len(plaintext)

            if len(plaintext) > total:
                print(f"  [ERROR] Plaintext ({len(plaintext)} chars) exceeds matrix size ({total} cells).")
                continue

            print(f"\n  Matrix: {n_rows} rows × {n_cols} cols = {total} cells")
            if pad_count > 0:
                print(f"  Padding {pad_count} '#' character(s) added")

            ciphertext = encrypt(plaintext, key1, key2)
            print(f"\n  Output (Encryption): {ciphertext}")
            print_freq_output(ciphertext)

        elif choice == '2':
            ciphertext = input("\n  Input 1: Ciphertext\n  > ").rstrip('\n')
            k1_str = input("  Input 2: Key 1 - row permutation (e.g. 3,5,1,4,2)\n  > ").strip()
            k2_str = input("  Input 3: Key 2 - column permutation (e.g. 1,3,2)\n  > ").strip()

            try:
                key1 = parse_key(k1_str)
                key2 = parse_key(k2_str)
            except ValueError:
                print("  [ERROR] Keys must be comma-separated integers e.g. 3,1,4,2")
                continue

            n_rows, n_cols = len(key1), len(key2)
            total = n_rows * n_cols

            if len(ciphertext) > total:
                print(f"  [ERROR] Ciphertext ({len(ciphertext)} chars) is longer than matrix size ({total} cells).")
                continue
            if len(ciphertext) < total:
                ciphertext = ciphertext + ' ' * (total - len(ciphertext))

            plaintext = decrypt(ciphertext, key1, key2)
            print(f"\n  Output (Decryption): {plaintext}")
            print_freq_output(plaintext)

        else:
            print("  [ERROR] Invalid option.")
