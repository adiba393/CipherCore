import string
from collections import Counter

PAD = ' '


def parse_key(key_str: str) -> list:
    parts = [int(x.strip()) for x in key_str.strip().split(',')]
    return [p - 1 for p in parts]


def apply_col_permutation(matrix, key2):
    n_cols = len(key2)
    return [[matrix[r][key2[c]] for c in range(n_cols)] for r in range(len(matrix))]


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
    n_rows, n_cols = len(key1), len(key2)
    total  = n_rows * n_cols
    padded = plaintext + PAD * (total - len(plaintext))

    matrix = [list(padded[r * n_cols:(r + 1) * n_cols]) for r in range(n_rows)]
    print_matrix(matrix, "Step 1: Original matrix")

    matrix = apply_col_permutation(matrix, key2)
    print_matrix(matrix, f"Step 2: After column permutation {[k+1 for k in key2]}")

    matrix = apply_row_permutation(matrix, key1)
    print_matrix(matrix, f"Step 3: After row permutation {[k+1 for k in key1]}")

    return ''.join(cell for row in matrix for cell in row)


def decrypt(ciphertext, key1, key2):
    n_rows, n_cols = len(key1), len(key2)
    matrix = [list(ciphertext[r * n_cols:(r + 1) * n_cols]) for r in range(n_rows)]
    matrix = apply_row_permutation(matrix, invert_permutation(key1))
    matrix = apply_col_permutation(matrix, invert_permutation(key2))
    return ''.join(cell for row in matrix for cell in row)


def frequency_analysis(text):
    letters = [ch.upper() for ch in text if ch.upper() in string.ascii_uppercase]
    total   = len(letters)
    if total == 0:
        return {}
    counts = Counter(letters)
    return {ch: round((counts.get(ch, 0) / total) * 100, 2)
            for ch in string.ascii_uppercase}


def print_freq_output(text):
    freq        = frequency_analysis(text)
    sorted_freq = sorted(freq.items(), key=lambda x: x[1], reverse=True)
    print("\n  Output (Result of the frequency analysis):")
    print("  " + "-" * 44)
    for letter, pct in sorted_freq:
        if pct > 0:
            bar = '█' * int(pct / 0.5)
            print(f"  {letter}: {pct:5.2f}%  {bar}")
    print("  " + "-" * 44)


ENGLISH_FREQ = {
    'E': 12.70, 'T': 9.06, 'A': 8.17, 'O': 7.51, 'I': 6.97,
    'N': 6.75, 'S': 6.33, 'H': 6.09, 'R': 5.99, 'D': 4.25,
    'L': 4.03, 'C': 2.78, 'U': 2.76, 'M': 2.41, 'W': 2.36,
    'F': 2.23, 'G': 2.02, 'Y': 1.97, 'P': 1.93, 'B': 1.49,
    'V': 0.98, 'K': 0.77, 'J': 0.15, 'X': 0.15, 'Q': 0.10, 'Z': 0.07
}


def score_text(text: str) -> float:
    freq = frequency_analysis(text)
    return sum(freq.get(ch, 0) * ENGLISH_FREQ.get(ch, 0) for ch in string.ascii_uppercase)


def brute_force_attack(ciphertext: str, key1_len: int, key2_len: int,
                       max_keys: int = 50000, top_n: int = 5) -> dict:
    """
    Tries all permutations of row/column keys up to max_keys combinations.
    For small key lengths (e.g. 3×3) this is complete. For larger keys it
    samples randomly since the space grows as (r! × c!).
    """
    from itertools import permutations
    import math, random as rng

    total_space = math.factorial(key1_len) * math.factorial(key2_len)
    candidates  = []
    tried       = 0
    exhaustive  = total_space <= max_keys

    all_k1 = list(permutations(range(key1_len)))
    all_k2 = list(permutations(range(key2_len)))

    if exhaustive:
        pairs = [(k1, k2) for k1 in all_k1 for k2 in all_k2]
    else:
        # Random sample without replacement up to max_keys
        pool = [(k1, k2) for k1 in all_k1 for k2 in all_k2]
        rng.shuffle(pool)
        pairs = pool[:max_keys]

    total_len = key1_len * key2_len
    if len(ciphertext) < total_len:
        ciphertext = ciphertext + ' ' * (total_len - len(ciphertext))
    if len(ciphertext) != total_len:
        return {'error': f'Ciphertext length {len(ciphertext)} must equal {key1_len}×{key2_len}={total_len}'}

    for k1, k2 in pairs:
        tried += 1
        try:
            pt = decrypt(ciphertext, list(k1), list(k2))
            s  = score_text(pt)
            candidates.append((s, list(k1), list(k2), pt))
        except Exception:
            continue

    candidates.sort(key=lambda x: x[0], reverse=True)
    top = [
        {
            'score':   round(s, 2),
            'key1':    [k + 1 for k in k1],
            'key2':    [k + 1 for k in k2],
            'plaintext': pt
        }
        for s, k1, k2, pt in candidates[:top_n]
    ]

    return {
        'tried':      tried,
        'total_space': total_space,
        'exhaustive': exhaustive,
        'top':        top,
        'warning':    None if exhaustive else f'Space too large ({total_space:,} combos) — sampled {tried:,} random keys.'
    }


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

        elif choice in ('1', '2'):
            text  = input("\n  Input 1: " + ("Plaintext" if choice == '1' else "Ciphertext") + "\n  > ").rstrip('\n')
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

            if choice == '1':
                if len(text) > total:
                    print(f"  [ERROR] Plaintext ({len(text)} chars) exceeds matrix size ({total} cells).")
                    continue
                result = encrypt(text, key1, key2)
                print(f"\n  Output (Encryption): {result}")
                print_freq_output(result)
            else:
                if len(text) > total:
                    print(f"  [ERROR] Ciphertext ({len(text)} chars) longer than matrix ({total} cells).")
                    continue
                if len(text) < total:
                    text = text + ' ' * (total - len(text))
                result = decrypt(text, key1, key2)
                print(f"\n  Output (Decryption): {result}")
                print_freq_output(result)
        else:
            print("  [ERROR] Invalid option.")
