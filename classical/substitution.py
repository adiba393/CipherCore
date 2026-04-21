"""
Substitution Cipher: Encryption, Decryption, Brute Force, and Frequency Analysis
"""

import string
import random
from collections import Counter

# English letter frequency (approximate %)
ENGLISH_FREQ = {
    'E': 12.70, 'T': 9.06, 'A': 8.17, 'O': 7.51, 'I': 6.97,
    'N': 6.75, 'S': 6.33, 'H': 6.09, 'R': 5.99, 'D': 4.25,
    'L': 4.03, 'C': 2.78, 'U': 2.76, 'M': 2.41, 'W': 2.36,
    'F': 2.23, 'G': 2.02, 'Y': 1.97, 'P': 1.93, 'B': 1.49,
    'V': 0.98, 'K': 0.77, 'J': 0.15, 'X': 0.15, 'Q': 0.10, 'Z': 0.07
}


def validate_key(key: str) -> bool:
    """Validate that the key is a 26-letter permutation."""
    key = key.upper()
    return (len(key) == 26 and
            set(key) == set(string.ascii_uppercase))


def generate_random_key() -> str:
    """Generate a random substitution key."""
    letters = list(string.ascii_uppercase)
    random.shuffle(letters)
    return ''.join(letters)


def encrypt(plaintext: str, key: str) -> str:
    """Encrypt plaintext using the substitution key."""
    key = key.upper()
    ciphertext = []
    for ch in plaintext.upper():
        if ch in string.ascii_uppercase:
            idx = ord(ch) - ord('A')
            ciphertext.append(key[idx])
        else:
            ciphertext.append(ch)
    return ''.join(ciphertext)


def decrypt(ciphertext: str, key: str) -> str:
    """Decrypt ciphertext using the substitution key."""
    key = key.upper()
    # Build reverse key
    reverse_key = [''] * 26
    for i, ch in enumerate(key):
        reverse_key[ord(ch) - ord('A')] = chr(i + ord('A'))
    reverse_key_str = ''.join(reverse_key)

    plaintext = []
    for ch in ciphertext.upper():
        if ch in string.ascii_uppercase:
            idx = ord(ch) - ord('A')
            plaintext.append(reverse_key_str[idx])
        else:
            plaintext.append(ch)
    return ''.join(plaintext)


def frequency_analysis(text: str) -> dict:
    """Perform frequency analysis on the given text."""
    text = text.upper()
    letters_only = [ch for ch in text if ch in string.ascii_uppercase]
    total = len(letters_only)
    if total == 0:
        return {}
    counts = Counter(letters_only)
    freq = {ch: round((counts.get(ch, 0) / total) * 100, 2)
            for ch in string.ascii_uppercase}
    return freq


def frequency_attack(ciphertext: str) -> tuple[str, str]:
    """
    Attempt to break substitution cipher using frequency analysis.
    Maps cipher letters to English letters by frequency rank.
    Returns (guessed_key, decrypted_text).
    """
    cipher_freq = frequency_analysis(ciphertext)
    # Sort cipher letters by frequency (descending)
    cipher_sorted = sorted(cipher_freq.items(), key=lambda x: x[1], reverse=True)
    # Sort English letters by frequency (descending)
    english_sorted = sorted(ENGLISH_FREQ.items(), key=lambda x: x[1], reverse=True)

    # Build mapping: cipher letter -> guessed plain letter
    mapping = {}
    for (c_letter, _), (e_letter, _) in zip(cipher_sorted, english_sorted):
        mapping[c_letter] = e_letter

    # Build guessed key (A-Z in plaintext order -> cipher substitution reverse)
    # key[i] = what plain letter i maps to in cipher
    # We need the forward key: plain[i] -> cipher[key[i]]
    # mapping is cipher -> plain, so reverse: plain -> cipher
    reverse_mapping = {v: k for k, v in mapping.items()}
    guessed_key = ''.join(reverse_mapping.get(chr(i + ord('A')), '?')
                           for i in range(26))

    decrypted = []
    for ch in ciphertext.upper():
        if ch in string.ascii_uppercase:
            decrypted.append(mapping.get(ch, '?'))
        else:
            decrypted.append(ch)

    return guessed_key, ''.join(decrypted)


def print_key_table(key: str):
    """Pretty-print the substitution key as a mapping table."""
    key = key.upper()
    print("\n  Substitution Key Table:")
    print("  " + "-" * 54)
    print("  Plain : " + " ".join(string.ascii_uppercase))
    print("  Cipher: " + " ".join(key))
    print("  " + "-" * 54)


def print_freq_output(text: str):
    """Print frequency analysis output."""
    freq = frequency_analysis(text)
    sorted_freq = sorted(freq.items(), key=lambda x: x[1], reverse=True)
    print("\n  Output (Result of the frequency analysis):")
    print("  " + "-" * 44)
    for letter, pct in sorted_freq:
        if pct > 0:
            bar = '█' * int(pct / 0.5)
            print(f"  {letter}: {pct:5.2f}%  {bar}")
    print("  " + "-" * 44)


def brute_force_attack(ciphertext: str, top_n: int = 5) -> list:
    """
    Brute force attack using frequency analysis + hill climbing.
    Since 26! keys is too large to enumerate, we use:
    1. Frequency mapping as a starting point
    2. Hill climbing: swap pairs of key letters and keep improvements
    Returns top_n candidate (score, key, plaintext) tuples.
    """
    # Score text by comparing letter frequencies to English
    def score(text: str) -> float:
        freq = frequency_analysis(text)
        return sum(
            freq.get(ch, 0) * ENGLISH_FREQ.get(ch, 0)
            for ch in string.ascii_uppercase
        )

    # Start from frequency-mapped key
    cipher_freq = frequency_analysis(ciphertext)
    cipher_sorted = [ch for ch, _ in sorted(cipher_freq.items(), key=lambda x: x[1], reverse=True)]
    english_sorted = [ch for ch, _ in sorted(ENGLISH_FREQ.items(), key=lambda x: x[1], reverse=True)]
    mapping = dict(zip(cipher_sorted, english_sorted))

    # Build forward key from mapping (cipher->plain means plain->cipher is reverse)
    reverse_mapping = {v: k for k, v in mapping.items()}
    current_key = list(''.join(reverse_mapping.get(chr(i + ord('A')), 'A') for i in range(26)))

    current_decrypted = decrypt(ciphertext, ''.join(current_key))
    current_score = score(current_decrypted)

    candidates = [(current_score, ''.join(current_key), current_decrypted)]

    # Hill climbing: try swapping every pair of letters in the key
    improved = True
    iterations = 0
    max_iterations = 500
    while improved and iterations < max_iterations:
        improved = False
        iterations += 1
        for i in range(26):
            for j in range(i + 1, 26):
                new_key = current_key[:]
                new_key[i], new_key[j] = new_key[j], new_key[i]
                new_key_str = ''.join(new_key)
                new_decrypted = decrypt(ciphertext, new_key_str)
                new_score = score(new_decrypted)
                if new_score > current_score:
                    current_key = new_key
                    current_score = new_score
                    current_decrypted = new_decrypted
                    improved = True
                    candidates.append((current_score, new_key_str, current_decrypted))

    # Return unique top N by score
    seen_keys = set()
    unique = []
    for s, k, t in sorted(candidates, key=lambda x: x[0], reverse=True):
        if k not in seen_keys:
            seen_keys.add(k)
            unique.append((s, k, t))
        if len(unique) >= top_n:
            break
    return unique


def run():
    """Interactive CLI for Substitution Cipher."""
    print("\n" + "="*60)
    print("       SUBSTITUTION CIPHER")
    print("="*60)

    while True:
        print("\n  [1] Encrypt")
        print("  [2] Decrypt")
        print("  [3] Brute Force Attack")
        print("  [0] Back to Main Menu")
        choice = input("\n  Select option: ").strip()

        if choice == '0':
            break

        elif choice == '1':
            plaintext = input("\n  Input 1: Plaintext string\n  > ").strip()
            key_input = input("  Input 2: Key (26-letter permutation, or press Enter to auto-generate)\n  > ").strip()
            if not key_input:
                key_input = generate_random_key()
                print(f"  [Auto-generated key]: {key_input}")
            if not validate_key(key_input):
                print("  [ERROR] Key must be a 26-letter permutation of A-Z.")
                continue
            ciphertext = encrypt(plaintext, key_input)
            print(f"\n  Output (Encryption): {ciphertext}")
            print_freq_output(ciphertext)

        elif choice == '2':
            ciphertext = input("\n  Input 1: Ciphertext string\n  > ").strip()
            key_input = input("  Input 2: Key (26-letter permutation)\n  > ").strip()
            if not validate_key(key_input):
                print("  [ERROR] Key must be a 26-letter permutation of A-Z.")
                continue
            plaintext = decrypt(ciphertext, key_input)
            print(f"\n  Output (Decryption): {plaintext}")
            print_freq_output(plaintext)

        elif choice == '3':
            ciphertext = input("\n  Input 1: Ciphertext\n  > ").strip()
            if not ciphertext:
                print("  [ERROR] Please enter a ciphertext.")
                continue
            print("\n  [*] Running brute force attack...")
            print("  [*] Strategy: frequency mapping + hill climbing key refinement.")
            print("  [*] The 26! (~4 x 10^26) keyspace makes true brute force impossible,")
            print("  [*] so this uses intelligent search guided by English letter frequencies.")
            results = brute_force_attack(ciphertext)
            print(f"\n  Output (Brute Force Attack — Top {len(results)} candidates):")
            print("  " + "="*56)
            for rank, (sc, key, text) in enumerate(results, 1):
                print(f"\n  Rank #{rank}  (fitness score: {sc:.2f})")
                print(f"  Guessed Key : {key}")
                print(f"  Decrypted   : {text}")
            print("\n  " + "="*56)
            print("  [NOTE] Fitness score = sum of (cipher freq x English freq) per letter.")
            print("  Higher score = closer match to English. Works best on 100+ character texts.")
            print("  Short texts may give approximate results due to limited frequency data.")

        else:
            print("  [ERROR] Invalid option.")
