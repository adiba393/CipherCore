import string
import random
from collections import Counter

ENGLISH_FREQ = {
    'E': 12.70, 'T': 9.06, 'A': 8.17, 'O': 7.51, 'I': 6.97,
    'N': 6.75, 'S': 6.33, 'H': 6.09, 'R': 5.99, 'D': 4.25,
    'L': 4.03, 'C': 2.78, 'U': 2.76, 'M': 2.41, 'W': 2.36,
    'F': 2.23, 'G': 2.02, 'Y': 1.97, 'P': 1.93, 'B': 1.49,
    'V': 0.98, 'K': 0.77, 'J': 0.15, 'X': 0.15, 'Q': 0.10, 'Z': 0.07
}


def validate_key(key: str) -> bool:
    key = key.upper()
    return len(key) == 26 and set(key) == set(string.ascii_uppercase)


def generate_random_key() -> str:
    letters = list(string.ascii_uppercase)
    random.shuffle(letters)
    return ''.join(letters)


def encrypt(plaintext: str, key: str) -> str:
    key = key.upper()
    result = []
    for ch in plaintext.upper():
        if ch in string.ascii_uppercase:
            result.append(key[ord(ch) - ord('A')])
        else:
            result.append(ch)
    return ''.join(result)


def decrypt(ciphertext: str, key: str) -> str:
    key = key.upper()
    reverse_key = [''] * 26
    for i, ch in enumerate(key):
        reverse_key[ord(ch) - ord('A')] = chr(i + ord('A'))
    reverse_key_str = ''.join(reverse_key)
    result = []
    for ch in ciphertext.upper():
        if ch in string.ascii_uppercase:
            result.append(reverse_key_str[ord(ch) - ord('A')])
        else:
            result.append(ch)
    return ''.join(result)


def frequency_analysis(text: str) -> dict:
    text = text.upper()
    letters = [ch for ch in text if ch in string.ascii_uppercase]
    total = len(letters)
    if total == 0:
        return {}
    counts = Counter(letters)
    return {ch: round((counts.get(ch, 0) / total) * 100, 2)
            for ch in string.ascii_uppercase}


def brute_force_attack(ciphertext: str, top_n: int = 5) -> dict:
    """
    Two-phase attack. Phase 1 maps cipher letters to English by frequency rank —
    fast but imprecise. Phase 2 does hill climbing: swap key letter pairs and keep
    anything that improves the English-likeness score. Bails out if time or memory
    runs over so it never hangs.
    """
    import tracemalloc, time

    def score(text: str) -> float:
        freq = frequency_analysis(text)
        return sum(freq.get(ch, 0) * ENGLISH_FREQ.get(ch, 0)
                   for ch in string.ascii_uppercase)

    cipher_freq = frequency_analysis(ciphertext)
    cipher_sorted  = [ch for ch, _ in sorted(cipher_freq.items(), key=lambda x: x[1], reverse=True)]
    english_sorted = [ch for ch, _ in sorted(ENGLISH_FREQ.items(), key=lambda x: x[1], reverse=True)]
    mapping = dict(zip(cipher_sorted, english_sorted))
    reverse_mapping = {v: k for k, v in mapping.items()}
    freq_key       = ''.join(reverse_mapping.get(chr(i + ord('A')), 'A') for i in range(26))
    freq_decrypted = decrypt(ciphertext, freq_key)
    freq_score     = score(freq_decrypted)

    phase1 = {'key': freq_key, 'text': freq_decrypted, 'score': round(freq_score, 2)}

    tracemalloc.start()
    start_time    = time.time()
    MAX_TIME      = 10
    MAX_MB        = 100
    memory_hit    = False
    timeout_hit   = False

    current_key       = list(freq_key)
    current_decrypted = freq_decrypted
    current_score     = freq_score
    candidates        = [(current_score, freq_key, freq_decrypted)]
    iterations        = 0

    try:
        improved = True
        while improved and iterations < 800:
            improved = False
            iterations += 1
            if time.time() - start_time > MAX_TIME:
                timeout_hit = True
                break
            _, peak = tracemalloc.get_traced_memory()
            if peak / 1024 / 1024 > MAX_MB:
                memory_hit = True
                break
            for i in range(26):
                for j in range(i + 1, 26):
                    new_key = current_key[:]
                    new_key[i], new_key[j] = new_key[j], new_key[i]
                    new_key_str   = ''.join(new_key)
                    new_decrypted = decrypt(ciphertext, new_key_str)
                    new_score     = score(new_decrypted)
                    if new_score > current_score:
                        current_key       = new_key
                        current_score     = new_score
                        current_decrypted = new_decrypted
                        improved          = True
                        candidates.append((current_score, new_key_str, new_decrypted))
    except MemoryError:
        memory_hit = True
    finally:
        tracemalloc.stop()

    seen, unique = set(), []
    for s, k, t in sorted(candidates, key=lambda x: x[0], reverse=True):
        if k not in seen:
            seen.add(k)
            unique.append({'score': round(s, 2), 'key': k, 'text': t})
        if len(unique) >= top_n:
            break

    warning = None
    if memory_hit:
        warning = 'Memory limit reached — showing frequency analysis result only.'
    elif timeout_hit:
        warning = 'Time limit reached — partial hill climbing result shown.'

    return {
        'phase1': phase1,
        'phase2_candidates': unique,
        'method': 'frequency_mapping_only' if (memory_hit or timeout_hit) else 'hill_climbing',
        'warning': warning,
        'iterations': iterations
    }


def print_freq_output(text: str):
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
            key_input  = input("  Input 2: Key (26-letter permutation)\n  > ").strip()
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
            print("\n  Running attack...")
            result = brute_force_attack(ciphertext)
            if result['warning']:
                print(f"  [!] {result['warning']}")
            print(f"\n  Phase 1 (frequency mapping):")
            print(f"  Key : {result['phase1']['key']}")
            print(f"  Text: {result['phase1']['text']}")
            if result['phase2_candidates']:
                print(f"\n  Phase 2 (hill climbing — {result['iterations']} iterations):")
                for i, c in enumerate(result['phase2_candidates'], 1):
                    print(f"  #{i} score={c['score']}  key={c['key']}")
                    print(f"      {c['text']}")
        else:
            print("  [ERROR] Invalid option.")
