"""
RSA - Full implementation from scratch.
Includes key generation, encryption, decryption, and factorization attack.
Uses Miller-Rabin primality test and modular exponentiation.
"""

import random
import math


# ─────────────────────────────────────────────
#  MATH HELPERS
# ─────────────────────────────────────────────

def mod_exp(base: int, exp: int, mod: int) -> int:
    """Fast modular exponentiation."""
    result = 1
    base %= mod
    while exp > 0:
        if exp & 1:
            result = (result * base) % mod
        base = (base * base) % mod
        exp >>= 1
    return result


def miller_rabin(n: int, k: int = 20) -> bool:
    """Probabilistic primality test. Returns True if n is likely prime."""
    if n < 2:
        return False
    if n in (2, 3, 5, 7):
        return True
    if n % 2 == 0:
        return False

    # Write n-1 as 2^r * d
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    for _ in range(k):
        a = random.randrange(2, n - 2)
        x = mod_exp(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = (x * x) % n
            if x == n - 1:
                break
        else:
            return False
    return True


def generate_prime(bits: int) -> int:
    """Generate a random prime of the given bit length."""
    while True:
        n = random.getrandbits(bits) | (1 << (bits - 1)) | 1
        if miller_rabin(n):
            return n


def extended_gcd(a: int, b: int) -> tuple[int, int, int]:
    """Extended Euclidean Algorithm. Returns (gcd, x, y) where ax + by = gcd."""
    if b == 0:
        return a, 1, 0
    g, x, y = extended_gcd(b, a % b)
    return g, y, x - (a // b) * y


def mod_inverse(a: int, m: int) -> int:
    """Modular inverse of a mod m."""
    g, x, _ = extended_gcd(a % m, m)
    if g != 1:
        raise ValueError("Modular inverse does not exist.")
    return x % m


# ─────────────────────────────────────────────
#  RSA CORE
# ─────────────────────────────────────────────

def generate_rsa_keys(bits: int = 1024) -> dict:
    """
    Generate RSA key pair.
    bits: total modulus size (each prime is bits//2).
    """
    half = bits // 2
    print(f"\n  [*] Generating {bits}-bit RSA key pair...")
    print(f"  [*] Finding prime p ({half} bits)...")
    p = generate_prime(half)
    print(f"  [*] Finding prime q ({half} bits)...")
    q = generate_prime(half)
    while q == p:
        q = generate_prime(half)

    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537  # Common public exponent
    d = mod_inverse(e, phi)

    return {
        'n': n, 'e': e, 'd': d,
        'p': p, 'q': q, 'phi': phi,
        'bits': bits
    }


def rsa_encrypt(message: str, n: int, e: int) -> int:
    """Encrypt a string message as an integer."""
    m_bytes = message.encode('utf-8')
    m_int = int.from_bytes(m_bytes, 'big')
    if m_int >= n:
        raise ValueError("Message too long for key size.")
    return mod_exp(m_int, e, n)


def rsa_decrypt(ciphertext: int, n: int, d: int) -> str:
    """Decrypt an integer ciphertext back to string."""
    m_int = mod_exp(ciphertext, d, n)
    m_bytes = m_int.to_bytes((m_int.bit_length() + 7) // 8, 'big')
    return m_bytes.decode('utf-8')


# ─────────────────────────────────────────────
#  FACTORIZATION ATTACKS
# ─────────────────────────────────────────────

def trial_division_attack(n: int, limit: int = 10**6) -> tuple[int, int] | None:
    """Trial division: try small primes up to limit."""
    if n % 2 == 0:
        return 2, n // 2
    i = 3
    while i * i <= n and i <= limit:
        if n % i == 0:
            return i, n // i
        i += 2
    return None


def pollard_rho(n: int, max_iter: int = 100000) -> int | None:
    """
    Pollard's Rho algorithm for integer factorization.
    Returns a non-trivial factor of n, or None.
    """
    if n % 2 == 0:
        return 2
    x = random.randint(2, n - 1)
    y = x
    c = random.randint(1, n - 1)
    d = 1
    for _ in range(max_iter):
        x = (x * x + c) % n
        y = (y * y + c) % n
        y = (y * y + c) % n
        d = math.gcd(abs(x - y), n)
        if d != 1 and d != n:
            return d
        if d == n:
            break
    return None


def factorization_attack(n: int, bits: int) -> tuple[int, int] | None:
    """
    Attempt to factor n using trial division and Pollard's Rho.
    Only feasible for small key sizes (~64-256 bits for demo).
    """
    if bits > 256:
        return None  # Not feasible

    print("  [*] Attempting trial division (primes up to 10^6)...")
    result = trial_division_attack(n)
    if result:
        return result

    print("  [*] Attempting Pollard's Rho algorithm...")
    for _ in range(20):  # Multiple attempts with random seeds
        factor = pollard_rho(n)
        if factor and factor != n:
            return factor, n // factor
    return None


# ─────────────────────────────────────────────
#  CLI
# ─────────────────────────────────────────────

def _do_factorization(keys: dict):
    """Run factorization attack and print results."""
    n_val = keys['n']
    bits_val = keys['bits']
    print(f"\n  Factorization Attack on n ({bits_val} bits)...")
    if bits_val > 256:
        print(f"  [NOTE] Key is {bits_val} bits — factorization is not feasible in practice.")
        print("  Use a 64-bit key to see a live attack demo.")
        return
    result = factorization_attack(n_val, bits_val)
    if result:
        p_found, q_found = result
        phi_found = (p_found - 1) * (q_found - 1)
        d_found = mod_inverse(keys['e'], phi_found)
        print("\n  [SUCCESS] n factored!")
        print(f"  p             = {p_found}")
        print(f"  q             = {q_found}")
        print(f"  phi(n)        = {phi_found}")
        print(f"  Recovered d   = {hex(d_found)}")
        if d_found == keys['d']:
            print("  [+] Recovered private key matches original!")
    else:
        print("  [FAILED] Could not factor n with available algorithms.")


def run():
    """Interactive CLI for RSA."""
    print("\n" + "="*60)
    print("       RSA (Rivest-Shamir-Adleman)")
    print("="*60)

    keys = None

    while True:
        print("\n  [1] Generate Keys")
        print("  [2] Encrypt")
        print("  [3] Decrypt")
        print("  [0] Back to Main Menu")
        choice = input("\n  Select option: ").strip()

        if choice == '0':
            break

        elif choice == '1':
            print("\n  Select key size:")
            print("  [1] 512 bits")
            print("  [2] 1024 bits")
            print("  [3] 2048 bits")
            print("  [4] 64 bits (fast demo — supports factorization attack)")
            ks = input("  Choice [default 1]: ").strip()
            bits_map = {'': 512, '1': 512, '2': 1024, '3': 2048, '4': 64}
            bits = bits_map.get(ks, 512)
            keys = generate_rsa_keys(bits)
            print(f"\n  " + "-"*56)
            print(f"  RSA-{bits} Key Pair")
            print(f"  " + "-"*56)
            print(f"  Public Key  e : {keys['e']}")
            print(f"  Public Key  n : {hex(keys['n'])}")
            print(f"  Private Key d : {hex(keys['d'])}")
            print(f"  " + "-"*56)
            print(f"  p   : {hex(keys['p'])}")
            print(f"  q   : {hex(keys['q'])}")
            print(f"  phi : {hex(keys['phi'])}")

        elif choice == '2':
            if keys is None:
                print("\n  [ERROR] Generate keys first (option 1).")
                continue
            msg = input("\n  Input 1: Plaintext\n  > ").strip()
            try:
                ct = rsa_encrypt(msg, keys['n'], keys['e'])
                keys['last_ct'] = ct
                print(f"\n  Output (Public Key):")
                print(f"    e = {keys['e']}")
                print(f"    n = {hex(keys['n'])}")
                print(f"  Output (Private Key):")
                print(f"    d = {hex(keys['d'])}")
                print(f"  Output (Ciphertext):")
                print(f"    int = {ct}")
                print(f"    hex = {hex(ct)}")
                _do_factorization(keys)
            except ValueError as e:
                print(f"\n  [ERROR] {e}")
                print("  Tip: use a shorter message or a larger key size.")

        elif choice == '3':
            if keys is None:
                print("\n  [ERROR] Generate keys first (option 1).")
                continue
            ct_in = input("\n  Input 1: Ciphertext (integer or hex with 0x prefix)\n  > ").strip()
            try:
                ct = int(ct_in, 16) if ct_in.startswith('0x') else int(ct_in)
            except ValueError:
                print("  [ERROR] Invalid ciphertext format.")
                continue
            try:
                pt = rsa_decrypt(ct, keys['n'], keys['d'])
                print(f"\n  Output (Public Key):")
                print(f"    e = {keys['e']}")
                print(f"    n = {hex(keys['n'])}")
                print(f"  Output (Private Key):")
                print(f"    d = {hex(keys['d'])}")
                print(f"  Output (Plaintext): {pt}")
                _do_factorization(keys)
            except Exception as e:
                print(f"  [ERROR] Decryption failed: {e}")

        else:
            print("  [ERROR] Invalid option.")
