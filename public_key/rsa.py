"""
RSA - Full implementation from scratch.
Includes key generation, encryption, decryption, and factorization attack.
Uses Miller-Rabin primality test and modular exponentiation.
"""

import random
import math

#  MATH HELPERS

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

#  RSA CORE

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

#  FACTORIZATION ATTACKS

def factorization_attack(n: int) -> tuple:
    """
    Trial division with a hard cap of 2M iterations (~1-2 seconds max).
    Fast enough to factor numbers up to ~44-bit. For larger n it gives up
    and returns None so the UI can show a 'too large' message.
    """
    if n < 4:
        return None
    if n % 2 == 0:
        return (2, n // 2)
    i = 3
    cap = min(int(n**0.5) + 1, 2_000_000)
    while i <= cap:
        if n % i == 0:
            return (i, n // i)
        i += 2
    return None


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

#  FACTORIZATION ATTACKS

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

