"""
ECC (Elliptic Curve Cryptography) - Full implementation from scratch.
Supports custom domain parameters over prime fields.
Implements ECDH key exchange.
"""

import random
from typing import Optional


# ─────────────────────────────────────────────
#  POINT ON ELLIPTIC CURVE
# ─────────────────────────────────────────────

class ECPoint:
    """Represents a point on an elliptic curve (or the point at infinity)."""

    def __init__(self, x: Optional[int], y: Optional[int],
                 curve: 'EllipticCurve'):
        self.x = x
        self.y = y
        self.curve = curve
        self.is_infinity = (x is None and y is None)

    def __eq__(self, other):
        if not isinstance(other, ECPoint):
            return False
        return (self.is_infinity == other.is_infinity and
                self.x == other.x and self.y == other.y)

    def __repr__(self):
        if self.is_infinity:
            return "O (Point at Infinity)"
        return f"({self.x}, {self.y})"

    def __neg__(self):
        if self.is_infinity:
            return self
        return ECPoint(self.x, (-self.y) % self.curve.p, self.curve)


class EllipticCurve:
    """
    Elliptic curve: y² = x³ + ax + b (mod p)
    Domain parameters: p, a, b, G (generator), n (order of G)
    """

    def __init__(self, p: int, a: int, b: int):
        self.p = p
        self.a = a
        self.b = b
        self._validate()

    def _validate(self):
        # Discriminant must be non-zero: 4a³ + 27b² ≠ 0 (mod p)
        disc = (4 * pow(self.a, 3, self.p) + 27 * pow(self.b, 2, self.p)) % self.p
        if disc == 0:
            raise ValueError("Invalid curve: discriminant is zero (singular curve).")

    def is_on_curve(self, point: ECPoint) -> bool:
        if point.is_infinity:
            return True
        lhs = pow(point.y, 2, self.p)
        rhs = (pow(point.x, 3, self.p) + self.a * point.x + self.b) % self.p
        return lhs == rhs

    def infinity(self) -> ECPoint:
        return ECPoint(None, None, self)

    def point(self, x: int, y: int) -> ECPoint:
        return ECPoint(x, y, self)

    def add(self, P: ECPoint, Q: ECPoint) -> ECPoint:
        """Point addition on the curve."""
        if P.is_infinity:
            return Q
        if Q.is_infinity:
            return P
        if P.x == Q.x and P.y != Q.y:
            return self.infinity()

        p = self.p
        if P == Q:
            # Point doubling
            if P.y == 0:
                return self.infinity()
            lam_num = (3 * P.x * P.x + self.a) % p
            lam_den = pow(2 * P.y, p - 2, p)  # modular inverse
        else:
            # Point addition
            lam_num = (Q.y - P.y) % p
            lam_den = pow((Q.x - P.x) % p, p - 2, p)

        lam = (lam_num * lam_den) % p
        x3 = (lam * lam - P.x - Q.x) % p
        y3 = (lam * (P.x - x3) - P.y) % p
        return ECPoint(x3, y3, self)

    def scalar_mul(self, k: int, P: ECPoint) -> ECPoint:
        """Scalar multiplication using double-and-add."""
        result = self.infinity()
        addend = P
        k = k % (P.curve.p if hasattr(P.curve, 'n') else P.curve.p)
        while k:
            if k & 1:
                result = self.add(result, addend)
            addend = self.add(addend, addend)
            k >>= 1
        return result

    def generate_all_points(self, G: ECPoint, n: int) -> list[ECPoint]:
        """Generate all multiples of G: G, 2G, ..., nG."""
        points = []
        current = G
        for i in range(1, n + 1):
            points.append((i, current))
            current = self.add(current, G)
            if current.is_infinity:
                break
        return points


# ─────────────────────────────────────────────
#  PREDEFINED CURVES
# ─────────────────────────────────────────────

PREDEFINED_CURVES = {
    'tiny': {
        'p': 23, 'a': 1, 'b': 1,
        'Gx': 3, 'Gy': 10, 'n': 28,
        'desc': 'Tiny curve y²=x³+x+1 (mod 23) — good for demonstration'
    },
    'small': {
        'p': 97, 'a': 2, 'b': 3,
        'Gx': 3, 'Gy': 6, 'n': 5,
        'desc': 'Small curve y²=x³+2x+3 (mod 97)'
    },
    'p17': {
        'p': 17, 'a': 2, 'b': 2,
        'Gx': 5, 'Gy': 1, 'n': 19,
        'desc': 'Textbook curve y²=x³+2x+2 (mod 17)'
    }
}


# ─────────────────────────────────────────────
#  ECDH KEY EXCHANGE
# ─────────────────────────────────────────────

def ecdh_key_exchange(curve: EllipticCurve, G: ECPoint, n: int):
    """Simulate ECDH between Alice (a) and Bob (b)."""
    print("\n  ─── Elliptic Curve Diffie-Hellman Key Exchange ───")
    print(f"  G = {G}")

    a = random.randint(2, n - 1)
    b = random.randint(2, n - 1)
    print(f"\n  Alice's private key a = {a}")
    print(f"  Bob's   private key b = {b}")

    A = curve.scalar_mul(a, G)  # Alice's public key
    B = curve.scalar_mul(b, G)  # Bob's public key
    print(f"\n  Alice's public key A = aG = {A}")
    print(f"  Bob's   public key B = bG = {B}")

    shared_A = curve.scalar_mul(a, B)  # Alice computes a*B
    shared_B = curve.scalar_mul(b, A)  # Bob computes b*A
    print(f"\n  Alice computes a*B = {shared_A}")
    print(f"  Bob   computes b*A = {shared_B}")

    if shared_A == shared_B:
        print(f"\n  [✓] Shared secret established: {shared_A}")
    else:
        print("\n  [ERROR] Key exchange failed — keys don't match!")

    return shared_A


# ─────────────────────────────────────────────
#  CLI
# ─────────────────────────────────────────────

def get_curve_params() -> tuple:
    """Prompt user for curve domain parameters or use a preset."""
    print("\n  Select curve:")
    print("  [1] Tiny curve (mod 23) — best for listing all points")
    print("  [2] Textbook curve (mod 17)")
    print("  [3] Small curve (mod 97)")
    print("  [4] Custom parameters")
    choice = input("\n  Choice [default 1]: ").strip() or '1'

    if choice in ('1','2','3'):
        key = {'1': 'tiny', '2': 'p17', '3': 'small'}[choice]
        params = PREDEFINED_CURVES[key]
        print(f"\n  Using: {params['desc']}")
        curve = EllipticCurve(params['p'], params['a'], params['b'])
        G = curve.point(params['Gx'], params['Gy'])
        n = params['n']
    else:
        print("\n  Enter domain parameters:")
        try:
            p = int(input("  Prime p: ").strip())
            a = int(input("  Coefficient a: ").strip())
            b = int(input("  Coefficient b: ").strip())
            Gx = int(input("  Generator G_x: ").strip())
            Gy = int(input("  Generator G_y: ").strip())
            n = int(input("  Order n (of generator G): ").strip())
            curve = EllipticCurve(p, a, b)
            G = curve.point(Gx, Gy)
        except ValueError as e:
            print(f"  [ERROR] {e}")
            return None, None, None

    if not curve.is_on_curve(G):
        print(f"  [ERROR] Generator point G={G} is not on the curve!")
        return None, None, None

    return curve, G, n


def run():
    """Interactive CLI for ECC."""
    print("\n" + "="*60)
    print("       ECC (Elliptic Curve Cryptography)")
    print("="*60)

    curve, G, n = None, None, None

    while True:
        print("\n  Options:")
        print("  [1] Set/Change Curve Parameters")
        print("  [2] List all points on the curve (multiples of G)")
        print("  [3] Generate ECC Key Pair")
        print("  [4] ECDH Key Exchange (simulate Alice & Bob)")
        print("  [5] Manual Point Arithmetic")
        print("  [0] Back to Main Menu")
        choice = input("\n  Select option: ").strip()

        if choice == '0':
            break

        elif choice == '1':
            curve, G, n = get_curve_params()
            if curve:
                print(f"\n  Curve: y² = x³ + {curve.a}x + {curve.b} (mod {curve.p})")
                print(f"  Generator G = {G}")
                print(f"  Order n = {n}")

        elif choice == '2':
            if curve is None:
                print("\n  [INFO] Using default tiny curve (mod 23).")
                params = PREDEFINED_CURVES['tiny']
                curve = EllipticCurve(params['p'], params['a'], params['b'])
                G = curve.point(params['Gx'], params['Gy'])
                n = params['n']

            print(f"\n  Curve: y² = x³ + {curve.a}x + {curve.b} (mod {curve.p})")
            print(f"  All multiples of G = {G}:\n")
            print(f"  {'k':>4}  {'kG':^30}  On Curve?")
            print("  " + "-"*50)
            points = curve.generate_all_points(G, n)
            for k, pt in points:
                on_curve = "✓" if curve.is_on_curve(pt) else "✗"
                print(f"  {k:>4}G = {str(pt):<30} {on_curve}")
            print(f"  {n+1:>4}G = O (Point at Infinity)")
            print(f"\n  Total points generated: {len(points)} + point at infinity")

        elif choice == '3':
            if curve is None:
                params = PREDEFINED_CURVES['tiny']
                curve = EllipticCurve(params['p'], params['a'], params['b'])
                G = curve.point(params['Gx'], params['Gy'])
                n = params['n']
                print(f"\n  [INFO] Using default tiny curve (mod {curve.p}).")

            private_key = random.randint(2, n - 1)
            public_key = curve.scalar_mul(private_key, G)

            print(f"\n  Curve: y² = x³ + {curve.a}x + {curve.b} (mod {curve.p})")
            print(f"  Generator G = {G}")
            print(f"  Order n = {n}")
            print(f"\n  Private key d = {private_key}")
            print(f"  Public  key Q = d×G = {public_key}")
            print(f"  Verification: Q on curve? {curve.is_on_curve(public_key)}")

        elif choice == '4':
            if curve is None:
                params = PREDEFINED_CURVES['tiny']
                curve = EllipticCurve(params['p'], params['a'], params['b'])
                G = curve.point(params['Gx'], params['Gy'])
                n = params['n']
                print(f"\n  [INFO] Using default tiny curve (mod {curve.p}).")
            ecdh_key_exchange(curve, G, n)

        elif choice == '5':
            if curve is None:
                print("\n  [ERROR] Set curve parameters first (option 1).")
                continue
            print(f"\n  Curve: y² = x³ + {curve.a}x + {curve.b} (mod {curve.p})")
            print("  Operations: [1] Add two points  [2] Scalar multiply")
            op = input("  Operation: ").strip()
            if op == '1':
                try:
                    x1 = int(input("  P1.x: "))
                    y1 = int(input("  P1.y: "))
                    x2 = int(input("  P2.x: "))
                    y2 = int(input("  P2.y: "))
                    P1 = curve.point(x1, y1)
                    P2 = curve.point(x2, y2)
                    if not curve.is_on_curve(P1):
                        print("  [ERROR] P1 is not on the curve.")
                        continue
                    if not curve.is_on_curve(P2):
                        print("  [ERROR] P2 is not on the curve.")
                        continue
                    result = curve.add(P1, P2)
                    print(f"\n  P1 + P2 = {result}")
                    print(f"  On curve: {curve.is_on_curve(result)}")
                except ValueError as e:
                    print(f"  [ERROR] {e}")
            elif op == '2':
                try:
                    k = int(input("  Scalar k: "))
                    x = int(input("  P.x: "))
                    y = int(input("  P.y: "))
                    P = curve.point(x, y)
                    if not curve.is_on_curve(P):
                        print("  [ERROR] P is not on the curve.")
                        continue
                    result = curve.scalar_mul(k, P)
                    print(f"\n  {k} × P = {result}")
                    print(f"  On curve: {curve.is_on_curve(result)}")
                except ValueError as e:
                    print(f"  [ERROR] {e}")
        else:
            print("  [ERROR] Invalid option.")
