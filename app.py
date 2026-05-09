"""
CSE721 Cryptography Web App — Flask Backend
Full implementation matching CLI functionality
"""

from flask import Flask, render_template, request, jsonify
import sys, os, json, random

sys.path.insert(0, os.path.dirname(__file__))

from classical.substitution import (
    encrypt as sub_encrypt, decrypt as sub_decrypt,
    generate_random_key, validate_key, frequency_analysis, brute_force_attack
)
from classical.double_transposition import (
    encrypt as dt_encrypt, decrypt as dt_decrypt,
    parse_key, frequency_analysis as dt_freq
)
from symmetric.aes import aes_encrypt, aes_decrypt, key_expansion, get_round_key, get_nr, generate_key as aes_gen_key
from symmetric.des import des_encrypt, des_decrypt, key_schedule, bits_to_bytes, generate_key as des_gen_key
from public_key.rsa import (
    generate_rsa_keys, rsa_encrypt, rsa_decrypt,
    factorization_attack, mod_inverse
)
from public_key.ecc import EllipticCurve, PREDEFINED_CURVES, ecdh_key_exchange as _ecdh

app = Flask(__name__)

@app.route('/api/substitution', methods=['POST'])
def api_substitution():
    data = request.json
    action = data.get('action')
    text = data.get('text', '').strip()
    key = data.get('key', '').strip().upper()

    if not text:
        return jsonify({'error': 'Please enter text.'}), 400

    if action in ('encrypt', 'decrypt'):
        if not key:
            key = generate_random_key()
        if not validate_key(key):
            return jsonify({'error': 'Key must be a 26-letter permutation of A-Z.'}), 400

        if action == 'encrypt':
            result_text = sub_encrypt(text, key)
            freq = frequency_analysis(result_text)
        else:
            result_text = sub_decrypt(text, key)
            freq = frequency_analysis(result_text)

        freq_sorted = sorted(freq.items(), key=lambda x: x[1], reverse=True)
        freq_data = [{'letter': l, 'pct': p} for l, p in freq_sorted if p > 0]

        return jsonify({
            'result': result_text,
            'key': key,
            'freq': freq_data,
            'action': action
        })

    elif action == 'bruteforce':
        result = brute_force_attack(text, top_n=5)
        return jsonify(result)

    return jsonify({'error': 'Unknown action'}), 400

@app.route('/api/transposition', methods=['POST'])
def api_transposition():
    data = request.json
    action = data.get('action')
    text = data.get('text', '')
    k1_str = data.get('key1', '').strip()
    k2_str = data.get('key2', '').strip()

    try:
        key1 = parse_key(k1_str)
        key2 = parse_key(k2_str)
    except Exception:
        return jsonify({'error': 'Keys must be comma-separated integers e.g. 3,1,4,2'}), 400

    n_rows, n_cols = len(key1), len(key2)
    total = n_rows * n_cols

    if action == 'encrypt':
        if len(text) > total:
            return jsonify({'error': f'Plaintext ({len(text)} chars) exceeds matrix size ({total} cells).'}), 400
        result = dt_encrypt(text, key1, key2)
        freq = dt_freq(result)
    else:
        # Auto-pad ciphertext with spaces if shorter than matrix (spaces are valid pad chars)
        if len(text) > total:
            return jsonify({'error': f'Ciphertext ({len(text)} chars) is longer than matrix size ({n_rows}×{n_cols}={total}).'}), 400
        if len(text) < total:
            text = text + ' ' * (total - len(text))
        result = dt_decrypt(text, key1, key2)
        freq = dt_freq(result)

    freq_sorted = sorted(freq.items(), key=lambda x: x[1], reverse=True)
    freq_data = [{'letter': l, 'pct': p} for l, p in freq_sorted if p > 0]

    # Build matrix for visualization
    pad_count = total - len(text) if action == 'encrypt' else 0
    padded_text = text + ' ' * pad_count
    matrix_before = [[padded_text[r*n_cols + c] for c in range(n_cols)] for r in range(n_rows)]

    return jsonify({
        'result': result,
        'freq': freq_data,
        'matrix': matrix_before,
        'rows': n_rows,
        'cols': n_cols,
        'padded': pad_count > 0
    })

@app.route('/api/des', methods=['POST'])
def api_des():
    data = request.json
    action = data.get('action')
    text = data.get('text', '').strip()
    key_hex = data.get('key', '').strip()

    # Key handling
    if not key_hex:
        key = des_gen_key()
        key_hex = key.hex().upper()
    else:
        try:
            key = bytes.fromhex(key_hex)
            if len(key) != 8:
                return jsonify({'error': 'DES key must be 8 bytes (16 hex chars).'}), 400
        except ValueError:
            return jsonify({'error': 'Invalid hex key.'}), 400

    # Round keys
    subkeys = key_schedule(key)
    round_keys = []
    for i, sk in enumerate(subkeys, 1):
        sk_bytes = bits_to_bytes(sk + [0]*16)
        round_keys.append({'round': i, 'key': ''.join(f'{b:02X}' for b in sk_bytes[:6])})

    try:
        if action == 'encrypt':
            ct = des_encrypt(text.encode('utf-8'), key)
            return jsonify({'result': ct.hex().upper(), 'key': key_hex, 'round_keys': round_keys})
        else:
            ct_bytes = bytes.fromhex(text)
            pt = des_decrypt(ct_bytes, key)
            return jsonify({'result': pt.decode('utf-8'), 'key': key_hex, 'round_keys': round_keys})
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/api/aes', methods=['POST'])
def api_aes():
    data = request.json
    action = data.get('action')
    text = data.get('text', '').strip()
    key_hex = data.get('key', '').strip()
    bits = int(data.get('bits', 128))

    if bits not in (128, 192, 256):
        bits = 128

    # Key handling
    if not key_hex:
        key = aes_gen_key(bits)
        key_hex = key.hex().upper()
    else:
        try:
            key = bytes.fromhex(key_hex)
            if len(key) * 8 != bits:
                return jsonify({'error': f'AES-{bits} key must be {bits//8} bytes ({bits//4} hex chars).'}), 400
        except ValueError:
            return jsonify({'error': 'Invalid hex key.'}), 400

    # Round keys
    w = key_expansion(key)
    nr = get_nr(key)
    round_keys = []
    for rnd in range(nr + 1):
        rk = get_round_key(w, rnd)
        rk_hex = ''.join(f'{rk[r][c]:02X}' for c in range(4) for r in range(4))
        round_keys.append({'round': rnd, 'key': rk_hex})

    try:
        if action == 'encrypt':
            ct = aes_encrypt(text.encode('utf-8'), key)
            return jsonify({'result': ct.hex().upper(), 'key': key_hex, 'bits': bits, 'round_keys': round_keys})
        else:
            ct_bytes = bytes.fromhex(text)
            pt = aes_decrypt(ct_bytes, key)
            return jsonify({'result': pt.decode('utf-8'), 'key': key_hex, 'bits': bits, 'round_keys': round_keys})
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/api/rsa', methods=['POST'])
def api_rsa():
    data = request.json
    action = data.get('action')

    if action == 'generate':
        bits = int(data.get('bits', 512))
        if bits not in (64, 512, 1024, 2048):
            bits = 512
        keys = generate_rsa_keys(bits)
        result = {
            'e': str(keys['e']),
            'n': hex(keys['n']),
            'd': hex(keys['d']),
            'p': hex(keys['p']),
            'q': hex(keys['q']),
            'phi': hex(keys['phi']),
            'bits': bits
        }
        # Try factorization regardless of key size — fails gracefully if too large
        fa = factorization_attack(keys['n'])
        if fa:
            p_f, q_f = fa
            phi_f = (p_f - 1) * (q_f - 1)
            d_f   = mod_inverse(keys['e'], phi_f)
            result['factorization'] = {
                'success': True,
                'p': str(p_f), 'q': str(q_f),
                'd_recovered': hex(d_f),
                'match': d_f == keys['d']
            }
        else:
            result['factorization'] = {
                'success': False,
                'message': f'Factorization failed — {bits}-bit modulus is too large for trial division. A real attack would require sub-exponential algorithms (GNFS, ECM) and significant compute time.'
            }
        return jsonify(result)

    elif action == 'encrypt':
        try:
            n = int(data.get('n', '0'), 16)
            e = int(data.get('e', '0'))
            msg = data.get('text', '').strip()
            ct = rsa_encrypt(msg, n, e)
            return jsonify({'ciphertext_int': str(ct), 'ciphertext_hex': hex(ct)})
        except Exception as ex:
            return jsonify({'error': str(ex)}), 400

    elif action == 'decrypt':
        try:
            n = int(data.get('n', '0'), 16)
            d = int(data.get('d', '0'), 16)
            ct_raw = data.get('ciphertext', '').strip()
            ct = int(ct_raw, 16) if ct_raw.startswith('0x') else int(ct_raw)
            pt = rsa_decrypt(ct, n, d)
            return jsonify({'plaintext': pt})
        except Exception as ex:
            return jsonify({'error': str(ex)}), 400

    return jsonify({'error': 'Unknown action'}), 400

@app.route('/api/ecc', methods=['POST'])
def api_ecc():
    data = request.json
    action = data.get('action')

    try:
        p  = int(data.get('p',  23))
        a  = int(data.get('a',  1))
        b  = int(data.get('b',  1))
        curve = EllipticCurve(p, a, b)
    except Exception as ex:
        return jsonify({'error': str(ex)}), 400

    if action == 'find_points':
        valid = []
        for x in range(p):
            rhs = (pow(x, 3, p) + a * x + b) % p
            for y in range(p):
                if pow(y, 2, p) == rhs:
                    valid.append({'x': x, 'y': y})
        return jsonify({'points': valid, 'count': len(valid), 'curve': f"y\u00b2 = x\u00b3 + {a}x + {b} (mod {p})"})

    elif action == 'set_generator':
        try:
            Gx = int(data.get('Gx'))
            Gy = int(data.get('Gy'))
        except:
            return jsonify({'error': 'Invalid generator coordinates.'}), 400
        G = curve.point(Gx, Gy)
        if not curve.is_on_curve(G):
            return jsonify({'error': f'Point ({Gx},{Gy}) is not on the curve.'}), 400
        multiples = []
        current = G
        n = 0
        for k in range(1, p * 2 + 10):
            multiples.append({'k': k, 'x': current.x, 'y': current.y})
            nxt = curve.add(current, G)
            if nxt.is_infinity:
                n = k + 1  # order = index of last point + 1, since (k+1)G = O
                break
            current = nxt
        else:
            n = len(multiples) + 1
        # Add the infinity point as nG = O
        multiples.append({'k': n, 'x': None, 'y': None, 'infinity': True})
        return jsonify({'multiples': multiples, 'n': n, 'G': {'x': Gx, 'y': Gy}})

    elif action == 'keygen':
        try:
            Gx = int(data.get('Gx'))
            Gy = int(data.get('Gy'))
            n  = int(data.get('n'))
            d  = int(data.get('d') or 0) or random.randint(2, n - 1)
        except:
            return jsonify({'error': 'Missing or invalid parameters.'}), 400
        G = curve.point(Gx, Gy)
        if not curve.is_on_curve(G):
            return jsonify({'error': 'Generator not on curve.'}), 400
        if d < 1:
            return jsonify({'error': 'Private key d must be at least 1.'}), 400
        effective_d = d % n
        # d % n == 0 means d is a multiple of n, which maps to the point at infinity
        Q = curve.scalar_mul(effective_d, G, n) if effective_d != 0 else curve.infinity()
        q_data = {'x': None, 'y': None, 'infinity': True} if Q.is_infinity else {'x': Q.x, 'y': Q.y, 'infinity': False}
        return jsonify({'private_key': d, 'effective_d': effective_d if effective_d != 0 else n, 'public_key': q_data, 'on_curve': curve.is_on_curve(Q), 'n': n})

    elif action == 'ecdh':
        try:
            Gx = int(data.get('Gx'))
            Gy = int(data.get('Gy'))
            n  = int(data.get('n'))
            alice_a = int(data.get('alice_a') or 0) or random.randint(2, n - 1)
            bob_b   = int(data.get('bob_b')   or 0) or random.randint(2, n - 1)
        except:
            return jsonify({'error': 'Missing parameters.'}), 400
        G = curve.point(Gx, Gy)
        if not curve.is_on_curve(G):
            return jsonify({'error': 'Generator not on curve.'}), 400
        if alice_a < 1:
            return jsonify({'error': 'Alice key must be at least 1.'}), 400
        if bob_b < 1:
            return jsonify({'error': 'Bob key must be at least 1.'}), 400
        alice_a_eff = alice_a % n
        bob_b_eff   = bob_b   % n
        if alice_a_eff == 0: alice_a_eff = n
        if bob_b_eff   == 0: bob_b_eff   = n
        A = curve.scalar_mul(alice_a_eff, G, n)
        B = curve.scalar_mul(bob_b_eff,   G, n)
        shared_A = curve.scalar_mul(alice_a_eff, B, n)
        shared_B = curve.scalar_mul(bob_b_eff,   A, n)
        return jsonify({
            'alice': {'private': alice_a, 'effective': alice_a_eff, 'public': {'x': A.x, 'y': A.y}},
            'bob':   {'private': bob_b,   'effective': bob_b_eff,   'public': {'x': B.x, 'y': B.y}},
            'shared_alice': {'x': shared_A.x, 'y': shared_A.y},
            'shared_bob':   {'x': shared_B.x, 'y': shared_B.y},
            'shared_key': shared_A.x,
            'match': shared_A == shared_B,
            'n': n
        })

    return jsonify({'error': 'Unknown action'}), 400

@app.route('/api/benchmark', methods=['POST'])
def api_benchmark():
    import time, os

    results = []

    def bench(label, category, key_size, security, fn, rounds=5):
        times = []
        for _ in range(rounds):
            t0 = time.perf_counter()
            fn()
            times.append((time.perf_counter() - t0) * 1000)
        avg = round(sum(times) / len(times), 3)
        mn  = round(min(times), 3)
        mx  = round(max(times), 3)
        results.append({
            'label': label,
            'category': category,
            'key_size': key_size,
            'security': security,
            'avg_ms': avg,
            'min_ms': mn,
            'max_ms': mx,
        })

    pt_short = b'Hello World!!!!!'     # 16 bytes
    pt_long  = os.urandom(1024)        # 1 KB

    # Substitution cipher
    from classical.substitution import encrypt as sub_enc, generate_random_key
    sub_key = generate_random_key()
    bench('Substitution (encrypt)', 'Classical', '26! keys', 'Broken — frequency analysis',
          lambda: sub_enc('HELLO WORLD THIS IS A TEST MESSAGE FOR BENCHMARKING', sub_key))

    # Double transposition
    from classical.double_transposition import encrypt as dt_enc, parse_key
    k1, k2 = parse_key('4,2,1,3'), parse_key('3,1,2')
    bench('Double Transposition (encrypt)', 'Classical', '~(n!×m!) keys', 'Weak — preserves frequencies',
          lambda: dt_enc('HELLO WORLD THIS IS A TEST MESSAGE FOR', k1, k2))

    # DES
    from symmetric.des import des_encrypt, generate_key as des_gen
    des_key = des_gen()
    bench('DES encrypt (16 bytes)', 'Symmetric', '56-bit', 'Broken — brute-forceable',
          lambda: des_encrypt(pt_short, des_key))
    bench('DES encrypt (1 KB)', 'Symmetric', '56-bit', 'Broken — brute-forceable',
          lambda: des_encrypt(pt_long, des_key))

    # AES-128
    from symmetric.aes import aes_encrypt, generate_key as aes_gen
    aes128 = aes_gen(128)
    bench('AES-128 encrypt (16 bytes)', 'Symmetric', '128-bit', 'Secure (~2¹²⁸)',
          lambda: aes_encrypt(pt_short, aes128))
    bench('AES-128 encrypt (1 KB)', 'Symmetric', '128-bit', 'Secure (~2¹²⁸)',
          lambda: aes_encrypt(pt_long, aes128))

    # AES-256
    aes256 = aes_gen(256)
    bench('AES-256 encrypt (16 bytes)', 'Symmetric', '256-bit', 'Very secure (~2²⁵⁶)',
          lambda: aes_encrypt(pt_short, aes256))
    bench('AES-256 encrypt (1 KB)', 'Symmetric', '256-bit', 'Very secure (~2²⁵⁶)',
          lambda: aes_encrypt(pt_long, aes256))

    # RSA — key gen is slow, only bench encrypt/decrypt
    from public_key.rsa import generate_rsa_keys, rsa_encrypt, rsa_decrypt
    rsa512  = generate_rsa_keys(512)
    rsa1024 = generate_rsa_keys(1024)

    ct512  = rsa_encrypt('HI', rsa512['n'],  rsa512['e'])
    ct1024 = rsa_encrypt('HI', rsa1024['n'], rsa1024['e'])

    bench('RSA-512 encrypt', 'Public-Key', '512-bit', 'Deprecated (<80-bit security)',
          lambda: rsa_encrypt('HI', rsa512['n'], rsa512['e']))
    bench('RSA-512 decrypt', 'Public-Key', '512-bit', 'Deprecated (<80-bit security)',
          lambda: rsa_decrypt(ct512, rsa512['n'], rsa512['d']))
    bench('RSA-1024 encrypt', 'Public-Key', '1024-bit', 'Borderline (~80-bit security)',
          lambda: rsa_encrypt('HI', rsa1024['n'], rsa1024['e']))
    bench('RSA-1024 decrypt', 'Public-Key', '1024-bit', 'Borderline (~80-bit security)',
          lambda: rsa_decrypt(ct1024, rsa1024['n'], rsa1024['d']))

    # ECC key gen
    from public_key.ecc import EllipticCurve
    curve = EllipticCurve(23, 1, 1)
    G = curve.point(3, 10)
    bench('ECC scalar multiply (mod 23)', 'Public-Key', '~23-bit field', 'Demo only — too small for real use',
          lambda: curve.scalar_mul(12, G, 27))

    return jsonify({'results': results})


@app.route('/')
def index():
    return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=True, port=5050)
