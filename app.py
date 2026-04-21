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


# ─── SUBSTITUTION ────────────────────────────────────────────
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
        results = brute_force_attack(text, top_n=5)
        candidates = [{'rank': i+1, 'score': round(s, 2), 'key': k, 'text': t}
                      for i, (s, k, t) in enumerate(results)]
        return jsonify({'candidates': candidates})

    return jsonify({'error': 'Unknown action'}), 400


# ─── DOUBLE TRANSPOSITION ────────────────────────────────────
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


# ─── DES ─────────────────────────────────────────────────────
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


# ─── AES ─────────────────────────────────────────────────────
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


# ─── RSA ─────────────────────────────────────────────────────
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
        # Attempt factorization for small keys
        if bits <= 64:
            fa = factorization_attack(keys['n'], bits)
            if fa:
                p_f, q_f = fa
                phi_f = (p_f - 1) * (q_f - 1)
                d_f = mod_inverse(keys['e'], phi_f)
                result['factorization'] = {
                    'p': str(p_f), 'q': str(q_f),
                    'd_recovered': hex(d_f),
                    'match': d_f == keys['d']
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


# ─── ECC ─────────────────────────────────────────────────────
@app.route('/api/ecc', methods=['POST'])
def api_ecc():
    data = request.json
    action = data.get('action')

    curve_name = data.get('curve', 'tiny')
    params = PREDEFINED_CURVES.get(curve_name, PREDEFINED_CURVES['tiny'])

    try:
        curve = EllipticCurve(params['p'], params['a'], params['b'])
        G = curve.point(params['Gx'], params['Gy'])
        n = params['n']
    except Exception as ex:
        return jsonify({'error': str(ex)}), 400

    if action == 'list_points':
        points_raw = curve.generate_all_points(G, n)
        points = [{'k': k, 'x': pt.x, 'y': pt.y} for k, pt in points_raw]
        return jsonify({
            'points': points,
            'curve': f"y² = x³ + {params['a']}x + {params['b']} (mod {params['p']})",
            'G': {'x': G.x, 'y': G.y},
            'n': n
        })

    elif action == 'keygen':
        d = random.randint(2, n - 1)
        Q = curve.scalar_mul(d, G)
        return jsonify({
            'private_key': d,
            'public_key': {'x': Q.x, 'y': Q.y},
            'on_curve': curve.is_on_curve(Q)
        })

    elif action == 'ecdh':
        a = random.randint(2, n - 1)
        b = random.randint(2, n - 1)
        A = curve.scalar_mul(a, G)
        B = curve.scalar_mul(b, G)
        shared_A = curve.scalar_mul(a, B)
        shared_B = curve.scalar_mul(b, A)
        return jsonify({
            'alice': {'private': a, 'public': {'x': A.x, 'y': A.y}},
            'bob':   {'private': b, 'public': {'x': B.x, 'y': B.y}},
            'shared_alice': {'x': shared_A.x, 'y': shared_A.y},
            'shared_bob':   {'x': shared_B.x, 'y': shared_B.y},
            'match': shared_A == shared_B
        })

    return jsonify({'error': 'Unknown action'}), 400


@app.route('/')
def index():
    return render_template('index.html')


if __name__ == '__main__':
    app.run(debug=True, port=5050)
