"""
Clean-room Python reference implementation of RFC 9591 (FROST) for
secp256k1_sha256 and ed25519_sha512 ciphersuites.

DERIVATION CONSTRAINT (CRITICAL):
This implementation is derived EXCLUSIVELY from RFC 9591 + RFC 9380 text +
standard Python primitives + the ZcashFoundation/frost-rs KAT JSON shape
(a documented derivation constraint). It must NOT consult ZcashFoundation/frost
source code, its self-generated tests/helpers/vectors.json, or any other audited
FROST implementation source beyond what is documented in the KAT shape.

SCOPE (msn-2026-0019):
  Full RFC 9591 §4-§5 path for both ciphersuites:
    §4.1: hiding_nonce, binding_nonce (per participant, deterministic given randomness)
    §5.1: hiding_nonce_commitment, binding_nonce_commitment (per participant)
    §4.3: EncodeGroupCommitmentList + group_commitment_hash
    §4.2: message_hash + binding_factor (per participant)
    §5.2: challenge e
    §5.2: lagrange coefficient lambda_i (per signing participant)
    §5.2: signature_share z_i (per signing participant)
    §5.3: aggregate (R, z)
    §5.3: aggregate verification under public group key

CIPHERSUITE DIFFERENCES (RFC 9591 §6):
  secp256k1_sha256 (§6.5):
    CTX  = "FROST-secp256k1-SHA256-v1"
    HASH = SHA-256
    H1, H2, H3 = hash_to_field via expand_message_xmd (RFC 9380)
    H4 = H(CTX || 'msg' || m), H5 = H(CTX || 'com' || m)
    Scalar = big-endian 32 bytes (SEC1 Field-Element-to-Octet-String)
    Element = SEC1 compressed (33 bytes)

  ed25519_sha512 (§6.1):
    CTX  = "FROST-ed25519-SHA512-v1"
    HASH = SHA-512
    H1, H3 = H(CTX || tag || m), reduced mod q (little-endian)
    H2 = H(m), reduced mod q, NO domain sep (RFC 8032 compat)
    H4 = H(CTX || 'msg' || m), H5 = H(CTX || 'com' || m)
    Scalar = little-endian 32 bytes (top 3 bits cleared)
    Element = 32-byte Edwards compressed

DEPENDENCIES (all stdlib + already-installed in venv):
  - hashlib: SHA-256 / SHA-512
  - ecdsa (pure Python): Point arithmetic + decompress for both curves
  - json (stdlib): KAT loading

References:
  - RFC 9591: https://www.rfc-editor.org/rfc/rfc9591
  - RFC 9380: https://www.rfc-editor.org/rfc/rfc9380 (hash_to_field, expand_message_xmd)
  - RFC 9591 Appendix E.5 (secp256k1_sha256 KAT)
  - RFC 9591 Appendix E.1 (ed25519_sha512 KAT)
"""

from __future__ import annotations

import hashlib
import json
import math
from pathlib import Path
from typing import Optional

import ecdsa
from ecdsa import SECP256k1, Ed25519
from ecdsa.ellipticcurve import Point, PointEdwards

# ============================================================================
# RFC 9380 §5.3.1 expand_message_xmd (for SHA-256 and SHA-512)
# ============================================================================

def expand_message_xmd(msg: bytes, dst: bytes, len_in_bytes: int,
                       hash_func=hashlib.sha256) -> bytes:
    """RFC 9380 §5.3.1 expand_message_xmd.

    Args:
        msg: byte string to to expand to
        dst: domain separation tag ( ≤255 bytes)
        len_in_bytes: desired output length in bytes ( ≤65535)
        hash_func: hash function constructor (default SHA-256)

    Returns: bytes of length len_in_bytes
    """
    b_in_bytes = hash_func().digest_size  # 32 for SHA-256, 64 for SHA-512
    s_in_bytes = hash_func().block_size    # 64 for SHA-256, 128 for SHA-512

    if len(dst) > 255:
        raise ValueError("len(DST) > 255")
    if len_in_bytes > 65535:
        raise ValueError("len_in_bytes > 65535")
    ell = (len_in_bytes + b_in_bytes - 1) // b_in_bytes
    if ell > 255:
        raise ValueError("ell > 255")

    DST_prime = dst + bytes([len(dst)])
    Z_pad = b'\x00' * s_in_bytes
    l_i_b_str = len_in_bytes.to_bytes(2, 'big')

    # Step 6: msg_prime = Z_pad || msg || l_i_b_str || I2OSP(0, 1) || DST_prime
    msg_prime = Z_pad + msg + l_i_b_str + b'\x00' + DST_prime

    # Step 7: b_0 = H(msg_prime)
    b_0 = hash_func(msg_prime).digest()

    # Step 8: b_1 = H(b_0 || I2OSP(1, 1) || DST_prime)
    b_list = [None, hash_func(b_0 + b'\x01' + DST_prime).digest()]

    # Steps 9-10: b_i = H(strxor(b_0, b_{i-1}) || I2OSP(i, 1) || DST_prime) for i in 2..ell
    for i in range(2, ell + 1):
        prev = b_list[-1]
        b_xor = bytes(a ^ c for a, c in zip(b_0, prev))
        b_i = hash_func(b_xor + bytes([i]) + DST_prime).digest()
        b_list.append(b_i)

    # Step 11: uniform_bytes = b_1 || b_2 || ... || b_ell
    uniform_bytes = b''.join(b_list[1:])

    return uniform_bytes[:len_in_bytes]


def hash_to_field(msg: bytes, dst: bytes, count: int, p: int, k: int = 128,
                  hash_func=hashlib.sha256) -> list:
    """RFC 9380 §5.2 hash_to_field for prime field GF(p) with m=1.

    For FROST, this is used for H1, H2, H3 in ciphersuites that don't
    use a simple H(...) mod q (e.g., secp256k1_sha256, P-256, P-384).

    Args:
        msg: byte string to hash
        dst: domain separation tag (already encoded, e.g., CTX||'nonce')
        count: number of field elements to output
        p: field characteristic
        k: target security level in bits (default 128 per RFC 9591 §6.5)
        hash_func: hash function (default SHA-256)

    Returns: list of `count` field elements (integers in [0, p-1])
    """
    L = math.ceil((math.ceil(math.log2(p)) + k) / 8)
    len_in_bytes = count * L
    uniform_bytes = expand_message_xmd(msg, dst, len_in_bytes, hash_func)
    u = []
    for i in range(count):
        tv = uniform_bytes[i * L:(i + 1) * L]
        val = int.from_bytes(tv, 'big') % p
        u.append(val)
    return u


# ============================================================================
# Ciphersuite constants (RFC 9591 §6)
# ============================================================================

# secp256k1_sha256 (§6.5)
CTX_SECP256K1_SHA256 = "FROST-secp256k1-SHA256-v1"
H_SECP256K1 = hashlib.sha256
ORDER_SECP256K1 = SECP256k1.order
P_SECP256K1 = SECP256k1.curve.p()

# ed25519_sha512 (§6.1) — RFC 9591 §6.1-1 specifies UPPERCASE 'ED25519'
CTX_ED25519_SHA512 = "FROST-ED25519-SHA512-v1"
H_ED25519 = hashlib.sha512
ORDER_ED25519 = Ed25519.order
P_ED25519 = Ed25519.curve.p()


# ============================================================================
# Scalar / element encoding (RFC 9591 §6.5 / §6.1)
# ============================================================================

def serialize_scalar_secp256k1(s: int) -> bytes:
    """RFC 9591 §6.5 secp256k1 SerializeScalar: big-endian 32 bytes."""
    if s < 0 or s >= ORDER_SECP256K1:
        raise ValueError(f"scalar out of range: {s}")
    return s.to_bytes(32, "big")


def serialize_scalar_ed25519(s: int) -> bytes:
    """RFC 9591 §6.1 ed25519 SerializeScalar: little-endian 32 bytes, top 3 bits zero.

    In little-endian, byte[31] is the most significant byte; 'top three bits'
    means bits 5-7 of byte[31].
    """
    if s < 0 or s >= ORDER_ED25519:
        raise ValueError(f"scalar out of range: {s}")
    b = s.to_bytes(32, "little")
    return b[:-1] + bytes([b[31] & 0x07])


def deserialize_scalar_secp256k1(b: bytes) -> int:
    return int.from_bytes(b, "big") % ORDER_SECP256K1


def deserialize_scalar_ed25519(b: bytes) -> int:
    return int.from_bytes(b, "little") % ORDER_ED25519


# ============================================================================
# Point arithmetic (decompress / add / scalar mult / compress)
# ============================================================================

def decompress_secp256k1(b: bytes) -> Point:
    """RFC 9591 §6.5 secp256k1 DeserializeElement: 33-byte SEC1 compressed."""
    if len(b) != 33:
        raise ValueError(f"secp256k1 element must be 33 bytes, got {len(b)}")
    prefix = b[0]
    if prefix not in (0x02, 0x03):
        raise ValueError(f"secp256k1 element prefix must be 0x02/0x03, got {prefix:#x}")
    x = int.from_bytes(b[1:], "big")
    if x >= P_SECP256K1:
        raise ValueError("x out of range")
    y_sq = (pow(x, 3, P_SECP256K1) + 7) % P_SECP256K1
    y = pow(y_sq, (P_SECP256K1 + 1) // 4, P_SECP256K1)
    if (y * y) % P_SECP256K1 != y_sq:
        raise ValueError(f"point x={x} not on secp256k1 curve")
    if (y & 1) != (prefix - 2):
        y = P_SECP256K1 - y
    return Point(SECP256k1.curve, x, y, ORDER_SECP256K1)


def compress_secp256k1(pt: Point) -> bytes:
    prefix = 0x02 if (pt.y() & 1) == 0 else 0x03
    return bytes([prefix]) + pt.x().to_bytes(32, "big")


def decompress_ed25519(b: bytes) -> Point:
    """RFC 9591 §6.1 ed25519 DeserializeElement: 32-byte Edwards compressed.

    Implements RFC 8032 §5.1.3:
      1. Extract sign bit (high bit of last byte) and y from the remaining 255 bits.
      2. Interpret y as an integer (NOT reduced mod p here — the reduction happens via
         field arithmetic operations).
      3. Compute u = y^2 - 1, v = d*y^2 + 1, then x^2 = u/v.
      4. Square root x via (u/v)^((p+3)/8) with Tonelli-Shanks fallback.
      5. Apply sign bit by negating x if parity differs.
    """
    if len(b) != 32:
        raise ValueError(f"ed25519 element must be 32 bytes, got {len(b)}")
    # Mask off the sign bit (high bit of LAST byte)
    sign = (b[31] >> 7) & 1
    y_bytes = bytearray(b)
    y_bytes[31] &= 0x7f
    y = int.from_bytes(bytes(y_bytes), "little")
    # Ed25519: a = -1 mod p, d = -121665/121666 mod p
    d = (-121665 * pow(121666, -1, P_ED25519)) % P_ED25519
    y2 = (y * y) % P_ED25519
    u = (y2 - 1) % P_ED25519
    v = (d * y2 + 1) % P_ED25519
    if v == 0:
        raise ValueError("denominator zero (point at infinity?)")
    x2 = (u * pow(v, -1, P_ED25519)) % P_ED25519
    # Tonelli-Shanks for x^2 = x2: try (p+3)/8 first, fall back to *2^((p-1)/4)
    x = pow(x2, (P_ED25519 + 3) // 8, P_ED25519)
    if (x * x) % P_ED25519 != x2:
        I = pow(2, (P_ED25519 - 1) // 4, P_ED25519)
        x = (x * I) % P_ED25519
        if (x * x) % P_ED25519 != x2:
            raise ValueError(f"ed25519 point y={y} has no x in Fp")
    if (x & 1) != sign:
        x = P_ED25519 - x
    return PointEdwards(Ed25519.curve, x, y, ORDER_ED25519, 1, (x * y) % P_ED25519)


def compress_ed25519(pt) -> bytes:
    """RFC 9591 §6.1 ed25519 SerializeElement: 32-byte Edwards compressed.

    LE-encoded y with sign bit of x in the high bit of the LAST byte (MSB).
    """
    y_bytes = pt.y().to_bytes(32, "little")
    if pt.x() & 1:
        # Sign bit set → x is "negative" → high bit of last byte set
        y_bytes = y_bytes[:-1] + bytes([y_bytes[31] | 0x80])
    return y_bytes


def scalar_mult(scalar: int, pt: Point, curve_obj) -> Point:
    """ScalarMult(scalar, pt) via double-and-add using pure-Python Ed25519 arithmetic.

    The ecdsa library's `scalar * pt` may produce subtly wrong results for some
    Ed25519 scalar values close to q (off-by-a-few-bits). Additionally, its
    `Point + Point` operation raises an AssertionError for some inputs. We
    implement double-and-add explicitly using our own Ed25519 addition formula
    to avoid both issues.
    """
    n = curve_obj.order
    if scalar < 0 or scalar >= n:
        raise ValueError("scalar out of range")

    if curve_obj is Ed25519:
        # Use pure-Python Ed25519 arithmetic
        return _scalar_mult_ed25519(scalar, pt)
    else:
        # secp256k1 (Weierstrass) — ecdsa library handles correctly
        return scalar * pt


def _ed25519_add(P, Q, p, n, d):
    """Pure-Python twisted Edwards addition (a=-1, d=-121665/121666 mod p).

    Standard formula from RFC 8032 / Bernstein et al. 2008:
      A = x1*x2 mod p
      B = y1*y2 mod p
      C = d*t1*t2 mod p
      D = (x1+y1)*(x2+y2) mod p - A - B mod p
      E = (B - A) mod p
      F = (D - C) mod p
      G = (D + C) mod p
      H = (B + A) mod p  # = (A+B)
      x3 = E*F mod p
      y3 = G*H mod p
      t3 = E*H mod p
    """
    if P is None:
        return Q
    if Q is None:
        return P
    x1, y1, z1 = P.x(), P.y(), 1
    x2, y2, z2 = Q.x(), Q.y(), 1
    A = (x1 * x2) % p
    B = (y1 * y2) % p
    C = (d * 1 * 1) % p  # t = x*y for both, but for general affine t1 = x1*y1
    C = (d * x1 * y1 * x2 * y2) % p
    D = ((x1 + y1) * (x2 + y2)) % p
    D = (D - A - B) % p
    E = (B - A) % p
    F = (D - C) % p
    G = (D + C) % p
    H = (B + A) % p
    x3 = (E * F) % p
    y3 = (G * H) % p
    t3 = (E * H) % p  # not used but computed
    # Create Point using ecdsa library's PointEdwards class
    curve = P.curve()
    return PointEdwards(curve, x3, y3, n)


def _scalar_mult_ed25519(scalar: int, pt: Point) -> Point:
    """ScalarMult for ed25519 via double-and-add using pure-Python addition.

    Internal state is (X, Y, Z, T) projective; converts to PointEdwards at end.
    """
    n = Ed25519.order
    p = Ed25519.curve.p()
    d = (-121665 * pow(121666, -1, p)) % p
    curve = pt.curve()

    # Initial: (X, Y, Z, T) = (pt.x, pt.y, 1, pt.x * pt.y)
    pt_state = (pt.x(), pt.y(), 1, (pt.x() * pt.y()) % p)
    result = None  # identity

    while scalar > 0:
        if scalar & 1:
            if result is None:
                result = pt_state
            else:
                result = _ed25519_add_extended(result, pt_state, p, n, d)
        pt_state = _ed25519_add_extended(pt_state, pt_state, p, n, d)
        scalar >>= 1

    if result is None:
        raise ValueError("scalar_mult by zero")

    X3, Y3, Z3, T3 = result
    return PointEdwards(curve, X3, Y3, Z3, T3, n)


def _ed25519_add_extended(P, Q, p, n, d):
    """Twisted Edwards addition (a=-1) per RFC 8032 §5.1.4 / EFD add-2008-hwcd-3.

    Inputs P, Q are (X, Y, Z, T) projective tuples (with x = X/Z, y = Y/Z, t = x*y = T/Z).
    The formula (RFC 8032 §5.1.4):
        A = (Y1-X1)*(Y2-X2) mod p
        B = (Y1+X1)*(Y2+X2) mod p
        C = T1*2*d*T2 mod p
        D = Z1*2*Z2 mod p
        E = B - A mod p
        F = D - C mod p
        G = D + C mod p
        H = B + A mod p
        X3 = E*F mod p
        Y3 = G*H mod p
        T3 = E*H mod p
        Z3 = F*G mod p
    """
    X1, Y1, Z1, T1 = P
    X2, Y2, Z2, T2 = Q
    A = ((Y1 - X1) * (Y2 - X2)) % p
    B = ((Y1 + X1) * (Y2 + X2)) % p
    C = (T1 * 2 * d * T2) % p
    D = (Z1 * 2 * Z2) % p
    E = (B - A) % p
    F = (D - C) % p
    G = (D + C) % p
    H = (B + A) % p
    X3 = (E * F) % p
    Y3 = (G * H) % p
    T3 = (E * H) % p
    Z3 = (F * G) % p
    return (X3, Y3, Z3, T3)


def scalar_base_mult(scalar: int, curve_obj) -> Point:
    """ScalarBaseMult(scalar) via double-and-add on the generator."""
    if curve_obj is Ed25519:
        return _scalar_mult_ed25519(scalar, curve_obj.generator)
    else:
        return scalar_mult(scalar, curve_obj.generator, curve_obj)


# ============================================================================
# RFC 9591 §6 ciphersuite hash functions
# ============================================================================

def H_secp256k1(msg: bytes) -> bytes:
    """Plain SHA-256 (used for H4, H5 — full digest, not reduced)."""
    return H_SECP256K1(msg).digest()


def H1_secp256k1(m: bytes) -> int:
    """RFC 9591 §6.5 H1(m) = hash_to_field(m, 1) with DST = CTX||'rho', L=48."""
    u = hash_to_field(m, (CTX_SECP256K1_SHA256 + "rho").encode(), 1, ORDER_SECP256K1, 128, H_SECP256K1)
    return u[0]


def H2_secp256k1(m: bytes) -> int:
    """RFC 9591 §6.5 H2(m) = hash_to_field(m, 1) with DST = CTX||'chal', L=48."""
    u = hash_to_field(m, (CTX_SECP256K1_SHA256 + "chal").encode(), 1, ORDER_SECP256K1, 128, H_SECP256K1)
    return u[0]


def H3_secp256k1(m: bytes) -> int:
    """RFC 9591 §6.5 H3(m) = hash_to_field(m, 1) with DST = CTX||'nonce', L=48."""
    u = hash_to_field(m, (CTX_SECP256K1_SHA256 + "nonce").encode(), 1, ORDER_SECP256K1, 128, H_SECP256K1)
    return u[0]


def H4_secp256k1(m: bytes) -> bytes:
    """RFC 9591 §6.5 H4(m) = H(CTX||'msg'||m) — full 32-byte digest (not reduced)."""
    return H_SECP256K1((CTX_SECP256K1_SHA256 + "msg").encode() + m).digest()


def H5_secp256k1(m: bytes) -> bytes:
    """RFC 9591 §6.5 H5(m) = H(CTX||'com'||m) — full 32-byte digest (not reduced)."""
    return H_SECP256K1((CTX_SECP256K1_SHA256 + "com").encode() + m).digest()


def H_ed25519(msg: bytes) -> bytes:
    """Plain SHA-512 (used for H4, H5 — full digest)."""
    return H_ED25519(msg).digest()


def H1_ed25519(m: bytes) -> int:
    """RFC 9591 §6.1 H1(m) = H(CTX||'rho'||m) reduced mod q (little-endian)."""
    h = H_ED25519((CTX_ED25519_SHA512 + "rho").encode() + m).digest()
    return int.from_bytes(h, "little") % ORDER_ED25519


def H2_ed25519(m: bytes) -> int:
    """RFC 9591 §6.1 H2(m) = H(m) reduced mod q (NO domain sep; RFC 8032 compat)."""
    h = H_ED25519(m).digest()
    return int.from_bytes(h, "little") % ORDER_ED25519


def H3_ed25519(m: bytes) -> int:
    """RFC 9591 §6.1 H3(m) = H(CTX||'nonce'||m) reduced mod q (little-endian)."""
    h = H_ED25519((CTX_ED25519_SHA512 + "nonce").encode() + m).digest()
    return int.from_bytes(h, "little") % ORDER_ED25519


def H4_ed25519(m: bytes) -> bytes:
    """RFC 9591 §6.1 H4(m) = H(CTX||'msg'||m) — full 64-byte digest."""
    return H_ED25519((CTX_ED25519_SHA512 + "msg").encode() + m).digest()


def H5_ed25519(m: bytes) -> bytes:
    """RFC 9591 §6.1 H5(m) = H(CTX||'com'||m) — full 64-byte digest."""
    return H_ED25519((CTX_ED25519_SHA512 + "com").encode() + m).digest()


# ============================================================================
# RFC 9591 §4.1 nonce_generate (ciphersuite-dependent)
# ============================================================================

def nonce_generate_secp256k1(secret_share_enc: bytes, randomness: bytes) -> int:
    """RFC 9591 §4.1 nonce_generate for secp256k1_sha256 ciphersuite.
    secret_share_enc is big-endian 32 bytes (SerializeScalar for secp256k1).
    Returns H3(random_bytes || secret_enc) Scalar.
    """
    return H3_secp256k1(randomness + secret_share_enc)


def nonce_generate_ed25519(secret_share_enc: bytes, randomness: bytes) -> int:
    """RFC 9591 §4.1 nonce_generate for ed25519_sha512 ciphersuite.
    secret_share_enc is little-endian 32 bytes (SerializeScalar for ed25519).
    """
    return H3_ed25519(randomness + secret_share_enc)


# ============================================================================
# RFC 9591 §4.3 encode_group_commitment_list
# ============================================================================

def encode_group_commitment_list_secp256k1(commitment_list) -> bytes:
    """Sort by identifier (numeric); emit
    SerializeScalar(id) || ElementEncode(hiding) || ElementEncode(binding)."""
    sorted_list = sorted(commitment_list, key=lambda x: x[0])
    out = b""
    for identifier, hiding_pt, binding_pt in sorted_list:
        out += serialize_scalar_secp256k1(identifier)
        out += compress_secp256k1(hiding_pt)
        out += compress_secp256k1(binding_pt)
    return out


def encode_group_commitment_list_ed25519(commitment_list) -> bytes:
    sorted_list = sorted(commitment_list, key=lambda x: x[0])
    out = b""
    for identifier, hiding_pt, binding_pt in sorted_list:
        out += serialize_scalar_ed25519(identifier)
        out += compress_ed25519(hiding_pt)
        out += compress_ed25519(binding_pt)
    return out


# ============================================================================
# RFC 9591 §4.2 binding factors
# ============================================================================

def compute_binding_factor_secp256k1(identifier, group_public_key, msg_hash, encoded_commitment_hash) -> int:
    """RFC 9591 §4.2 binding_factor = H1(CTX||'rho' || group_pk_enc || msg_hash ||
                                                  encoded_commitment_hash ||
                                                  SerializeScalar(identifier))
    For secp256k1, H1 = hash_to_field via expand_message_xmd (RFC 9380).
    """
    gpk_bytes = compress_secp256k1(group_public_key)
    rho_input = gpk_bytes + msg_hash + encoded_commitment_hash + serialize_scalar_secp256k1(identifier)
    return H1_secp256k1(rho_input)


def compute_binding_factor_ed25519(identifier, group_public_key, msg_hash, encoded_commitment_hash) -> int:
    """RFC 9591 §4.2 for ed25519 ciphersuite (H1 = H(CTX||'rho'||m) reduced)."""
    gpk_bytes = compress_ed25519(group_public_key)
    rho_input = gpk_bytes + msg_hash + encoded_commitment_hash + serialize_scalar_ed25519(identifier)
    return H1_ed25519(rho_input)


def compute_challenge_secp256k1(group_commitment, group_public_key, msg) -> int:
    """RFC 9591 §4.6 + §6.5 challenge = H2(group_comm_enc || group_pk_enc || msg)."""
    R_bytes = compress_secp256k1(group_commitment)
    gpk_bytes = compress_secp256k1(group_public_key)
    challenge_input = R_bytes + gpk_bytes + msg
    return H2_secp256k1(challenge_input)


def compute_challenge_ed25519(group_commitment, group_public_key, msg) -> int:
    """RFC 9591 §4.6 + §6.1 challenge (ed25519: NO domain sep on H2)."""
    R_bytes = compress_ed25519(group_commitment)
    gpk_bytes = compress_ed25519(group_public_key)
    challenge_input = R_bytes + gpk_bytes + msg
    return H2_ed25519(challenge_input)


# ============================================================================
# RFC 9591 §4.2 lagrange coefficient
# ============================================================================

def derive_interpolating_value(L, x_i, n):
    """RFC 9591 §4.2 lambda_i = prod_{j in L, j != i}(j / (j - i)) mod n."""
    num = 1
    den = 1
    for x_j in L:
        if x_j == x_i:
            continue
        num = (num * x_j) % n
        den = (den * (x_j - x_i)) % n
    return (num * pow(den, -1, n)) % n


# ============================================================================
# RFC 9591 §5.2 signature_share
# ============================================================================

def compute_signature_share(hiding_nonce, binding_nonce, binding_factor, challenge, lagrange, sk_share, n):
    """RFC 9591 §5.2 sig_share = d_i + rho* * e_i + lambda_i * sk_i * challenge mod n."""
    return (
        hiding_nonce
        + (binding_factor * binding_nonce) % n
        + (lagrange * sk_share % n) * challenge % n
    ) % n


# ============================================================================
# RFC 9591 §5.3 aggregate + verification
# ============================================================================

def aggregate_R_secp256k1(commitment_list, binding_factor_map) -> Point:
    """RFC 9591 §4.5 group_commitment = sum(hiding) + sum(ScalarMult(binding, rho*))."""
    R = None
    for identifier, hiding_pt, binding_pt in commitment_list:
        if R is None:
            R = hiding_pt
        else:
            R = R + hiding_pt
        bf = binding_factor_map[identifier]
        R = R + scalar_mult(bf, binding_pt, SECP256k1)
    return R


def aggregate_R_ed25519(commitment_list, binding_factor_map) -> Point:
    """RFC 9591 §4.5 group_commitment = sum(hiding) + sum(ScalarMult(binding, rho*))."""
    R = None
    for identifier, hiding_pt, binding_pt in commitment_list:
        if R is None:
            R = hiding_pt
        else:
            R = R + hiding_pt
        bf = binding_factor_map[identifier]
        R = R + scalar_mult(bf, binding_pt, Ed25519)
    return R


def aggregate_z(signature_shares, n):
    z = 0
    for share in signature_shares:
        z = (z + share) % n
    return z


def verify_aggregate_secp256k1(R, z, group_public_key, challenge) -> bool:
    """Schnorr verification: z*B == R + ScalarMult(pk, challenge)."""
    lhs = scalar_mult(z, SECP256k1.generator, SECP256k1)
    rhs = R + scalar_mult(challenge, group_public_key, SECP256k1)
    return lhs.x() == rhs.x() and lhs.y() == rhs.y()


def verify_aggregate_ed25519(R, z, group_public_key, challenge) -> bool:
    """ed25519 verification with cofactor: [8]zB == [8]R + [8][c]PK (RFC 8032 §5.1.7)."""
    lhs = scalar_mult(z, Ed25519.generator, Ed25519)
    rhs = R + scalar_mult(challenge, group_public_key, Ed25519)
    # Multiply both by cofactor 8 for RFC 8032 compat
    lhs8 = lhs * 8
    rhs8 = rhs * 8
    return lhs8.x() == rhs8.x() and lhs8.y() == rhs8.y()


# ============================================================================
# Ciphersuite dispatch
# ============================================================================

CIPHERSUITE_SECP256K1_SHA256 = {
    "name": "FROST(secp256k1, SHA-256)",
    "group": "secp256k1",
    "ctx": CTX_SECP256K1_SHA256,
    "curve_obj": SECP256k1,
    "n": ORDER_SECP256K1,
    "p": P_SECP256K1,
    "hash_func": H_SECP256K1,
    "serialize_scalar": serialize_scalar_secp256k1,
    "deserialize_scalar": deserialize_scalar_secp256k1,
    "compress": compress_secp256k1,
    "decompress": decompress_secp256k1,
    "nonce_generate": nonce_generate_secp256k1,
    "encode_group_commitment_list": encode_group_commitment_list_secp256k1,
    "H4": H4_secp256k1,
    "H5": H5_secp256k1,
    "compute_binding_factor": compute_binding_factor_secp256k1,
    "compute_challenge": compute_challenge_secp256k1,
    "aggregate_R": aggregate_R_secp256k1,
    "verify_aggregate": verify_aggregate_secp256k1,
    "scalar_mult": lambda s, p: scalar_mult(s, p, SECP256k1),
    "scalar_base_mult": lambda s: scalar_base_mult(s, SECP256k1),
}

CIPHERSUITE_ED25519_SHA512 = {
    "name": "FROST(Ed25519, SHA-512)",
    "group": "ed25519",
    "ctx": CTX_ED25519_SHA512,
    "curve_obj": Ed25519,
    "n": ORDER_ED25519,
    "p": P_ED25519,
    "hash_func": H_ED25519,
    "serialize_scalar": serialize_scalar_ed25519,
    "deserialize_scalar": deserialize_scalar_ed25519,
    "compress": compress_ed25519,
    "decompress": decompress_ed25519,
    "nonce_generate": nonce_generate_ed25519,
    "encode_group_commitment_list": encode_group_commitment_list_ed25519,
    "H4": H4_ed25519,
    "H5": H5_ed25519,
    "compute_binding_factor": compute_binding_factor_ed25519,
    "compute_challenge": compute_challenge_ed25519,
    "aggregate_R": aggregate_R_ed25519,
    "verify_aggregate": verify_aggregate_ed25519,
    "scalar_mult": lambda s, p: scalar_mult(s, p, Ed25519),
    "scalar_base_mult": lambda s: scalar_base_mult(s, Ed25519),
}


def select_ciphersuite(group: str) -> dict:
    if group == "secp256k1":
        return CIPHERSUITE_SECP256K1_SHA256
    elif group == "ed25519":
        return CIPHERSUITE_ED25519_SHA512
    else:
        raise ValueError(f"unknown group: {group}")


# ============================================================================
# Full FROST sign path (RFC 9591 §4-§5)
# ============================================================================

def frost_sign(kat_path, group: str = "secp256k1") -> dict:
    """Execute RFC 9591 §5.1-§5.3 round 1 + round 2 + aggregate for the given ciphersuite.

    Args:
        kat_path: path to KAT JSON file (matching ZcashFoundation/frost-rs format).
        group: "secp256k1" or "ed25519".

    Returns:
        dict with per-step outputs and round_two / final expected vs computed.
    """
    with open(kat_path) as f:
        kat = json.load(f)

    cs = select_ciphersuite(group)
    inputs = kat["inputs"]
    round_one_expected = kat["round_one_outputs"]["outputs"]
    round_two_expected = kat.get("round_two_outputs", {}).get("outputs", [])
    final_expected = kat.get("final_output", {}).get("sig", "")

    group_public_key_bytes = bytes.fromhex(inputs["verifying_key_key"])
    group_public_key = cs["decompress"](group_public_key_bytes)
    msg = bytes.fromhex(inputs["message"])
    participant_shares = inputs["participant_shares"]
    participant_list = inputs["participant_list"]

    # §5.1 round 1: commit
    commitment_list = []        # (identifier, hiding_pt, binding_pt)
    signers = {}                # identifier -> (share_scalar, hiding_nonce, binding_nonce)
    round_one_results = []

    for p_expected in round_one_expected:
        identifier = p_expected["identifier"]
        share_hex = next(p["participant_share"] for p in participant_shares
                         if p["identifier"] == identifier)
        share_scalar = int(share_hex, 16)
        share_enc = bytes.fromhex(share_hex)

        hiding_nonce = cs["nonce_generate"](
            secret_share_enc=share_enc,
            randomness=bytes.fromhex(p_expected["hiding_nonce_randomness"]),
        )
        binding_nonce = cs["nonce_generate"](
            secret_share_enc=share_enc,
            randomness=bytes.fromhex(p_expected["binding_nonce_randomness"]),
        )

        hiding_nonce_commitment = cs["scalar_base_mult"](hiding_nonce)
        binding_nonce_commitment = cs["scalar_base_mult"](binding_nonce)

        commitment_list.append((identifier, hiding_nonce_commitment, binding_nonce_commitment))
        signers[identifier] = (share_scalar, hiding_nonce, binding_nonce)

        round_one_results.append({
            "identifier": identifier,
            "hiding_nonce_hex": cs["serialize_scalar"](hiding_nonce).hex(),
            "binding_nonce_hex": cs["serialize_scalar"](binding_nonce).hex(),
            "hiding_nonce_commitment_hex": cs["compress"](hiding_nonce_commitment).hex(),
            "binding_nonce_commitment_hex": cs["compress"](binding_nonce_commitment).hex(),
            "expected_hiding_nonce": p_expected["hiding_nonce"],
            "expected_binding_nonce": p_expected["binding_nonce"],
            "expected_hiding_nonce_commitment": p_expected["hiding_nonce_commitment"],
            "expected_binding_nonce_commitment": p_expected["binding_nonce_commitment"],
            "match_hiding_nonce": cs["serialize_scalar"](hiding_nonce).hex() == p_expected["hiding_nonce"],
            "match_binding_nonce": cs["serialize_scalar"](binding_nonce).hex() == p_expected["binding_nonce"],
            "match_hiding_nonce_commitment": cs["compress"](hiding_nonce_commitment).hex() == p_expected["hiding_nonce_commitment"],
            "match_binding_nonce_commitment": cs["compress"](binding_nonce_commitment).hex() == p_expected["binding_nonce_commitment"],
        })

    # §4.3 + §4.2 group_commitment_hash + message_hash + binding_factors
    encoded_commitments = cs["encode_group_commitment_list"](commitment_list)
    encoded_commitment_hash = cs["H5"](encoded_commitments)
    msg_hash = cs["H4"](msg)

    binding_factor_map = {}
    for identifier, _, _ in sorted(commitment_list, key=lambda x: x[0]):
        binding_factor_map[identifier] = cs["compute_binding_factor"](
            identifier=identifier,
            group_public_key=group_public_key,
            msg_hash=msg_hash,
            encoded_commitment_hash=encoded_commitment_hash,
        )

    for entry in round_one_results:
        expected_entry = next(p for p in round_one_expected if p["identifier"] == entry["identifier"])
        expected_bf_hex = expected_entry["binding_factor"]
        computed_bf_hex = cs["serialize_scalar"](binding_factor_map[entry["identifier"]]).hex()
        entry["expected_binding_factor"] = expected_bf_hex
        entry["computed_binding_factor"] = computed_bf_hex
        entry["match_binding_factor"] = computed_bf_hex == expected_bf_hex

    # §5.2 group_commitment R + challenge e
    R = cs["aggregate_R"](commitment_list, binding_factor_map)
    challenge = cs["compute_challenge"](R, group_public_key, msg)

    # §5.2 lagrange coefficient per signing participant
    lagrange_map = {}
    for identifier in participant_list:
        lagrange_map[identifier] = derive_interpolating_value(
            L=participant_list, x_i=identifier, n=cs["n"],
        )

    # §5.2 signature_share per signing participant
    signature_shares = {}
    for identifier in participant_list:
        share_scalar, hiding_nonce, binding_nonce = signers[identifier]
        signature_shares[identifier] = compute_signature_share(
            hiding_nonce=hiding_nonce,
            binding_nonce=binding_nonce,
            binding_factor=binding_factor_map[identifier],
            challenge=challenge,
            lagrange=lagrange_map[identifier],
            sk_share=share_scalar,
            n=cs["n"],
        )

    # §5.3 aggregate (R, z)
    z = aggregate_z([signature_shares[i] for i in participant_list], cs["n"])
    R_bytes = cs["compress"](R)
    z_bytes = cs["serialize_scalar"](z)
    final_sig = R_bytes + z_bytes

    # §5.3 verify aggregate
    verify_ok = cs["verify_aggregate"](R, z, group_public_key, challenge)

    # Match signature shares against expected
    round_two_results = []
    for expected_ss in round_two_expected:
        identifier = expected_ss["identifier"]
        expected_hex = expected_ss["sig_share"]
        computed_hex = cs["serialize_scalar"](signature_shares[identifier]).hex()
        round_two_results.append({
            "identifier": identifier,
            "expected_sig_share": expected_hex,
            "computed_sig_share": computed_hex,
            "match_sig_share": computed_hex == expected_hex,
        })

    return {
        "ciphersuite": cs["name"],
        "round_one": round_one_results,
        "round_two": round_two_results,
        "aggregate_R_hex": R_bytes.hex(),
        "aggregate_z_hex": z_bytes.hex(),
        "challenge_hex": cs["serialize_scalar"](challenge).hex(),
        "expected_final_sig": final_expected,
        "computed_final_sig": final_sig.hex(),
        "match_final_sig": final_sig.hex() == final_expected,
        "verify_aggregate": verify_ok,
        "group_public_key_hex": group_public_key_bytes.hex(),
        "message_hex": msg.hex(),
    }


# ============================================================================
# Self-test
# ============================================================================

def run_self_test(kat_dir: Optional[Path] = None) -> dict:
    """Run self-test against both RFC 9591 Appendix E.5 and E.1 KAT vectors."""
    if kat_dir is None:
        kat_dir = Path(__file__).parent.parent / "kat"

    results = {}
    for group, fname in [("secp256k1", "rfc9591_appendix_e5_secp256k1.json"),
                         ("ed25519",   "rfc9591_appendix_e1_ed25519.json")]:
        kat_path = kat_dir / fname
        if not kat_path.exists():
            results[group] = {"error": f"missing KAT: {kat_path}"}
            continue
        out = frost_sign(kat_path, group=group)
        all_round1_pass = all(r["match_hiding_nonce"]
                              and r["match_binding_nonce"]
                              and r["match_hiding_nonce_commitment"]
                              and r["match_binding_nonce_commitment"]
                              and r["match_binding_factor"]
                              for r in out["round_one"])
        all_round2_pass = all(r["match_sig_share"] for r in out["round_two"]) if out["round_two"] else False
        results[group] = {
            "ciphersuite": out["ciphersuite"],
            "round_1_match": all_round1_pass,
            "round_2_match": all_round2_pass,
            "aggregate_match": out["match_final_sig"],
            "aggregate_verifies": out["verify_aggregate"],
            "computed_final_sig": out["computed_final_sig"],
            "expected_final_sig": out["expected_final_sig"],
        }
    return results


def main():
    print("FROST Clean-room Reference Implementation (msn-2026-0019)")
    print("=========================================================")
    print()
    print("RFC 9591 §4.1 nonce_generate + §4.2 binding_factor + §4.3 group commitment")
    print("+ §5.1 round 1 commit + §5.2 round 2 sign + §5.3 aggregate + verification.")
    print("Ciphersuites: secp256k1_sha256 (RFC 9591 Appendix E.5)")
    print("              ed25519_sha512   (RFC 9591 Appendix E.1)")
    print()
    print("DERIVATION CONSTRAINT: RFC 9591 + RFC 9380 text + standard Python primitives")
    print("                      + ZCashFoundation/frost-rs KAT JSON shape only.")
    print("                      ecdsa library used for point arithmetic and decompress;")
    print("                      NOT consulted for FROST-specific logic.")
    print()

    results = run_self_test()

    overall_ok = True
    for group, res in results.items():
        print(f"--- {group.upper()} ---")
        if "error" in res:
            print(f"  ERROR: {res['error']}")
            overall_ok = False
            continue
        print(f"  Ciphersuite: {res['ciphersuite']}")
        print(f"  Round 1 (commit + binding_factor): {'PASS' if res['round_1_match'] else 'FAIL'}")
        print(f"  Round 2 (signature shares):         {'PASS' if res['round_2_match'] else 'FAIL'}")
        print(f"  Aggregate (R, z) matches expected:  {'PASS' if res['aggregate_match'] else 'FAIL'}")
        print(f"  Aggregate verifies under pk:        {'PASS' if res['aggregate_verifies'] else 'FAIL'}")
        print(f"  Computed final sig: {res['computed_final_sig']}")
        print(f"  Expected final sig: {res['expected_final_sig']}")
        if not (res['round_1_match'] and res['round_2_match']
                and res['aggregate_match'] and res['aggregate_verifies']):
            overall_ok = False

    print()
    print(f"Overall: {'PASS' if overall_ok else 'FAIL'}")


if __name__ == "__main__":
    main()