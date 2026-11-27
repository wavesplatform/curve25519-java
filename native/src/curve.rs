//! X25519, XEdDSA and VXEdDSA, bit-for-bit compatible with the legacy ref10/donna code
//! from libsignal's curve25519-java (and with this library's pure-Java provider).
//!
//! The heavy lifting (scalar multiplication, SHA-512) is done by curve25519-dalek and sha2,
//! which select the fastest available code path at runtime:
//!
//! * x86-64: AVX-512 IFMA or AVX2 vector backends for curve operations, AVX2 for SHA-512;
//! * aarch64: SHA-512 crypto extensions (ARMv8.2-SHA, all Apple Silicon) for hashing,
//!   64-bit serial field arithmetic for curve operations.

use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::montgomery::MontgomeryPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::{IsIdentity, VartimeMultiscalarMul};
use sha2::{Digest, Sha512};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};
use zeroize::Zeroize;

use crate::fe::{self, Fe};

/// Maximum VXEdDSA message length, as enforced by the legacy implementation.
pub const VRF_MSG_MAX_LEN: usize = 1_048_576;

/// Ed25519 base point encoding, used as a domain-separation prefix by the generalized EdDSA hashes.
const B_BYTES: [u8; 32] = [
    0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
];

const VRF_PROTOCOL_NAME: &[u8; 30] = b"VEdDSA_25519_SHA512_Elligator2";
const LABELSET_LEN: usize = 3 + VRF_PROTOCOL_NAME.len() + 2;

/// `labelset_add(labelset_new("VEdDSA_25519_SHA512_Elligator2", ""), "<n>")`.
fn vrf_labelset(n: u8) -> [u8; LABELSET_LEN] {
    let mut ls = [0u8; LABELSET_LEN];
    ls[0] = 3; // number of labels
    ls[1] = VRF_PROTOCOL_NAME.len() as u8;
    ls[2..32].copy_from_slice(VRF_PROTOCOL_NAME);
    ls[32] = 0; // empty customization label
    ls[33] = 1;
    ls[34] = n;
    ls
}

fn sha512(parts: &[&[u8]]) -> [u8; 64] {
    let mut h = Sha512::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

fn scalar_wide(parts: &[&[u8]]) -> Scalar {
    let mut hash = sha512(parts);
    let s = Scalar::from_bytes_mod_order_wide(&hash);
    hash.zeroize();
    s
}

/// Unclamped X25519: `privkey` is used as a raw 256-bit little-endian integer, exactly like
/// the legacy curve25519-donna build (whose clamping is commented out). Callers clamp at
/// key generation time.
pub fn x25519(privkey: &[u8; 32], pubkey: &[u8; 32]) -> [u8; 32] {
    let bits = (0..256).rev().map(|i| (privkey[i >> 3] >> (i & 7)) & 1 == 1);
    MontgomeryPoint(*pubkey).mul_bits_be(bits).to_bytes()
}

/// X25519 public key: `privkey * 9`. The base point has prime order, so this equals the
/// fixed-base Edwards multiplication by `privkey mod l`, which is several times faster than
/// a Montgomery ladder and yields the identical u-coordinate (including `u = 0` for `l | k`).
pub fn public_key(privkey: &[u8; 32]) -> [u8; 32] {
    let mut k = Scalar::from_bytes_mod_order(*privkey);
    let u = EdwardsPoint::mul_base(&k).to_montgomery().to_bytes();
    k.zeroize();
    u
}

struct EdKeyPair {
    /// Ed25519 public key with the sign bit forced to zero.
    public: [u8; 32],
    /// Private scalar bytes as hashed by the legacy code: the raw private key, or its
    /// negation mod l when the Edwards sign bit had to be flipped.
    secret_bytes: [u8; 32],
    secret: Scalar,
}

impl Drop for EdKeyPair {
    fn drop(&mut self) {
        self.secret_bytes.zeroize();
        self.secret.zeroize();
    }
}

/// XEdDSA key conversion (`calculate_25519_keypair`): derive the Edwards key pair whose
/// public key has sign bit 0.
fn ed_keypair(privkey: &[u8; 32]) -> EdKeyPair {
    let mut k = Scalar::from_bytes_mod_order(*privkey);
    let mut public = EdwardsPoint::mul_base(&k).compress().to_bytes();
    let negate = Choice::from(public[31] >> 7);
    public[31] &= 0x7f;

    let mut neg = -k;
    let mut neg_bytes = neg.to_bytes();
    let mut secret_bytes = *privkey;
    for (b, n) in secret_bytes.iter_mut().zip(neg_bytes.iter()) {
        b.conditional_assign(n, negate);
    }
    let secret = Scalar::conditional_select(&k, &neg, negate);

    k.zeroize();
    neg.zeroize();
    neg_bytes.zeroize();
    EdKeyPair { public, secret_bytes, secret }
}

/// Converts an X25519 public key to the Edwards y-coordinate encoding (sign bit clear).
fn montgomery_to_edwards_y(pubkey: &[u8; 32]) -> [u8; 32] {
    fe::montx_to_edy(&Fe::from_bytes(pubkey)).to_bytes()
}

/// XEdDSA signature (`xed25519_sign`). `random` is the 64-byte nonce suffix.
pub fn xeddsa_sign(privkey: &[u8; 32], msg: &[u8], random: &[u8; 64]) -> [u8; 64] {
    let kp = ed_keypair(privkey);

    let mut prefix = [0xffu8; 32];
    prefix[0] = 0xfe;
    let mut r = scalar_wide(&[&prefix, &kp.secret_bytes, msg, random]);
    let big_r = EdwardsPoint::mul_base(&r).compress().to_bytes();
    let h = scalar_wide(&[&big_r, &kp.public, msg]);
    let s = h * kp.secret + r;
    r.zeroize();

    let mut sig = [0u8; 64];
    sig[..32].copy_from_slice(&big_r);
    sig[32..].copy_from_slice(s.as_bytes());
    sig
}

/// XEdDSA verification (`curve25519_verify`): the Edwards sign bit is taken from the high
/// bit of the signature's last byte, and S only has to be < 2^253.
pub fn xeddsa_verify(pubkey: &[u8; 32], msg: &[u8], sig: &[u8; 64]) -> bool {
    let mut ed_pub = montgomery_to_edwards_y(pubkey);
    ed_pub[31] |= sig[63] & 0x80;

    let mut s_bytes = [0u8; 32];
    s_bytes.copy_from_slice(&sig[32..]);
    s_bytes[31] &= 0x7f;
    if s_bytes[31] & 0xe0 != 0 {
        return false;
    }
    let Some(a) = CompressedEdwardsY(ed_pub).decompress() else {
        return false;
    };

    let big_r = &sig[..32];
    let h = scalar_wide(&[big_r, &ed_pub, msg]);
    // ref10 multiplies by the unreduced S; B has order l, so S mod l gives the same point.
    let s = Scalar::from_bytes_mod_order(s_bytes);
    let r_check = EdwardsPoint::vartime_double_scalar_mul_basepoint(&h, &-a, &s).compress();
    r_check.as_bytes().ct_eq(big_r).into()
}

/// VXEdDSA `hash_to_point`: SHA-512, Signal's Elligator 2, then cofactor clearing.
fn hash_to_point(parts: &[&[u8]]) -> EdwardsPoint {
    let mut hash = sha512(parts);
    let sign_bit = hash[31] & 0x80;
    hash[31] &= 0x7f;
    let mut r_bytes = [0u8; 32];
    r_bytes.copy_from_slice(&hash[..32]);

    let u = fe::elligator(&Fe::from_bytes(&r_bytes));
    let mut y = fe::montx_to_edy(&u).to_bytes();
    y[31] |= sign_bit;
    // Elligator always yields a point on the curve, so decompression cannot fail; the
    // identity fallback is rejected by the callers' neutral-point checks.
    CompressedEdwardsY(y)
        .decompress()
        .unwrap_or_default()
        .mul_by_cofactor()
}

/// VXEdDSA signature (`generalized_xveddsa_25519_sign`, empty customization label).
/// Returns `None` for messages over [`VRF_MSG_MAX_LEN`].
pub fn vxeddsa_sign(privkey: &[u8; 32], msg: &[u8], random: &[u8; 32]) -> Option<[u8; 96]> {
    if msg.len() > VRF_MSG_MAX_LEN {
        return None;
    }
    let kp = ed_keypair(privkey);

    let ls1 = vrf_labelset(b'1');
    let bv = hash_to_point(&[&B_BYTES, &ls1, &kp.public, msg]);
    if bv.is_identity() {
        return None;
    }
    let kv = kp.secret * bv;
    let bv_bytes = bv.compress().to_bytes();
    let kv_bytes = kv.compress().to_bytes();

    // r = H(B || labelset2 || Z || pad || k || pad || labelset2 || K || Bv || Kv || M)
    let ls2 = vrf_labelset(b'2');
    let pad1 = (128 - (32 + LABELSET_LEN + 32) % 128) % 128;
    let pad2 = (128 - (32 + LABELSET_LEN + 32 + pad1 + 32) % 128) % 128;
    let zeros = [0u8; 128];
    let mut r = scalar_wide(&[
        &B_BYTES,
        &ls2,
        random,
        &zeros[..pad1],
        &kp.secret_bytes,
        &zeros[..pad2],
        &ls2,
        &kp.public,
        &bv_bytes,
        &kv_bytes,
        msg,
    ]);
    let big_r = EdwardsPoint::mul_base(&r).compress().to_bytes();
    let rv = (r * bv).compress().to_bytes();

    let ls3 = vrf_labelset(b'3');
    let h = scalar_wide(&[
        &B_BYTES, &ls3, &big_r, &ls3, &kp.public, &bv_bytes, &kv_bytes, &rv, msg,
    ]);
    let s = r + h * kp.secret;
    r.zeroize();

    let mut sig = [0u8; 96];
    sig[..32].copy_from_slice(&kv_bytes);
    sig[32..64].copy_from_slice(h.as_bytes());
    sig[64..].copy_from_slice(s.as_bytes());
    Some(sig)
}

/// VXEdDSA verification (`generalized_xveddsa_25519_verify`); returns the 32-byte VRF output.
pub fn vxeddsa_verify(pubkey: &[u8; 32], msg: &[u8], sig: &[u8; 96]) -> Option<[u8; 32]> {
    if !fe::is_reduced(pubkey) || msg.len() > VRF_MSG_MAX_LEN {
        return None;
    }
    let k_bytes = montgomery_to_edwards_y(pubkey);

    let kv_bytes: &[u8; 32] = sig[..32].try_into().ok()?;
    let h_bytes: [u8; 32] = sig[32..64].try_into().ok()?;
    let s_bytes: [u8; 32] = sig[64..].try_into().ok()?;

    let mut kv_unsigned = *kv_bytes;
    kv_unsigned[31] &= 0x7f;
    if !fe::is_reduced(&kv_unsigned) {
        return None;
    }
    let h = Option::<Scalar>::from(Scalar::from_canonical_bytes(h_bytes))?;
    let s = Option::<Scalar>::from(Scalar::from_canonical_bytes(s_bytes))?;

    let ls1 = vrf_labelset(b'1');
    let bv = hash_to_point(&[&B_BYTES, &ls1, &k_bytes, msg]);
    if bv.is_identity() {
        return None;
    }

    // R = s*B - h*K and Rv = s*Bv - h*Kv
    let k_point = CompressedEdwardsY(k_bytes).decompress()?;
    let big_r = EdwardsPoint::vartime_double_scalar_mul_basepoint(&h, &-k_point, &s)
        .compress()
        .to_bytes();
    let kv_point = CompressedEdwardsY(*kv_bytes).decompress()?;
    // Verification only handles public data, so variable-time Straus is fine here.
    let rv = EdwardsPoint::vartime_multiscalar_mul([s, h], [bv, -kv_point])
        .compress()
        .to_bytes();

    let ckv = kv_point.mul_by_cofactor();
    if k_point.mul_by_cofactor().is_identity() || ckv.is_identity() {
        return None;
    }

    let ls3 = vrf_labelset(b'3');
    let bv_bytes = bv.compress().to_bytes();
    let h_check = scalar_wide(&[
        &B_BYTES, &ls3, &big_r, &ls3, &k_bytes, &bv_bytes, kv_bytes, &rv, msg,
    ]);
    if !bool::from(h_check.as_bytes().ct_eq(&h_bytes)) {
        return None;
    }

    let ls4 = vrf_labelset(b'4');
    let v = sha512(&[&B_BYTES, &ls4, ckv.compress().as_bytes()]);
    let mut out = [0u8; 32];
    out.copy_from_slice(&v[..32]);
    Some(out)
}
