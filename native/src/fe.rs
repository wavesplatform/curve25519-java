//! Minimal GF(2^255 - 19) arithmetic on top of fiat-crypto's formally verified field code.
//!
//! curve25519-dalek keeps its `FieldElement` private, but XEdDSA/VXEdDSA need a handful of
//! raw field operations that dalek does not expose with the exact legacy semantics:
//!
//! * the Montgomery -> Edwards map `y = (u - 1) / (u + 1)` where `1/0 == 0` (ref10's
//!   `fe_invert` is a modular exponentiation, so `u = -1` maps to `y = 0` instead of failing);
//! * Signal's Elligator 2 variant used by VXEdDSA's `hash_to_point`, which is *not* the
//!   RFC 9380 map dalek implements.
//!
//! Everything here is constant time.

#[cfg(target_pointer_width = "64")]
use fiat_crypto::curve25519_64 as f;
#[cfg(not(target_pointer_width = "64"))]
use fiat_crypto::curve25519_32 as f;

use f::{fiat_25519_loose_field_element as Loose, fiat_25519_tight_field_element as Tight};

#[derive(Clone, Copy)]
pub struct Fe(Tight);

impl Fe {
    pub fn zero() -> Fe {
        Fe::from_bytes(&[0u8; 32])
    }

    pub fn one() -> Fe {
        let mut b = [0u8; 32];
        b[0] = 1;
        Fe::from_bytes(&b)
    }

    pub fn from_u32(v: u32) -> Fe {
        let mut b = [0u8; 32];
        b[..4].copy_from_slice(&v.to_le_bytes());
        Fe::from_bytes(&b)
    }

    /// Same semantics as ref10 `fe_frombytes`: the top bit is ignored and non-canonical
    /// encodings (values in `[p, 2^255)`) are accepted and reduced.
    pub fn from_bytes(bytes: &[u8; 32]) -> Fe {
        let mut b = *bytes;
        b[31] &= 0x7f;
        let mut out = Tight(Default::default());
        f::fiat_25519_from_bytes(&mut out, &b);
        Fe(out)
    }

    /// Canonical little-endian encoding, same as ref10 `fe_tobytes`.
    pub fn to_bytes(self) -> [u8; 32] {
        let mut out = [0u8; 32];
        f::fiat_25519_to_bytes(&mut out, &self.0);
        out
    }

    fn relax(&self) -> Loose {
        let mut out = Loose(Default::default());
        f::fiat_25519_relax(&mut out, &self.0);
        out
    }

    fn carry(l: &Loose) -> Fe {
        let mut out = Tight(Default::default());
        f::fiat_25519_carry(&mut out, l);
        Fe(out)
    }

    pub fn add(&self, o: &Fe) -> Fe {
        let mut l = Loose(Default::default());
        f::fiat_25519_add(&mut l, &self.0, &o.0);
        Fe::carry(&l)
    }

    pub fn sub(&self, o: &Fe) -> Fe {
        let mut l = Loose(Default::default());
        f::fiat_25519_sub(&mut l, &self.0, &o.0);
        Fe::carry(&l)
    }

    pub fn neg(&self) -> Fe {
        let mut l = Loose(Default::default());
        f::fiat_25519_opp(&mut l, &self.0);
        Fe::carry(&l)
    }

    pub fn mul(&self, o: &Fe) -> Fe {
        let mut out = Tight(Default::default());
        f::fiat_25519_carry_mul(&mut out, &self.relax(), &o.relax());
        Fe(out)
    }

    pub fn square(&self) -> Fe {
        let mut out = Tight(Default::default());
        f::fiat_25519_carry_square(&mut out, &self.relax());
        Fe(out)
    }

    fn square_n(&self, n: u32) -> Fe {
        let mut t = *self;
        for _ in 0..n {
            t = t.square();
        }
        t
    }

    /// Returns `b` if `choice == 1`, else `self`. `choice` must be 0 or 1.
    pub fn select(&self, b: &Fe, choice: u8) -> Fe {
        let mut out = Tight(Default::default());
        f::fiat_25519_selectznz(&mut out.0, choice, &self.0.0, &b.0.0);
        Fe(out)
    }

    /// Returns `(z^(2^250 - 1), z^11)`; the shared prefix of the inversion and
    /// `pow22523` addition chains (same chain as ref10).
    fn pow_2_250_1(&self) -> (Fe, Fe) {
        let z = self;
        let z2 = z.square();
        let z9 = z2.square_n(2).mul(z);
        let z11 = z9.mul(&z2);
        let z_5_0 = z11.square().mul(&z9);
        let z_10_0 = z_5_0.square_n(5).mul(&z_5_0);
        let z_20_0 = z_10_0.square_n(10).mul(&z_10_0);
        let z_40_0 = z_20_0.square_n(20).mul(&z_20_0);
        let z_50_0 = z_40_0.square_n(10).mul(&z_10_0);
        let z_100_0 = z_50_0.square_n(50).mul(&z_50_0);
        let z_200_0 = z_100_0.square_n(100).mul(&z_100_0);
        let z_250_0 = z_200_0.square_n(50).mul(&z_50_0);
        (z_250_0, z11)
    }

    /// `self^(p-2)`; maps 0 to 0 exactly like ref10 `fe_invert`.
    pub fn invert(&self) -> Fe {
        let (t, z11) = self.pow_2_250_1();
        t.square_n(5).mul(&z11)
    }

    /// `self^((p-5)/8)` (ref10 `fe_pow22523`).
    pub fn pow22523(&self) -> Fe {
        let (t, _) = self.pow_2_250_1();
        t.square_n(2).mul(self)
    }
}

/// `y = (u - 1) / (u + 1)` with `1/0 == 0` (ref10 `fe_montx_to_edy`).
pub fn montx_to_edy(u: &Fe) -> Fe {
    let one = Fe::one();
    u.sub(&one).mul(&u.add(&one).invert())
}

/// Montgomery curve right-hand side `u(u^2 + Au + 1)` (ref10 `fe_mont_rhs`).
fn mont_rhs(u: &Fe) -> Fe {
    let a = Fe::from_u32(486662);
    u.mul(&u.square().add(&a.mul(u)).add(&Fe::one()))
}

/// 1 if `x` is a non-square, 0 if it is a square or zero (legacy `legendre_is_nonsquare`).
fn is_nonsquare(x: &Fe) -> u8 {
    // x^((p-1)/2) = ((x^((p-5)/8))^4) * x^2
    let t = x.pow22523().square_n(2).mul(x).mul(x);
    // The Legendre symbol is 0, 1 or p-1; only p-1 has its lowest top-byte bit set.
    t.to_bytes()[31] & 1
}

/// Signal's Elligator 2 map to a Montgomery u-coordinate (legacy `elligator`).
pub fn elligator(r: &Fe) -> Fe {
    let a = Fe::from_u32(486662);
    let one = Fe::one();
    let two_r2 = r.square().add(&r.square());
    let x = a.mul(&two_r2.add(&one).invert()).neg(); // x = -A / (1 + 2r^2)
    let nonsquare = is_nonsquare(&mont_rhs(&x));
    let u = x.add(&Fe::zero().select(&a, nonsquare)); // x, or x + A
    u.select(&u.neg(), nonsquare) // x, or -x - A
}

/// Canonical-encoding check (ref10 `fe_isreduced`): bit 255 clear and value < p.
pub fn is_reduced(bytes: &[u8; 32]) -> bool {
    use subtle::ConstantTimeEq;
    Fe::from_bytes(bytes).to_bytes().ct_eq(bytes).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invert_and_zero() {
        let x = Fe::from_u32(123456789);
        assert_eq!(x.mul(&x.invert()).to_bytes(), Fe::one().to_bytes());
        assert_eq!(Fe::zero().invert().to_bytes(), [0u8; 32]);
    }

    #[test]
    fn minus_one_maps_to_y_zero() {
        let minus_one = Fe::one().neg();
        assert_eq!(montx_to_edy(&minus_one).to_bytes(), [0u8; 32]);
    }

    #[test]
    fn reduced_check() {
        let mut p = [0xffu8; 32];
        p[0] = 0xed;
        p[31] = 0x7f;
        assert!(!is_reduced(&p));
        p[0] = 0xec;
        assert!(is_reduced(&p));
        assert!(!is_reduced(&[0xff; 32]));
    }
}
