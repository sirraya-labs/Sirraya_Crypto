// =============================================================================
// polynomial.rs — FIPS 204 ML-DSA-44
//
// All algorithms cite the exact FIPS 204 algorithm number and line.
// The NTT uses plain mod-q arithmetic (Algorithms 41 & 42) — no Montgomery.
// Montgomery reduction (Algorithm 49) is used ONLY for pointwise_mul since
// it is an optional optimization permitted by §8 ("any mathematically
// equivalent set of steps").
//
// PATCHED: zeroization hardened to use volatile writes (see Poly::zeroize
// and zeroize_bytes below) so the compiler cannot optimize away clears of
// secret key material as dead stores.
// =============================================================================

use crate::constants_44::*;
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake128, Shake256,
};

// =============================================================================
// 1. Modular arithmetic helpers
// =============================================================================

/// Montgomery reduction — Algorithm 49.
///
/// Input: a with |a| ≤ 2^31 · q
/// Output: r such that r ≡ a · 2^{−32} (mod q), |r| < 2q
#[inline(always)]
pub fn montgomery_reduce(a: i64) -> i32 {
    // Line 1: QINV = 58728449  (q^{-1} mod 2^32, positive i32)
    // Line 2: t = (a mod 2^32) · QINV  mod 2^32
    let t = (a as i32).wrapping_mul(QINV);
    // Line 3: r = (a − t·q) / 2^32
    ((a - (t as i64) * (Q as i64)) >> 32) as i32
}

/// Full reduce into [0, q−1].
#[inline(always)]
pub fn freeze(a: i32) -> i32 {
    let r = a % Q;
    if r < 0 {
        r + Q
    } else {
        r
    }
}

/// Centred reduce: map a into (−q/2, q/2].
#[inline(always)]
pub fn centered(a: i32) -> i32 {
    let r = freeze(a);
    if r > (Q - 1) / 2 {
        r - Q
    } else {
        r
    }
}

// =============================================================================
// 2. Rounding functions — FIPS 204 §7.4
// =============================================================================

/// Power2Round — Algorithm 35.
///
/// Decomposes r into (r1, r0) such that r ≡ r1·2^d + r0 (mod q).
/// r0 = r+ mod± 2^d  means r0 is in (−2^{d-1}, 2^{d-1}] i.e. (−4096, 4096].
pub fn power2round(r: i32) -> (i32, i32) {
    let r_plus = freeze(r); // Alg 35 line 1
    let two_d = 1i32 << D; // 2^13 = 8192
    let half = 1i32 << (D - 1); // 2^12 = 4096
    // Alg 35 line 2: r0 = r+ mod± 2^d  →  range (−4096, 4096]
    let mut r0 = r_plus % two_d; // r0 ∈ [0, 8191]
    if r0 > half {
        r0 -= two_d;
    } // map (4096, 8191] → (−4096, −1]
    let r1 = (r_plus - r0) >> D; // Alg 35 line 3
    (r1, r0)
}

/// Decompose — Algorithm 36.
///
/// For ML-DSA-44: γ₂ = (q-1)/88 = 95232
/// Decomposes r into (r1, r0) such that r ≡ r1·2γ₂ + r0 (mod q).
/// r0 = r+ mod± (2γ₂) means r0 is in (−γ₂, γ₂] i.e. (−95232, 95232].
pub fn decompose(r: i32) -> (i32, i32) {
    let r_plus = freeze(r); // Alg 36 line 1
    let alpha = 2 * GAMMA2; // = 190464 for ML-DSA-44
    // Alg 36 line 2: r0 = r+ mod± alpha  →  range (−GAMMA2, GAMMA2]
    let mut r0 = r_plus % alpha; // r0 ∈ [0, alpha−1]
    if r0 > GAMMA2 {
        r0 -= alpha;
    } // map (GAMMA2, alpha−1] → (−GAMMA2, −1]
    // Alg 36 lines 3-6: special case
    if r_plus - r0 == Q - 1 {
        (0, r0 - 1)
    } else {
        ((r_plus - r0) / alpha, r0)
    }
}

/// MakeHint — Algorithm 39.
pub fn make_hint_coeff(z: i32, r: i32) -> i32 {
    let r1 = decompose(r).0; // Alg 39 line 1
    let v1 = decompose(freeze(r + z)).0; // Alg 39 line 2
    if r1 != v1 {
        1
    } else {
        0
    } // Alg 39 line 3
}

/// UseHint — Algorithm 40.
pub fn use_hint_coeff(h: i32, r: i32) -> i32 {
    let m = (Q - 1) / (2 * GAMMA2); // Alg 40 line 1 (= 44 for ML-DSA-44)
    let (r1, r0) = decompose(r); // Alg 40 line 2
    if h == 1 {
        if r0 > 0 {
            (r1 + 1).rem_euclid(m)
        } // Alg 40 line 3
        else {
            (r1 - 1).rem_euclid(m)
        } // Alg 40 line 4
    } else {
        r1 // Alg 40 line 5
    }
}

// =============================================================================
// 3. NTT and inverse NTT — FIPS 204 Algorithms 41 & 42
//
// These are implemented *exactly* as written in the standard using plain mod q.
// No Montgomery optimisation is applied here so the code is directly auditable
// against the spec line-by-line.
// =============================================================================

/// Forward NTT — Algorithm 41.
///
/// Input:  w[0..255] ∈ Z_q
/// Output: ŵ[0..255] ∈ T_q   (in-place)
pub fn ntt(w: &mut [i32; N]) {
    let mut m: usize = 0; // Alg 41 line 4 (m ← 0)
    let mut len: usize = 128; // Alg 41 line 5

    while len >= 1 {
        // Alg 41 line 6
        let mut start: usize = 0; // Alg 41 line 7
        while start < N {
            // Alg 41 line 8
            m += 1; // Alg 41 line 9
            let z = ZETAS[m] as i64; // Alg 41 line 10
            for j in start..start + len {
                // Alg 41 line 11
                // Alg 41 lines 12-14
                let t = ((z * w[j + len] as i64).rem_euclid(Q as i64)) as i32;
                w[j + len] = (w[j] - t).rem_euclid(Q);
                w[j] = (w[j] + t).rem_euclid(Q);
            }
            start += 2 * len; // Alg 41 line 16
        }
        len >>= 1; // Alg 41 line 18
    }
}

/// Inverse NTT — Algorithm 42.
///
/// Input:  ŵ[0..255] ∈ T_q
/// Output: w[0..255] ∈ R_q   (in-place)
pub fn invntt(w: &mut [i32; N]) {
    let mut m: usize = 256; // Alg 42 line 4
    let mut len: usize = 1; // Alg 42 line 5

    while len < N {
        // Alg 42 line 6
        let mut start: usize = 0; // Alg 42 line 7
        while start < N {
            // Alg 42 line 8
            m -= 1; // Alg 42 line 9
            let z = (-(ZETAS[m] as i64)).rem_euclid(Q as i64); // Alg 42 line 10
            for j in start..start + len {
                // Alg 42 line 11
                let t = w[j]; // Alg 42 line 12
                w[j] = (t + w[j + len]).rem_euclid(Q); // Alg 42 line 13
                w[j + len] = (t - w[j + len]).rem_euclid(Q); // Alg 42 line 14
                w[j + len] = ((z * w[j + len] as i64).rem_euclid(Q as i64)) as i32;
                // Alg 42 line 15
            }
            start += 2 * len; // Alg 42 line 17
        }
        len <<= 1; // Alg 42 line 19
    }

    // Alg 42 lines 21-24: multiply each coefficient by f = 256^{-1} mod q = 8347681
    let f: i64 = 8_347_681;
    for j in 0..N {
        w[j] = ((f * w[j] as i64).rem_euclid(Q as i64)) as i32;
    }
}

// =============================================================================
// 4. Polynomial type
// =============================================================================

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Poly {
    pub coeffs: [i32; N],
}

impl Default for Poly {
    fn default() -> Self {
        Self::zero()
    }
}

impl Poly {
    pub const fn zero() -> Self {
        Self { coeffs: [0; N] }
    }

    /// Forward NTT in-place (Algorithm 41).
    pub fn ntt(&mut self) {
        ntt(&mut self.coeffs);
    }

    /// Inverse NTT in-place (Algorithm 42).
    pub fn invntt(&mut self) {
        invntt(&mut self.coeffs);
    }

    /// Pointwise multiply in NTT domain (Algorithm 45).
    ///
    /// Uses Montgomery reduction as an optimisation permitted by §8.
    /// Both operands must be in NTT (T_q) form.
    pub fn pointwise_mul(&self, rhs: &Self) -> Self {
        let mut r = Self::zero();
        for i in 0..N {
            let a = self.coeffs[i] as i64;
            let b = rhs.coeffs[i] as i64;
            r.coeffs[i] = (a * b).rem_euclid(Q as i64) as i32;
        }
        r
    }

    pub fn add(&self, rhs: &Self) -> Self {
        let mut r = Self::zero();
        for i in 0..N {
            r.coeffs[i] = (self.coeffs[i] + rhs.coeffs[i]).rem_euclid(Q);
        }
        r
    }

    pub fn sub(&self, rhs: &Self) -> Self {
        let mut r = Self::zero();
        for i in 0..N {
            r.coeffs[i] = (self.coeffs[i] - rhs.coeffs[i]).rem_euclid(Q);
        }
        r
    }

    pub fn reduce(&mut self) {
        for c in self.coeffs.iter_mut() {
            *c = freeze(*c);
        }
    }

    /// Infinity-norm check using centred representation.
    ///
    /// PATCHED: this used to be `self.coeffs.iter().all(|&c| ...)`, which
    /// short-circuits on the first out-of-bound coefficient. That leaks the
    /// index of the first failing coefficient through timing — a finer-
    /// grained signal layered on top of the (expected, documented) per-key
    /// variance in the rejection-sampling loop's iteration count. This
    /// touches every coefficient unconditionally and ORs the failures
    /// together, so the check itself takes the same time regardless of
    /// where — or whether — a coefficient is out of bound.
    pub fn chknorm(&self, bound: i32) -> bool {
        let mut bad: u32 = 0;
        for &c in self.coeffs.iter() {
            bad |= (centered(c).abs() >= bound) as u32;
        }
        bad == 0
    }

    pub fn coeff(&self, i: usize) -> i32 {
        self.coeffs[i]
    }
    pub fn set_coeff(&mut self, i: usize, v: i32) {
        self.coeffs[i] = v;
    }

    /// Zero out this polynomial's coefficients such that the compiler cannot
    /// optimize the writes away as dead stores (unlike a plain `*c = 0` loop,
    /// which LLVM is free to eliminate if it can prove the buffer is never
    /// read again — exactly the case right before a value is dropped).
    ///
    /// PATCHED: uses `write_volatile` per element instead of a plain store,
    /// plus a compiler fence to prevent reordering across the clear.
    pub fn zeroize(&mut self) {
        for c in self.coeffs.iter_mut() {
            unsafe { core::ptr::write_volatile(c, 0) };
        }
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }

    pub fn power2round(&self) -> (Self, Self) {
        let mut hi = Self::zero();
        let mut lo = Self::zero();
        for i in 0..N {
            let (h, l) = power2round(self.coeffs[i]);
            hi.coeffs[i] = h;
            lo.coeffs[i] = l;
        }
        (hi, lo)
    }

    pub fn decompose(&self) -> (Self, Self) {
        let mut hi = Self::zero();
        let mut lo = Self::zero();
        for i in 0..N {
            let (h, l) = decompose(self.coeffs[i]);
            hi.coeffs[i] = h;
            lo.coeffs[i] = l;
        }
        (hi, lo)
    }
}

/// Zero out a raw secret byte buffer (seeds, key bytes, hashes derived from
/// secret material, etc.) using volatile writes so the compiler cannot
/// eliminate the clear as a dead store.
///
/// PATCHED: added as part of the zeroization hardening pass — call this on
/// every `[u8; N]` that holds secret seed / key material once it is no
/// longer needed (see mldsa44.rs for call sites).
#[inline(always)]
pub fn zeroize_bytes(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        unsafe { core::ptr::write_volatile(b, 0) };
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

// =============================================================================
// 5. SHAKE wrappers — FIPS 202 / FIPS 204 §3.7
// =============================================================================

pub fn shake128(output: &mut [u8], input: &[u8]) {
    let mut h = Shake128::default();
    h.update(input);
    h.finalize_xof().read(output);
}
pub fn shake256(output: &mut [u8], input: &[u8]) {
    let mut h = Shake256::default();
    h.update(input);
    h.finalize_xof().read(output);
}
pub fn shake256_2(output: &mut [u8], a: &[u8], b: &[u8]) {
    let mut h = Shake256::default();
    h.update(a);
    h.update(b);
    h.finalize_xof().read(output);
}
pub fn shake256_3(output: &mut [u8], a: &[u8], b: &[u8], c: &[u8]) {
    let mut h = Shake256::default();
    h.update(a);
    h.update(b);
    h.update(c);
    h.finalize_xof().read(output);
}

// =============================================================================
// 6. Sampling — FIPS 204 §7.3
// =============================================================================

/// RejNTTPoly — Algorithm 30.
/// Samples a̅ ∈ T_q from seed ρ (34 bytes = 32 + 2 for column/row indices).
pub fn rej_ntt_poly(rho: &[u8; SEEDBYTES], col: u8, row: u8) -> Poly {
    let mut seed = [0u8; 34];
    seed[..32].copy_from_slice(rho);
    seed[32] = col;
    seed[33] = row;

    let mut poly = Poly::zero();
    let mut ctr = 0usize;
    let mut buf = [0u8; 3];
    let mut h = Shake128::default();
    h.update(&seed);
    let mut reader = h.finalize_xof();

    while ctr < N {
        reader.read(&mut buf); // Alg 30 line 5
        // CoeffFromThreeBytes — Algorithm 14
        let b2_prime = (buf[2] & 0x7F) as i32; // Alg 14 line 1-4
        let z = ((b2_prime as i32) << 16) | ((buf[1] as i32) << 8) | (buf[0] as i32);
        if z < Q {
            // Alg 14 line 6
            poly.coeffs[ctr] = z;
            ctr += 1;
        }
    }
    poly
}

/// RejBoundedPoly — Algorithm 31.
/// Samples a ∈ R with coefficients in [−η, η] from a 66-byte seed.
pub fn rej_bounded_poly(seed66: &[u8; 66]) -> Poly {
    let mut poly = Poly::zero();
    let mut ctr = 0usize;
    let mut h = Shake256::default();
    h.update(seed66);
    let mut reader = h.finalize_xof();
    let mut byte = [0u8; 1];

    while ctr < N {
        reader.read(&mut byte); // Alg 31 line 5
        let z = byte[0] as i32;
        // CoeffFromHalfByte (Algorithm 15, η=2): b mod 5; reject if b ≥ 15
        let z0 = z & 0x0F;
        let z1 = z >> 4;
        if z0 < 15 {
            // Alg 15 line 1
            poly.coeffs[ctr] = 2 - (z0 - (205 * z0 >> 10) * 5); // 2 − (z0 mod 5)
            ctr += 1;
        }
        if ctr < N && z1 < 15 {
            poly.coeffs[ctr] = 2 - (z1 - (205 * z1 >> 10) * 5);
            ctr += 1;
        }
    }
    poly
}

/// ExpandMask — Algorithm 34.
/// For ML-DSA-44: γ₁ = 2^17, so c = 1 + bitlen(γ₁−1) = 18
/// Samples y[r] ∈ R with coefficients in [−γ₁+1, γ₁]
pub fn expand_mask_poly(rho_prime: &[u8; RHO_PRIME_BYTES], nonce: u16) -> Poly {
    // Alg 34 line 3: ρ′ = ρ″ || IntegerToBytes(μ+r, 2)
    let n_lo = (nonce & 0xFF) as u8;
    let n_hi = (nonce >> 8) as u8;
    // ML-DSA-44: c=18, so 32*18 = 576 bytes (Alg 34 line 4)
    let mut buf = [0u8; 576];
    {
        let mut h = Shake256::default();
        h.update(rho_prime);
        h.update(&[n_lo, n_hi]);
        h.finalize_xof().read(&mut buf);
    }
    // Pack 4 coefficients into 9 bytes (4 × 18 bits = 72 bits)
    let mut poly = Poly::zero();
    for i in 0..(N / 4) {
        let b = i * 9;
        let v0 = (buf[b] as u32) | ((buf[b + 1] as u32) << 8) | ((buf[b + 2] as u32 & 0x03) << 16);
        let v1 = ((buf[b + 2] as u32) >> 2) | ((buf[b + 3] as u32) << 6) | ((buf[b + 4] as u32 & 0x0F) << 14);
        let v2 = ((buf[b + 4] as u32) >> 4) | ((buf[b + 5] as u32) << 4) | ((buf[b + 6] as u32 & 0x3F) << 12);
        let v3 = ((buf[b + 6] as u32) >> 6) | ((buf[b + 7] as u32) << 2) | ((buf[b + 8] as u32) << 10);
        poly.coeffs[4 * i] = GAMMA1 - v0 as i32;
        poly.coeffs[4 * i + 1] = GAMMA1 - v1 as i32;
        poly.coeffs[4 * i + 2] = GAMMA1 - v2 as i32;
        poly.coeffs[4 * i + 3] = GAMMA1 - v3 as i32;
    }
    poly
}

/// SampleInBall — Algorithm 29.
/// For ML-DSA-44: τ = 39
/// Generates c ∈ B_τ from c̃ ∈ B^{λ/4}.
pub fn sample_in_ball(c_tilde: &[u8]) -> Poly {
    let mut poly = Poly::zero();
    let mut h = Shake256::default();
    h.update(c_tilde);
    let mut reader = h.finalize_xof();

    // Alg 29 lines 4-5: s ← H.Squeeze(8),  ℎ ← BytesToBits(s)
    let mut sign_bytes = [0u8; 8];
    reader.read(&mut sign_bytes);
    let mut signs: u64 = 0;
    for i in 0..8 {
        signs |= (sign_bytes[i] as u64) << (8 * i);
    }

    // Alg 29 lines 6-13: Fisher-Yates for TAU positions
    let mut jbuf = [0u8; 1];
    for i in (N - TAU)..N {
        // Alg 29 line 6
        // Alg 29 lines 7-10: squeeze bytes until j ≤ i
        let j = loop {
            reader.read(&mut jbuf);
            let candidate = jbuf[0] as usize;
            if candidate <= i {
                break candidate;
            }
        };
        poly.coeffs[i] = poly.coeffs[j]; // Alg 29 line 11
        poly.coeffs[j] = 1 - 2 * ((signs & 1) as i32); // Alg 29 line 12
        signs >>= 1;
    }
    poly
}

// =============================================================================
// 7. Packing / unpacking — FIPS 204 §7.2
// =============================================================================

// ---- t1: SimpleBitPack(t1, 2^10 − 1) — 10 bits per coeff — Algorithm 22 ----
pub fn polyt1_pack(buf: &mut [u8; POLYT1_PACKEDBYTES], p: &Poly) {
    for i in 0..(N / 4) {
        let t = [
            p.coeffs[4 * i] as u32 & 0x3FF,
            p.coeffs[4 * i + 1] as u32 & 0x3FF,
            p.coeffs[4 * i + 2] as u32 & 0x3FF,
            p.coeffs[4 * i + 3] as u32 & 0x3FF,
        ];
        let b = i * 5;
        buf[b] = t[0] as u8;
        buf[b + 1] = (t[0] >> 8 | t[1] << 2) as u8;
        buf[b + 2] = (t[1] >> 6 | t[2] << 4) as u8;
        buf[b + 3] = (t[2] >> 4 | t[3] << 6) as u8;
        buf[b + 4] = (t[3] >> 2) as u8;
    }
}
pub fn polyt1_unpack(buf: &[u8; POLYT1_PACKEDBYTES]) -> Poly {
    let mut p = Poly::zero();
    for i in 0..(N / 4) {
        let b = i * 5;
        p.coeffs[4 * i] = ((buf[b] as i32) | ((buf[b + 1] as i32) << 8)) & 0x3FF;
        p.coeffs[4 * i + 1] = ((buf[b + 1] as i32 >> 2) | ((buf[b + 2] as i32) << 6)) & 0x3FF;
        p.coeffs[4 * i + 2] = ((buf[b + 2] as i32 >> 4) | ((buf[b + 3] as i32) << 4)) & 0x3FF;
        p.coeffs[4 * i + 3] = ((buf[b + 3] as i32 >> 6) | ((buf[b + 4] as i32) << 2)) & 0x3FF;
    }
    p
}

// ---- t0: BitPack(t0, 2^{d-1}−1, 2^{d-1}) — 13 bits centred — Algorithm 24 ----
pub fn polyt0_pack(buf: &mut [u8; POLYT0_PACKEDBYTES], p: &Poly) {
    let half = 1i32 << (D - 1);
    for i in 0..(N / 8) {
        let t: [u32; 8] =
            core::array::from_fn(|j| (half - p.coeffs[8 * i + j]) as u32 & ((1 << D) - 1));
        let b = i * 13;
        buf[b] = t[0] as u8;
        buf[b + 1] = (t[0] >> 8 | t[1] << 5) as u8;
        buf[b + 2] = (t[1] >> 3) as u8;
        buf[b + 3] = (t[1] >> 11 | t[2] << 2) as u8;
        buf[b + 4] = (t[2] >> 6 | t[3] << 7) as u8;
        buf[b + 5] = (t[3] >> 1) as u8;
        buf[b + 6] = (t[3] >> 9 | t[4] << 4) as u8;
        buf[b + 7] = (t[4] >> 4) as u8;
        buf[b + 8] = (t[4] >> 12 | t[5] << 1) as u8;
        buf[b + 9] = (t[5] >> 7 | t[6] << 6) as u8;
        buf[b + 10] = (t[6] >> 2) as u8;
        buf[b + 11] = (t[6] >> 10 | t[7] << 3) as u8;
        buf[b + 12] = (t[7] >> 5) as u8;
    }
}
pub fn polyt0_unpack(buf: &[u8; POLYT0_PACKEDBYTES]) -> Poly {
    let half = 1i32 << (D - 1);
    let mask = (1i32 << D) - 1;
    let mut p = Poly::zero();
    for i in 0..(N / 8) {
        let b = i * 13;
        let (b0, b1, b2, b3, b4, b5, b6, b7, b8, b9, b10, b11, b12) = (
            buf[b] as i32,
            buf[b + 1] as i32,
            buf[b + 2] as i32,
            buf[b + 3] as i32,
            buf[b + 4] as i32,
            buf[b + 5] as i32,
            buf[b + 6] as i32,
            buf[b + 7] as i32,
            buf[b + 8] as i32,
            buf[b + 9] as i32,
            buf[b + 10] as i32,
            buf[b + 11] as i32,
            buf[b + 12] as i32,
        );
        let t = [
            b0 | (b1 << 8),
            (b1 >> 5) | (b2 << 3) | (b3 << 11),
            (b3 >> 2) | (b4 << 6),
            (b4 >> 7) | (b5 << 1) | (b6 << 9),
            (b6 >> 4) | (b7 << 4) | (b8 << 12),
            (b8 >> 1) | (b9 << 7),
            (b9 >> 6) | (b10 << 2) | (b11 << 10),
            (b11 >> 3) | (b12 << 5),
        ];
        for j in 0..8 {
            p.coeffs[8 * i + j] = half - (t[j] & mask);
        }
    }
    p
}

// ---- s1/s2: BitPack(s, η, η) — 3 bits per coeff (η=2) — Algorithm 24 ----
pub fn polyeta_pack(buf: &mut [u8; POLYETA_PACKEDBYTES], p: &Poly) {
    for i in 0..(N / 8) {
        let t: [u8; 8] = core::array::from_fn(|j| (ETA - p.coeffs[8 * i + j]) as u8);
        let b = i * 3;
        buf[b] = t[0] | (t[1] << 3) | (t[2] << 6);
        buf[b + 1] = (t[2] >> 2) | (t[3] << 1) | (t[4] << 4) | (t[5] << 7);
        buf[b + 2] = (t[5] >> 1) | (t[6] << 2) | (t[7] << 5);
    }
}
pub fn polyeta_unpack(buf: &[u8; POLYETA_PACKEDBYTES]) -> Poly {
    let mut p = Poly::zero();
    for i in 0..(N / 8) {
        let b = i * 3;
        let (b0, b1, b2) = (buf[b] as i32, buf[b + 1] as i32, buf[b + 2] as i32);
        p.coeffs[8 * i] = ETA - (b0 & 0x07);
        p.coeffs[8 * i + 1] = ETA - ((b0 >> 3) & 0x07);
        p.coeffs[8 * i + 2] = ETA - ((b0 >> 6) | ((b1 & 0x01) << 2));
        p.coeffs[8 * i + 3] = ETA - ((b1 >> 1) & 0x07);
        p.coeffs[8 * i + 4] = ETA - ((b1 >> 4) & 0x07);
        p.coeffs[8 * i + 5] = ETA - ((b1 >> 7) | ((b2 & 0x03) << 1));
        p.coeffs[8 * i + 6] = ETA - ((b2 >> 2) & 0x07);
        p.coeffs[8 * i + 7] = ETA - ((b2 >> 5) & 0x07);
    }
    p
}

// ---- z: BitPack(z, γ₁−1, γ₁) — 18 bits per coeff for ML-DSA-44 — Algorithm 26 ----
pub fn polyz_pack(buf: &mut [u8; POLYZ_PACKEDBYTES], p: &Poly) {
    // ML-DSA-44: gamma1 = 2^17, 18 bits per coefficient
    // 4 coefficients × 18 bits = 72 bits = 9 bytes
    for i in 0..(N / 4) {
        let v0 = (GAMMA1 - p.coeffs[4 * i]) as u32 & 0x3FFFF;
        let v1 = (GAMMA1 - p.coeffs[4 * i + 1]) as u32 & 0x3FFFF;
        let v2 = (GAMMA1 - p.coeffs[4 * i + 2]) as u32 & 0x3FFFF;
        let v3 = (GAMMA1 - p.coeffs[4 * i + 3]) as u32 & 0x3FFFF;
        let b = i * 9;
        buf[b] = v0 as u8;
        buf[b + 1] = (v0 >> 8) as u8;
        buf[b + 2] = (v0 >> 16 | v1 << 2) as u8;
        buf[b + 3] = (v1 >> 6) as u8;
        buf[b + 4] = (v1 >> 14 | v2 << 4) as u8;
        buf[b + 5] = (v2 >> 4) as u8;
        buf[b + 6] = (v2 >> 12 | v3 << 6) as u8;
        buf[b + 7] = (v3 >> 2) as u8;
        buf[b + 8] = (v3 >> 10) as u8;
    }
}
pub fn polyz_unpack(buf: &[u8; POLYZ_PACKEDBYTES]) -> Poly {
    let mut p = Poly::zero();
    for i in 0..(N / 4) {
        let b = i * 9;
        let v0 = (buf[b] as u32) | ((buf[b + 1] as u32) << 8) | ((buf[b + 2] as u32 & 0x03) << 16);
        let v1 = ((buf[b + 2] as u32) >> 2) | ((buf[b + 3] as u32) << 6) | ((buf[b + 4] as u32 & 0x0F) << 14);
        let v2 = ((buf[b + 4] as u32) >> 4) | ((buf[b + 5] as u32) << 4) | ((buf[b + 6] as u32 & 0x3F) << 12);
        let v3 = ((buf[b + 6] as u32) >> 6) | ((buf[b + 7] as u32) << 2) | ((buf[b + 8] as u32) << 10);
        p.coeffs[4 * i] = GAMMA1 - v0 as i32;
        p.coeffs[4 * i + 1] = GAMMA1 - v1 as i32;
        p.coeffs[4 * i + 2] = GAMMA1 - v2 as i32;
        p.coeffs[4 * i + 3] = GAMMA1 - v3 as i32;
    }
    p
}

// ---- w1: SimpleBitPack(w1, (q-1)/(2γ₂)−1) — 6 bits per coeff for ML-DSA-44 — Algorithm 28 ----
pub fn polyw1_pack(buf: &mut [u8; POLYW1_PACKEDBYTES], p: &Poly) {
    // ML-DSA-44: (q-1)/(2*gamma2) = (q-1)/(2*(q-1)/88) = 44, max value = 43, needs 6 bits
    // 4 coefficients × 6 bits = 24 bits = 3 bytes
    for i in 0..(N / 4) {
        let t = [
            p.coeffs[4 * i] as u8 & 0x3F,
            p.coeffs[4 * i + 1] as u8 & 0x3F,
            p.coeffs[4 * i + 2] as u8 & 0x3F,
            p.coeffs[4 * i + 3] as u8 & 0x3F,
        ];
        let b = i * 3;
        buf[b] = t[0] | (t[1] << 6);
        buf[b + 1] = (t[1] >> 2) | (t[2] << 4);
        buf[b + 2] = (t[2] >> 4) | (t[3] << 2);
    }
}

// ---- HintBitPack / HintBitUnpack — Algorithms 20 & 21 ----
pub fn hint_pack(h: &[Poly; K], buf: &mut [u8; OMEGA + K]) -> Option<usize> {
    let mut index = 0usize; // Alg 20 line 2
    for i in 0..K {
        // Alg 20 line 3
        for j in 0..N {
            // Alg 20 line 4
            if h[i].coeffs[j] != 0 {
                // Alg 20 line 5
                if index >= OMEGA {
                    return None;
                }
                buf[index] = j as u8; // Alg 20 line 6
                index += 1;
            }
        }
        buf[OMEGA + i] = index as u8; // Alg 20 line 10
    }
    for idx in index..OMEGA {
        buf[idx] = 0;
    }
    Some(index)
}

pub fn hint_unpack(buf: &[u8; OMEGA + K]) -> Option<[Poly; K]> {
    let mut h = [Poly::zero(); K];
    let mut index = 0usize; // Alg 21 line 2
    for i in 0..K {
        // Alg 21 line 3
        let end = buf[OMEGA + i] as usize;
        if end < index || end > OMEGA {
            return None;
        } // Alg 21 line 4
        let first = index;
        while index < end {
            // Alg 21 line 7
            if index > first && buf[index - 1] >= buf[index] {
                return None; // Alg 21 line 9 (strictly increasing)
            }
            h[i].coeffs[buf[index] as usize] = 1; // Alg 21 line 12
            index += 1;
        }
    }
    for i in index..OMEGA {
        // Alg 21 line 16
        if buf[i] != 0 {
            return None;
        } // Alg 21 line 17
    }
    Some(h)
}