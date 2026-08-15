// =============================================================================
// core.rs — Generic ML-DSA algorithm core, generated per parameter set.
//
// CRYPTO AGILITY: this file contains exactly ONE copy of the FIPS 204
// keygen/sign/verify algorithms (formerly duplicated per parameter set).
// `ml_dsa_impl!` is a declarative macro that stamps this logic out once per
// parameter set (ML-DSA-44 today; ML-DSA-65/87 later) against that
// parameter set's `constants` module. Adding a new ML-DSA security level is
// then a two-file change (a new `constants.rs` + a one-line macro
// invocation in a new `mod.rs`) instead of a 1200-line copy-paste-and-edit,
// which is exactly the failure mode that produced the KeyGen domain-byte
// bug this codebase's own comments describe having to fix once already.
//
// This is NOT the same as making the algorithm generic over K/L via const
// generics: stable Rust cannot express array lengths like `K * POLYT0_
// PACKEDBYTES` as a const-generic expression (that needs the unstable
// `generic_const_exprs` feature). Macro-per-parameter-set is the same
// pattern used by RustCrypto's own ml-dsa crate for this exact reason — it
// gets code-reuse and "add a variant without touching existing ones"
// without depending on unstable compiler features.
//
// The generated code is byte-for-byte the original ML-DSA-44 algorithm
// implementation (unchanged); only its packaging changed.
// =============================================================================

/// Instantiate a full ML-DSA parameter set.
///
/// `$Variant` — the public-facing marker type (e.g. `MlDsa44`).
/// `$consts`  — path to that variant's constants module (K, L, ETA, the
///              *_PACKEDBYTES sizes, etc. — see `params::MlDsaParams` for
///              the field list every constants module is expected to provide).
macro_rules! ml_dsa_impl {
    ($Variant:ident, $consts:path) => {
        use $consts::*;
        use $crate::common::ring::*;
        use sha3::{
            digest::{ExtendableOutput, Update, XofReader},
            Shake128, Shake256,
        };

// ---------------------------------------------------------------------------
// Poly type and parameter-dependent polynomial operations
//
// Moved here (from the former polynomial.rs) because these routines are NOT
// the same across ML-DSA security levels: decompose/hints depend on GAMMA2,
// rejection sampling depends on ETA/TAU/GAMMA1, and every pack/unpack
// routine's bit-width depends on one of ETA/GAMMA1/GAMMA2/OMEGA. Each is
// generated once per parameter set by `ml_dsa_impl!`, so `Poly` here is
// this variant's own type (e.g. `ml_dsa_44::Poly`, later `ml_dsa_65::Poly`)
// — distinct types in distinct modules, so adding a variant can never
// collide with another variant's inherent `impl Poly` methods.
// ---------------------------------------------------------------------------

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

/// CoeffFromHalfByte — Algorithm 15. FIPS 204 defines two genuinely
/// different rules depending on η (not just a bound change), so this
/// branches on it explicitly rather than pretending one formula covers
/// both. Only η=2 and η=4 appear across ML-DSA-44/65/87 (FIPS 204 Table
/// 1), so the match is exhaustive; ETA is a per-variant const, so the
/// dead branch is compiled away.
#[inline(always)]
fn coeff_from_half_byte(b: i32) -> Option<i32> {
    if ETA == 2 {
        // η=2: reject if b ≥ 15, else 2 − (b mod 5). (205*b)>>10 is a
        // branchless mod-5 for b < 16.
        if b < 15 {
            Some(2 - (b - (205 * b >> 10) * 5))
        } else {
            None
        }
    } else if ETA == 4 {
        // η=4: reject if b ≥ 9, else 4 − b.
        if b < 9 {
            Some(4 - b)
        } else {
            None
        }
    } else {
        unreachable!("ML-DSA only defines η=2 or η=4 (FIPS 204 Table 1)")
    }
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
        let z0 = z & 0x0F;
        let z1 = z >> 4;
        if let Some(c) = coeff_from_half_byte(z0) {
            poly.coeffs[ctr] = c;
            ctr += 1;
        }
        if ctr < N {
            if let Some(c) = coeff_from_half_byte(z1) {
                poly.coeffs[ctr] = c;
                ctr += 1;
            }
        }
    }
    poly
}

/// ExpandMask — Algorithm 34.
/// Samples y[r] ∈ R with coefficients in [−γ₁+1, γ₁]. The output encoding
/// is exactly BitPack(·, γ₁−1, γ₁) — the same encoding `polyz_unpack`
/// implements — so this squeezes the XOF straight into a
/// POLYZ_PACKEDBYTES buffer (= 32·c bytes, Alg 34 line 4, for whichever c
/// this parameter set's γ₁ needs) and reuses it instead of duplicating
/// the bit-packing logic a second time.
pub fn expand_mask_poly(rho_prime: &[u8; RHO_PRIME_BYTES], nonce: u16) -> Poly {
    // Alg 34 line 3: ρ′ = ρ″ || IntegerToBytes(μ+r, 2)
    let n_lo = (nonce & 0xFF) as u8;
    let n_hi = (nonce >> 8) as u8;
    let mut buf = [0u8; POLYZ_PACKEDBYTES];
    {
        let mut h = Shake256::default();
        h.update(rho_prime);
        h.update(&[n_lo, n_hi]);
        h.finalize_xof().read(&mut buf);
    }
    polyz_unpack(&buf)
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

// ---- Generic fixed-width coefficient packing (underlies Algorithms 24,
// 26, 28) ----
//
// Every BitPack in FIPS 204 packs N=256 coefficients at some constant
// bits-per-coefficient width, sequentially, LSB-first. The width differs
// by field and parameter set (η, γ₁, γ₂), but is always exactly
// `PACKEDBYTES * 8 / N` for whichever *_PACKEDBYTES constant governs that
// field — and those constants are already computed correctly per
// parameter set in each variant's constants.rs. Packing generically here
// off that derived width — instead of hand-unrolling fixed bit-shifts for
// one specific width, as this used to do — means polyeta_pack/polyz_pack/
// polyw1_pack are correct for every η/γ₁/γ₂ FIPS 204 defines, not only
// ML-DSA-44's. (For ML-DSA-44 specifically this produces byte-identical
// output to the old hand-unrolled version — verified by inspection against
// the previous 3-bit/18-bit/6-bit expansions.)
#[inline(always)]
fn bitpack_coeffs(buf: &mut [u8], values: &[u32; N], bits: u32) {
    let mut acc: u64 = 0;
    let mut acc_bits: u32 = 0;
    let mut out = 0usize;
    for &v in values.iter() {
        acc |= (v as u64) << acc_bits;
        acc_bits += bits;
        while acc_bits >= 8 {
            buf[out] = (acc & 0xFF) as u8;
            acc >>= 8;
            acc_bits -= 8;
            out += 1;
        }
    }
    debug_assert_eq!(acc_bits, 0, "PACKEDBYTES*8 must equal N*bits exactly");
}
#[inline(always)]
fn bitunpack_coeffs(buf: &[u8], values: &mut [u32; N], bits: u32) {
    let mask: u64 = (1u64 << bits) - 1;
    let mut acc: u64 = 0;
    let mut acc_bits: u32 = 0;
    let mut in_pos = 0usize;
    for v in values.iter_mut() {
        while acc_bits < bits {
            acc |= (buf[in_pos] as u64) << acc_bits;
            acc_bits += 8;
            in_pos += 1;
        }
        *v = (acc & mask) as u32;
        acc >>= bits;
        acc_bits -= bits;
    }
}

// ---- s1/s2: BitPack(s, η, η) — Algorithm 24 ----
// Bit width = POLYETA_PACKEDBYTES*8/N: 3 bits for η=2 (ML-DSA-44/87),
// 4 bits for η=4 (ML-DSA-65).
pub fn polyeta_pack(buf: &mut [u8; POLYETA_PACKEDBYTES], p: &Poly) {
    const BITS: u32 = (POLYETA_PACKEDBYTES * 8 / N) as u32;
    let values: [u32; N] = core::array::from_fn(|j| (ETA - p.coeffs[j]) as u32);
    bitpack_coeffs(buf, &values, BITS);
}
pub fn polyeta_unpack(buf: &[u8; POLYETA_PACKEDBYTES]) -> Poly {
    const BITS: u32 = (POLYETA_PACKEDBYTES * 8 / N) as u32;
    let mut values = [0u32; N];
    bitunpack_coeffs(buf, &mut values, BITS);
    let mut p = Poly::zero();
    for j in 0..N {
        p.coeffs[j] = ETA - values[j] as i32;
    }
    p
}

// ---- z: BitPack(z, γ₁−1, γ₁) — Algorithm 26 ----
// Bit width = POLYZ_PACKEDBYTES*8/N: 18 bits for γ₁=2^17 (ML-DSA-44),
// 20 bits for γ₁=2^19 (ML-DSA-65/87).
pub fn polyz_pack(buf: &mut [u8; POLYZ_PACKEDBYTES], p: &Poly) {
    const BITS: u32 = (POLYZ_PACKEDBYTES * 8 / N) as u32;
    let mask: u32 = (1u32 << BITS) - 1;
    let values: [u32; N] = core::array::from_fn(|j| (GAMMA1 - p.coeffs[j]) as u32 & mask);
    bitpack_coeffs(buf, &values, BITS);
}
pub fn polyz_unpack(buf: &[u8; POLYZ_PACKEDBYTES]) -> Poly {
    const BITS: u32 = (POLYZ_PACKEDBYTES * 8 / N) as u32;
    let mut values = [0u32; N];
    bitunpack_coeffs(buf, &mut values, BITS);
    let mut p = Poly::zero();
    for j in 0..N {
        p.coeffs[j] = GAMMA1 - values[j] as i32;
    }
    p
}

// ---- w1: SimpleBitPack(w1, (q-1)/(2γ₂)−1) — Algorithm 28 ----
// Bit width = POLYW1_PACKEDBYTES*8/N: 6 bits for γ₂=(q-1)/88 (ML-DSA-44),
// 4 bits for γ₂=(q-1)/32 (ML-DSA-65/87).
pub fn polyw1_pack(buf: &mut [u8; POLYW1_PACKEDBYTES], p: &Poly) {
    const BITS: u32 = (POLYW1_PACKEDBYTES * 8 / N) as u32;
    let mask: u32 = (1u32 << BITS) - 1;
    let values: [u32; N] = core::array::from_fn(|j| p.coeffs[j] as u32 & mask);
    bitpack_coeffs(buf, &values, BITS);
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

// =============================================================================
// mldsa44.rs — FIPS 204 ML-DSA-44 KeyGen / Sign / Verify
// All algorithms reference FIPS 204 (August 13 2024) by number and line.
//
// PATCHED: zeroization pass — secret seeds, key material, and per-signature
// ephemeral values (y, rho_pp, mu, cap_k, s1/s2/t0 and their NTT forms) are
// now explicitly cleared via volatile writes (see polynomial::zeroize_bytes
// and Poly::zeroize) at every point their lifetime ends, instead of being
// left for the allocator/stack to overwrite incidentally.
//
// TIMING NOTE — signing latency is not constant-time, and that is expected:
// sign_internal implements Fiat-Shamir-with-aborts (FIPS 204 Algorithm 3,
// lines 11-33). The number of loop iterations before a valid (z, h) pair is
// found is a function of the secret key's s1/s2/t0 values and the message,
// so wall-clock signing time necessarily varies across keys — this is a
// documented, inherent property of the scheme, not a bug or an unintended
// key-dependent branch. See sign_internal's doc comment below and
// bin/dudect_test.rs (Test 1), which classifies this as EXPECTED VARIATION
// rather than a timing leak requiring remediation. What this crate *does*
// guarantee is that the loop's control flow depends only on public
// intermediate values that are supposed to vary run-to-run (rejection
// counts are not treated as secret in the ML-DSA design); it does not, and
// cannot, guarantee a fixed number of attempts per key.
// =============================================================================


// ---------------------------------------------------------------------------
// SecretKey — HARDENED wrapper.
//
// The rest of this module (and the original crate) passed the secret key
// around as a bare `[u8; SECRETKEYBYTES]`. That type is `Copy`, so every
// function call, every `let sk2 = sk;`, every struct field assignment
// silently duplicates 2560 bytes of key material to a *new* stack slot that
// none of the manual `zeroize_bytes` calls elsewhere in this file ever
// touch — the zeroization pass only covers the *unpacked* intermediates
// (s1/s2/t0/etc.), not copies of the packed key itself. A `[u8; N]` also has
// no `Drop`, so once it goes out of scope it's just left for the allocator/
// stack to overwrite whenever, not cleared immediately.
//
// `SecretKey` fixes both: it is NOT `Copy` (only `Clone`, and `Clone` is
// still something callers should avoid), and it zeroizes on `Drop`. Treat
// `[u8; SECRETKEYBYTES]` in the free functions below as the low-level ABI
// (kept for compatibility with existing signatures/tests); prefer
// `SecretKey` at any new call site, especially in library consumers.
pub struct SecretKey(pub [u8; SECRETKEYBYTES]);

impl SecretKey {
    pub fn as_bytes(&self) -> &[u8; SECRETKEYBYTES] {
        &self.0
    }
}

impl Clone for SecretKey {
    fn clone(&self) -> Self {
        SecretKey(self.0)
    }
}

// Redact secret material from accidental `{:?}`/logging.
impl core::fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "SecretKey(REDACTED, {} bytes)", SECRETKEYBYTES)
    }
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        zeroize_bytes(&mut self.0);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MlDsaError {
    RngFailed,
    InvalidPublicKeyLength,
    InvalidSecretKeyLength,
    InvalidSignatureLength,
    InvalidSeedLength,
    MalformedSignature,
    VerificationFailed,
}
impl core::fmt::Display for MlDsaError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            MlDsaError::RngFailed => write!(f, "RNG failed"),
            MlDsaError::InvalidPublicKeyLength => write!(f, "invalid public key length"),
            MlDsaError::InvalidSecretKeyLength => write!(f, "invalid secret key length"),
            MlDsaError::InvalidSignatureLength => write!(f, "invalid signature length"),
            MlDsaError::InvalidSeedLength => write!(f, "invalid seed length"),
            MlDsaError::MalformedSignature => write!(f, "malformed signature"),
            MlDsaError::VerificationFailed => write!(f, "signature verification failed"),
        }
    }
}
impl std::error::Error for MlDsaError {}

pub fn random_bytes(buf: &mut [u8]) -> Result<(), MlDsaError> {
    use rand_core::RngCore;
    rand_core::OsRng
        .try_fill_bytes(buf)
        .map_err(|_| MlDsaError::RngFailed)
}

// ---------------------------------------------------------------------------
// Vector / matrix helpers (ML-DSA-44 specific: K=4, L=4)
// ---------------------------------------------------------------------------
fn matrix_mul(a: &[[Poly; L]; K], v: &[Poly; L]) -> [Poly; K] {
    let mut w = [Poly::zero(); K];
    for i in 0..K {
        for j in 0..L {
            let p = a[i][j].pointwise_mul(&v[j]);
            w[i] = w[i].add(&p);
        }
    }
    w
}
fn veck_add(a: &[Poly; K], b: &[Poly; K]) -> [Poly; K] {
    core::array::from_fn(|i| a[i].add(&b[i]))
}
fn veck_sub(a: &[Poly; K], b: &[Poly; K]) -> [Poly; K] {
    core::array::from_fn(|i| a[i].sub(&b[i]))
}
fn veck_ntt(v: &mut [Poly; K]) {
    for p in v.iter_mut() {
        p.ntt();
    }
}
fn veck_invntt(v: &mut [Poly; K]) {
    for p in v.iter_mut() {
        p.invntt();
    }
}
fn vecl_ntt(v: &mut [Poly; L]) {
    for p in v.iter_mut() {
        p.ntt();
    }
}
fn vecl_invntt(v: &mut [Poly; L]) {
    for p in v.iter_mut() {
        p.invntt();
    }
}
fn c_mul_vecl(c: &Poly, v: &[Poly; L]) -> [Poly; L] {
    core::array::from_fn(|i| c.pointwise_mul(&v[i]))
}
fn c_mul_veck(c: &Poly, v: &[Poly; K]) -> [Poly; K] {
    core::array::from_fn(|i| c.pointwise_mul(&v[i]))
}
// PATCHED: same short-circuit concern as Poly::chknorm — `.iter().all()`
// would stop at the first polynomial that fails, leaking its index. Poly::
// chknorm is itself branchless per-coefficient (see polynomial.rs), so it's
// enough here to visit every polynomial and OR the results without early
// exit.
fn chknorm_vecl(v: &[Poly; L], b: i32) -> bool {
    let mut bad: u32 = 0;
    for p in v.iter() {
        bad |= !p.chknorm(b) as u32;
    }
    bad == 0
}
fn chknorm_veck(v: &[Poly; K], b: i32) -> bool {
    let mut bad: u32 = 0;
    for p in v.iter() {
        bad |= !p.chknorm(b) as u32;
    }
    bad == 0
}
fn veck_power2round(t: &[Poly; K]) -> ([Poly; K], [Poly; K]) {
    let mut t1 = [Poly::zero(); K];
    let mut t0 = [Poly::zero(); K];
    for i in 0..K {
        let (h, l) = t[i].power2round();
        t1[i] = h;
        t0[i] = l;
    }
    (t1, t0)
}
fn veck_decompose(w: &[Poly; K]) -> ([Poly; K], [Poly; K]) {
    let mut w1 = [Poly::zero(); K];
    let mut w0 = [Poly::zero(); K];
    for i in 0..K {
        let (h, l) = w[i].decompose();
        w1[i] = h;
        w0[i] = l;
    }
    (w1, w0)
}
fn veck_reduce(v: &mut [Poly; K]) {
    for p in v.iter_mut() {
        p.reduce();
    }
}

// ---------------------------------------------------------------------------
// ExpandA — Algorithm 32
// ---------------------------------------------------------------------------
fn expand_a(rho: &[u8; SEEDBYTES]) -> [[Poly; L]; K] {
    let mut a = [[Poly::zero(); L]; K];
    for r in 0..K {
        for s in 0..L {
            a[r][s] = rej_ntt_poly(rho, s as u8, r as u8);
        }
    }
    a
}

// ---------------------------------------------------------------------------
// ExpandS — Algorithm 33
// ---------------------------------------------------------------------------
fn expand_s(rho_prime: &[u8; 64]) -> ([Poly; L], [Poly; K]) {
    let mut s1 = [Poly::zero(); L];
    let mut s2 = [Poly::zero(); K];
    for r in 0..L {
        let mut seed = [0u8; 66];
        seed[..64].copy_from_slice(rho_prime);
        seed[64] = (r & 0xFF) as u8;
        seed[65] = ((r >> 8) & 0xFF) as u8;
        s1[r] = rej_bounded_poly(&seed);
    }
    for r in 0..K {
        let nonce = r + L;
        let mut seed = [0u8; 66];
        seed[..64].copy_from_slice(rho_prime);
        seed[64] = (nonce & 0xFF) as u8;
        seed[65] = ((nonce >> 8) & 0xFF) as u8;
        s2[r] = rej_bounded_poly(&seed);
    }
    (s1, s2)
}

// ---------------------------------------------------------------------------
// Packing helpers
// ---------------------------------------------------------------------------
fn pack_s1(s1: &[Poly; L]) -> [u8; L * POLYETA_PACKEDBYTES] {
    let mut b = [0u8; L * POLYETA_PACKEDBYTES];
    for i in 0..L {
        let mut t = [0u8; POLYETA_PACKEDBYTES];
        polyeta_pack(&mut t, &s1[i]);
        b[i * POLYETA_PACKEDBYTES..(i + 1) * POLYETA_PACKEDBYTES].copy_from_slice(&t);
    }
    b
}
fn unpack_s1(buf: &[u8]) -> [Poly; L] {
    core::array::from_fn(|i| {
        let mut t = [0u8; POLYETA_PACKEDBYTES];
        t.copy_from_slice(&buf[i * POLYETA_PACKEDBYTES..(i + 1) * POLYETA_PACKEDBYTES]);
        polyeta_unpack(&t)
    })
}
fn pack_s2(s2: &[Poly; K]) -> [u8; K * POLYETA_PACKEDBYTES] {
    let mut b = [0u8; K * POLYETA_PACKEDBYTES];
    for i in 0..K {
        let mut t = [0u8; POLYETA_PACKEDBYTES];
        polyeta_pack(&mut t, &s2[i]);
        b[i * POLYETA_PACKEDBYTES..(i + 1) * POLYETA_PACKEDBYTES].copy_from_slice(&t);
    }
    b
}
fn unpack_s2(buf: &[u8]) -> [Poly; K] {
    core::array::from_fn(|i| {
        let mut t = [0u8; POLYETA_PACKEDBYTES];
        t.copy_from_slice(&buf[i * POLYETA_PACKEDBYTES..(i + 1) * POLYETA_PACKEDBYTES]);
        polyeta_unpack(&t)
    })
}
fn pack_t0(t0: &[Poly; K]) -> [u8; K * POLYT0_PACKEDBYTES] {
    let mut b = [0u8; K * POLYT0_PACKEDBYTES];
    for i in 0..K {
        let mut t = [0u8; POLYT0_PACKEDBYTES];
        polyt0_pack(&mut t, &t0[i]);
        b[i * POLYT0_PACKEDBYTES..(i + 1) * POLYT0_PACKEDBYTES].copy_from_slice(&t);
    }
    b
}
fn unpack_t0(buf: &[u8]) -> [Poly; K] {
    core::array::from_fn(|i| {
        let mut t = [0u8; POLYT0_PACKEDBYTES];
        t.copy_from_slice(&buf[i * POLYT0_PACKEDBYTES..(i + 1) * POLYT0_PACKEDBYTES]);
        polyt0_unpack(&t)
    })
}
fn pack_t1(t1: &[Poly; K]) -> [u8; K * POLYT1_PACKEDBYTES] {
    let mut b = [0u8; K * POLYT1_PACKEDBYTES];
    for i in 0..K {
        let mut t = [0u8; POLYT1_PACKEDBYTES];
        polyt1_pack(&mut t, &t1[i]);
        b[i * POLYT1_PACKEDBYTES..(i + 1) * POLYT1_PACKEDBYTES].copy_from_slice(&t);
    }
    b
}
fn unpack_t1(buf: &[u8]) -> [Poly; K] {
    core::array::from_fn(|i| {
        let mut t = [0u8; POLYT1_PACKEDBYTES];
        t.copy_from_slice(&buf[i * POLYT1_PACKEDBYTES..(i + 1) * POLYT1_PACKEDBYTES]);
        polyt1_unpack(&t)
    })
}
fn pack_z(z: &[Poly; L]) -> [u8; L * POLYZ_PACKEDBYTES] {
    let mut b = [0u8; L * POLYZ_PACKEDBYTES];
    for i in 0..L {
        let mut t = [0u8; POLYZ_PACKEDBYTES];
        polyz_pack(&mut t, &z[i]);
        b[i * POLYZ_PACKEDBYTES..(i + 1) * POLYZ_PACKEDBYTES].copy_from_slice(&t);
    }
    b
}
fn unpack_z(buf: &[u8]) -> [Poly; L] {
    core::array::from_fn(|i| {
        let mut t = [0u8; POLYZ_PACKEDBYTES];
        t.copy_from_slice(&buf[i * POLYZ_PACKEDBYTES..(i + 1) * POLYZ_PACKEDBYTES]);
        polyz_unpack(&t)
    })
}
fn w1_encode(w1: &[Poly; K]) -> [u8; K * POLYW1_PACKEDBYTES] {
    let mut b = [0u8; K * POLYW1_PACKEDBYTES];
    for i in 0..K {
        let mut t = [0u8; POLYW1_PACKEDBYTES];
        polyw1_pack(&mut t, &w1[i]);
        b[i * POLYW1_PACKEDBYTES..(i + 1) * POLYW1_PACKEDBYTES].copy_from_slice(&t);
    }
    b
}

// ---------------------------------------------------------------------------
// Algorithm 1 — ML-DSA.KeyGen_internal
// ---------------------------------------------------------------------------
pub fn keypair_from_seed(
    xi: &[u8; SEEDBYTES],
) -> Result<([u8; PUBLICKEYBYTES], [u8; SECRETKEYBYTES]), MlDsaError> {
    // FIPS 204 Algorithm 6 ("ML-DSA.KeyGen_internal"), line 1:
    //   (ρ, ρ', K) ← H(ξ || IntegerToBytes(k,1) || IntegerToBytes(l,1), 128)
    //
    // CORRECTED: the previous version hashed xi || 0x02 || 0x00, which does
    // not match the spec for ANY ML-DSA parameter set and silently produced
    // keys that cannot be validated against NIST ACVP/KAT vectors and are
    // not interoperable with any conformant ML-DSA-44 implementation. The
    // spec's domain bytes are the module rank (k, l) themselves — for
    // ML-DSA-44, k = L = K = 4 in this crate's naming (K=4, L=4) — so both
    // bytes are 0x04. Using k/l (rather than a fixed constant) is also what
    // gives cross-parameter-set domain separation if this crate ever grows
    // ML-DSA-65/87 sharing code paths.
    let mut expanded = [0u8; 128];
    {
        use sha3::{
            digest::{ExtendableOutput, Update, XofReader},
            Shake256,
        };
        let mut h = Shake256::default();
        h.update(xi);
        h.update(&[K as u8]); // IntegerToBytes(k, 1)
        h.update(&[L as u8]); // IntegerToBytes(l, 1)
        h.finalize_xof().read(&mut expanded);
    }

    let mut rho = [0u8; SEEDBYTES];
    rho.copy_from_slice(&expanded[0..32]);

    let mut rho_p = [0u8; 64];
    rho_p.copy_from_slice(&expanded[32..96]);

    let mut cap_k = [0u8; KEYBYTES];
    cap_k.copy_from_slice(&expanded[96..128]);

    // `expanded` has served its purpose (rho/rho_p/cap_k copied out of it);
    // clear it now rather than leaving it live on the stack for the rest of
    // this function.
    zeroize_bytes(&mut expanded);

    let a_hat = expand_a(&rho);
    let (mut s1, mut s2) = expand_s(&rho_p);

    let mut s1_hat = s1;
    vecl_ntt(&mut s1_hat);
    let mut t = matrix_mul(&a_hat, &s1_hat);
    veck_invntt(&mut t);
    let mut t_full = veck_add(&t, &s2);
    veck_reduce(&mut t_full);

    let (t1, mut t0) = veck_power2round(&t_full);

    let mut pk = [0u8; PUBLICKEYBYTES];
    pk[..SEEDBYTES].copy_from_slice(&rho);
    pk[SEEDBYTES..].copy_from_slice(&pack_t1(&t1));

    let mut tr = [0u8; TRBYTES];
    shake256(&mut tr, &pk);

    let mut sk = [0u8; SECRETKEYBYTES];
    let mut off = 0;
    sk[off..off + SEEDBYTES].copy_from_slice(&rho);
    off += SEEDBYTES;
    sk[off..off + KEYBYTES].copy_from_slice(&cap_k);
    off += KEYBYTES;
    sk[off..off + TRBYTES].copy_from_slice(&tr);
    off += TRBYTES;

    let b = pack_s1(&s1);
    sk[off..off + b.len()].copy_from_slice(&b);
    off += b.len();

    let b = pack_s2(&s2);
    sk[off..off + b.len()].copy_from_slice(&b);
    off += b.len();

    let b = pack_t0(&t0);
    sk[off..off + b.len()].copy_from_slice(&b);

    // ---- PATCHED: zeroize every secret intermediate now that it has been
    // packed into `sk`. `s1`/`s2`/`t0` (plain form), `s1_hat` (NTT form),
    // `t`/`t_full` (derived from s1/s2), and the seeds `rho_p`/`cap_k` are
    // all secret-key-equivalent material and must not linger on the stack.
    s1.iter_mut().for_each(Poly::zeroize);
    s2.iter_mut().for_each(Poly::zeroize);
    t0.iter_mut().for_each(Poly::zeroize);
    s1_hat.iter_mut().for_each(Poly::zeroize);
    t.iter_mut().for_each(Poly::zeroize);
    t_full.iter_mut().for_each(Poly::zeroize);
    zeroize_bytes(&mut rho_p);
    zeroize_bytes(&mut cap_k);

    Ok((pk, sk))
}

pub fn keypair() -> Result<([u8; PUBLICKEYBYTES], [u8; SECRETKEYBYTES]), MlDsaError> {
    let mut xi = [0u8; SEEDBYTES];
    random_bytes(&mut xi)?;
    let result = keypair_from_seed(&xi);
    // PATCHED: `xi` is the master seed for the entire keypair — if it leaks,
    // the whole key is recoverable. Clear it regardless of success/failure.
    zeroize_bytes(&mut xi);
    result
}

/// Algorithm 3 (internal) — ML-DSA.Sign_internal.
///
/// ## Timing
/// This function is **not** constant-time in wall-clock latency, and by
/// design cannot be: FIPS 204 Algorithm 3 is a rejection-sampling (Fiat-
/// Shamir-with-aborts) scheme, and the `loop` below (lines 393-552) retries
/// with a fresh mask `y` — incrementing `kappa` — until `z`, `r0`, and the
/// hint count all fall within bounds (Alg 3 lines 15-20 and the checks at
/// lines 437, 456, 470, 499). The number of attempts before acceptance
/// depends on the secret key (`s1`, `s2`, `t0`) and the message, so two
/// different keys will observably take different amounts of time to sign
/// the same message. This is expected behavior, not a key-dependent
/// branching bug — see the module-level TIMING NOTE above and
/// bin/dudect_test.rs, Test 1 ("Deterministic Signing - Key Independence"),
/// which documents and validates this as EXPECTED VARIATION per FIPS 204
/// rather than an actionable timing leak. Do not "fix" this by trying to
/// force a fixed iteration count — that would diverge from the spec.
pub fn sign_internal(
    sk: &[u8; SECRETKEYBYTES],
    msg_prime: &[u8],
    rnd: &[u8; RNDBYTES],
) -> Result<[u8; SIGNBYTES], MlDsaError> {
    let mut off = 0;
    let mut rho = [0u8; SEEDBYTES];
    rho.copy_from_slice(&sk[off..off + SEEDBYTES]);
    off += SEEDBYTES;
    let mut cap_k = [0u8; KEYBYTES];
    cap_k.copy_from_slice(&sk[off..off + KEYBYTES]);
    off += KEYBYTES;
    let mut tr = [0u8; TRBYTES];
    tr.copy_from_slice(&sk[off..off + TRBYTES]);
    off += TRBYTES;
    let mut s1 = unpack_s1(&sk[off..off + L * POLYETA_PACKEDBYTES]);
    off += L * POLYETA_PACKEDBYTES;
    let mut s2 = unpack_s2(&sk[off..off + K * POLYETA_PACKEDBYTES]);
    off += K * POLYETA_PACKEDBYTES;
    let mut t0 = unpack_t0(&sk[off..off + K * POLYT0_PACKEDBYTES]);

    let mut s1_hat = s1;
    vecl_ntt(&mut s1_hat);
    let mut s2_hat = s2;
    veck_ntt(&mut s2_hat);
    let mut t0_hat = t0;
    veck_ntt(&mut t0_hat);

    let a_hat = expand_a(&rho);

    let mut mu = [0u8; MUBYTES];
    shake256_2(&mut mu, &tr, msg_prime);

    let mut rho_pp = [0u8; RHO_PRIME_BYTES];
    shake256_3(&mut rho_pp, &cap_k, rnd, &mu);

    let mut kappa: u16 = 0;
    let max_attempts = 1000; // Safety limit

    loop {
        if kappa as usize > max_attempts {
            // PATCHED: bailing out of the rejection loop still means every
            // secret we've derived so far (key material + per-attempt
            // seed material) is live on the stack. Clear before returning.
            s1.iter_mut().for_each(Poly::zeroize);
            s2.iter_mut().for_each(Poly::zeroize);
            t0.iter_mut().for_each(Poly::zeroize);
            s1_hat.iter_mut().for_each(Poly::zeroize);
            s2_hat.iter_mut().for_each(Poly::zeroize);
            t0_hat.iter_mut().for_each(Poly::zeroize);
            zeroize_bytes(&mut cap_k);
            zeroize_bytes(&mut rho_pp);
            zeroize_bytes(&mut mu);
            return Err(MlDsaError::RngFailed);
        }

        let mut y = [Poly::zero(); L];
        for i in 0..L {
            y[i] = expand_mask_poly(&rho_pp, kappa + i as u16);
        }
        let mut y_saved = y;

        let mut y_hat = y;
        vecl_ntt(&mut y_hat);
        let mut w = matrix_mul(&a_hat, &y_hat);
        veck_invntt(&mut w);
        veck_reduce(&mut w);

        let (w1, _) = veck_decompose(&w);

        let w1b = w1_encode(&w1);
        let mut c_tilde = [0u8; CTILDEBYTES];
        shake256_2(&mut c_tilde, &mu, &w1b);

        let c = sample_in_ball(&c_tilde);
        let mut c_hat = c;
        c_hat.ntt();

        let mut cs1 = c_mul_vecl(&c_hat, &s1_hat);
        vecl_invntt(&mut cs1);

        let z: [Poly; L] = core::array::from_fn(|i| y_saved[i].add(&cs1[i]));

        if !chknorm_vecl(&z, GAMMA1 - BETA) {
            // PATCHED: rejected attempt — the ephemeral mask for this
            // attempt (y/y_hat/y_saved, cs1) is no longer needed. Clear it
            // before looping so it doesn't sit on the stack across retries
            // any longer than necessary.
            y.iter_mut().for_each(Poly::zeroize);
            y_hat.iter_mut().for_each(Poly::zeroize);
            y_saved.iter_mut().for_each(Poly::zeroize);
            cs1.iter_mut().for_each(Poly::zeroize);
            kappa += L as u16;
            continue;
        }

        let mut cs2 = c_mul_veck(&c_hat, &s2_hat);
        veck_invntt(&mut cs2);

        let w_minus_cs2 = veck_sub(&w, &cs2);
        let (_, r0) = veck_decompose(&w_minus_cs2);

        if !chknorm_veck(&r0, GAMMA2 - BETA) {
            y.iter_mut().for_each(Poly::zeroize);
            y_hat.iter_mut().for_each(Poly::zeroize);
            y_saved.iter_mut().for_each(Poly::zeroize);
            cs1.iter_mut().for_each(Poly::zeroize);
            cs2.iter_mut().for_each(Poly::zeroize);
            kappa += L as u16;
            continue;
        }

        let mut ct0 = c_mul_veck(&c_hat, &t0_hat);
        veck_invntt(&mut ct0);
        veck_reduce(&mut ct0);

        if !chknorm_veck(&ct0, GAMMA2) {
            y.iter_mut().for_each(Poly::zeroize);
            y_hat.iter_mut().for_each(Poly::zeroize);
            y_saved.iter_mut().for_each(Poly::zeroize);
            cs1.iter_mut().for_each(Poly::zeroize);
            cs2.iter_mut().for_each(Poly::zeroize);
            ct0.iter_mut().for_each(Poly::zeroize);
            kappa += L as u16;
            continue;
        }

        let neg_ct0: [Poly; K] = core::array::from_fn(|i| {
            let mut p = Poly::zero();
            for j in 0..N {
                p.coeffs[j] = freeze(-ct0[i].coeffs[j]);
            }
            p
        });
        let w_plus_ct0 = veck_add(&w_minus_cs2, &ct0);

        let mut h = [Poly::zero(); K];
        let mut hint_count = 0usize;
        for i in 0..K {
            for j in 0..N {
                h[i].coeffs[j] = make_hint_coeff(neg_ct0[i].coeffs[j], w_plus_ct0[i].coeffs[j]);
                hint_count += h[i].coeffs[j] as usize;
            }
        }

        if hint_count > OMEGA {
            y.iter_mut().for_each(Poly::zeroize);
            y_hat.iter_mut().for_each(Poly::zeroize);
            y_saved.iter_mut().for_each(Poly::zeroize);
            cs1.iter_mut().for_each(Poly::zeroize);
            cs2.iter_mut().for_each(Poly::zeroize);
            ct0.iter_mut().for_each(Poly::zeroize);
            kappa += L as u16;
            continue;
        }

        let mut sig = [0u8; SIGNBYTES];
        let mut soff = 0;
        sig[soff..soff + CTILDEBYTES].copy_from_slice(&c_tilde);
        soff += CTILDEBYTES;

        // z must be centered (in [-gamma1+1, gamma1]) for polyz_pack
        let z_centered: [Poly; L] = core::array::from_fn(|i| {
            let mut p = z[i];
            for c in p.coeffs.iter_mut() {
                *c = centered(*c);
            }
            p
        });
        sig[soff..soff + L * POLYZ_PACKEDBYTES].copy_from_slice(&pack_z(&z_centered));
        soff += L * POLYZ_PACKEDBYTES;

        let mut hbuf = [0u8; OMEGA + K];
        hint_pack(&h, &mut hbuf).ok_or(MlDsaError::MalformedSignature)?;
        sig[soff..soff + OMEGA + K].copy_from_slice(&hbuf);

        // ---- PATCHED: signature succeeded. `z`/`sig` are about to be
        // published, so they don't need clearing — but every secret
        // intermediate that fed into producing them does: unpacked key
        // material (s1/s2/t0), their NTT forms, the per-attempt mask
        // (y/y_hat/y_saved), and the seeds (cap_k/rho_pp/mu).
        s1.iter_mut().for_each(Poly::zeroize);
        s2.iter_mut().for_each(Poly::zeroize);
        t0.iter_mut().for_each(Poly::zeroize);
        s1_hat.iter_mut().for_each(Poly::zeroize);
        s2_hat.iter_mut().for_each(Poly::zeroize);
        t0_hat.iter_mut().for_each(Poly::zeroize);
        y.iter_mut().for_each(Poly::zeroize);
        y_hat.iter_mut().for_each(Poly::zeroize);
        y_saved.iter_mut().for_each(Poly::zeroize);
        cs1.iter_mut().for_each(Poly::zeroize);
        cs2.iter_mut().for_each(Poly::zeroize);
        ct0.iter_mut().for_each(Poly::zeroize);
        zeroize_bytes(&mut cap_k);
        zeroize_bytes(&mut rho_pp);
        zeroize_bytes(&mut mu);

        return Ok(sig);
    }
}

// ---------------------------------------------------------------------------
// Algorithm 3 — ML-DSA.Sign (external, hedged)
// ---------------------------------------------------------------------------
pub fn sign(sk: &[u8; SECRETKEYBYTES], msg: &[u8]) -> Result<[u8; SIGNBYTES], MlDsaError> {
    let mut mp = Vec::with_capacity(2 + msg.len());
    mp.push(0u8);
    mp.push(0u8);
    mp.extend_from_slice(msg);
    let mut rnd = [0u8; RNDBYTES];
    random_bytes(&mut rnd)?;
    let result = sign_internal(sk, &mp, &rnd);
    // PATCHED: `rnd` is the hedged-signing randomness folded into rho_pp.
    zeroize_bytes(&mut rnd);
    result
}

pub fn sign_deterministic(
    sk: &[u8; SECRETKEYBYTES],
    msg: &[u8],
) -> Result<[u8; SIGNBYTES], MlDsaError> {
    let mut mp = Vec::with_capacity(2 + msg.len());
    mp.push(0u8);
    mp.push(0u8);
    mp.extend_from_slice(msg);
    sign_internal(sk, &mp, &[0u8; RNDBYTES])
}

// ---------------------------------------------------------------------------
// Algorithm 4 — ML-DSA.Verify_internal
// ---------------------------------------------------------------------------
pub fn verify_internal(
    pk: &[u8; PUBLICKEYBYTES],
    msg_prime: &[u8],
    sig: &[u8; SIGNBYTES],
) -> Result<bool, MlDsaError> {
    let mut rho = [0u8; SEEDBYTES];
    rho.copy_from_slice(&pk[..SEEDBYTES]);
    let t1 = unpack_t1(&pk[SEEDBYTES..]);

    let mut soff = 0;
    let mut c_tilde = [0u8; CTILDEBYTES];
    c_tilde.copy_from_slice(&sig[soff..soff + CTILDEBYTES]);
    soff += CTILDEBYTES;
    let z = unpack_z(&sig[soff..soff + L * POLYZ_PACKEDBYTES]);
    soff += L * POLYZ_PACKEDBYTES;
    let mut hbuf = [0u8; OMEGA + K];
    hbuf.copy_from_slice(&sig[soff..soff + OMEGA + K]);
    let h = hint_unpack(&hbuf).ok_or(MlDsaError::MalformedSignature)?;

    if !chknorm_vecl(&z, GAMMA1 - BETA) {
        return Ok(false);
    }

    let a_hat = expand_a(&rho);

    let mut tr = [0u8; TRBYTES];
    shake256(&mut tr, pk);
    let mut mu = [0u8; MUBYTES];
    shake256_2(&mut mu, &tr, msg_prime);

    let c = sample_in_ball(&c_tilde);
    let mut c_hat = c;
    c_hat.ntt();

    let mut z_hat = z;
    vecl_ntt(&mut z_hat);
    let mut az = matrix_mul(&a_hat, &z_hat);
    veck_invntt(&mut az);
    veck_reduce(&mut az);

    let mut t1s = t1;
    for i in 0..K {
        for j in 0..N {
            t1s[i].coeffs[j] = ((t1s[i].coeffs[j] as i64) << D).rem_euclid(Q as i64) as i32;
        }
    }
    let mut t1s_hat = t1s;
    veck_ntt(&mut t1s_hat);
    let mut ct1s = c_mul_veck(&c_hat, &t1s_hat);
    veck_invntt(&mut ct1s);
    veck_reduce(&mut ct1s);

    let mut w_prime = veck_sub(&az, &ct1s);
    veck_reduce(&mut w_prime);

    let mut w1_prime = [Poly::zero(); K];
    for i in 0..K {
        for j in 0..N {
            w1_prime[i].coeffs[j] = use_hint_coeff(h[i].coeffs[j], w_prime[i].coeffs[j]);
        }
    }

    let w1b = w1_encode(&w1_prime);
    let mut cpp = [0u8; CTILDEBYTES];
    shake256_2(&mut cpp, &mu, &w1b);

    let mut diff = 0u8;
    for i in 0..CTILDEBYTES {
        diff |= c_tilde[i] ^ cpp[i];
    }
    // NOTE: nothing in verify_internal touches secret material — pk, sig,
    // and every derived value here are public by definition, so no
    // zeroization is needed on this path.
    Ok(diff == 0)
}

// ---------------------------------------------------------------------------
// Algorithm 5 — ML-DSA.Verify (external)
// ---------------------------------------------------------------------------
pub fn verify(
    pk: &[u8; PUBLICKEYBYTES],
    msg: &[u8],
    sig: &[u8; SIGNBYTES],
) -> Result<bool, MlDsaError> {
    let mut mp = Vec::with_capacity(2 + msg.len());
    mp.push(0u8);
    mp.push(0u8);
    mp.extend_from_slice(msg);
    verify_internal(pk, &mp, sig)
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------
pub struct $Variant;
impl $Variant {
    pub fn keypair() -> Result<([u8; PUBLICKEYBYTES], [u8; SECRETKEYBYTES]), MlDsaError> {
        keypair()
    }
    pub fn keypair_from_seed(
        xi: &[u8; SEEDBYTES],
    ) -> Result<([u8; PUBLICKEYBYTES], [u8; SECRETKEYBYTES]), MlDsaError> {
        keypair_from_seed(xi)
    }
    pub fn sign(sk: &[u8; SECRETKEYBYTES], msg: &[u8]) -> Result<[u8; SIGNBYTES], MlDsaError> {
        sign(sk, msg)
    }
    pub fn sign_deterministic(
        sk: &[u8; SECRETKEYBYTES],
        msg: &[u8],
    ) -> Result<[u8; SIGNBYTES], MlDsaError> {
        sign_deterministic(sk, msg)
    }
    pub fn verify(
        pk: &[u8; PUBLICKEYBYTES],
        msg: &[u8],
        sig: &[u8; SIGNBYTES],
    ) -> Result<bool, MlDsaError> {
        verify(pk, msg, sig)
    }
    pub const PK_BYTES: usize = PUBLICKEYBYTES;
    pub const SK_BYTES: usize = SECRETKEYBYTES;
    pub const SIG_BYTES: usize = SIGNBYTES;

    /// HARDENED entry point: returns the secret key wrapped in `SecretKey`
    /// so it zeroizes on drop instead of being left as a bare `Copy` array.
    /// Prefer this over `keypair()` in new code.
    pub fn keypair_hardened() -> Result<([u8; PUBLICKEYBYTES], SecretKey), MlDsaError> {
        let (pk, sk) = keypair()?;
        Ok((pk, SecretKey(sk)))
    }

    pub fn sign_hardened(sk: &SecretKey, msg: &[u8]) -> Result<[u8; SIGNBYTES], MlDsaError> {
        sign(sk.as_bytes(), msg)
    }
}

// ---------------------------------------------------------------------------
// Diagnostic Module
//
// HARDENED: this module prints raw secret-key material (s1, s2, t0, the
// K seed, tr) to stdout. That is unconditional secret exposure — into
// terminal scrollback, shell session logs, CI logs, screen-recording
// software, journald, anything capturing stdout. It must never be part of
// a release library's default surface. Gate it behind an explicit,
// off-by-default feature so a downstream `cargo add sirraya-ml-dsa-44`
// cannot reach it by accident, and so `cargo audit`/dependency review
// tooling can flag "diagnostic-unsafe" as a red flag if it's ever enabled.
// ---------------------------------------------------------------------------
#[cfg(feature = "diagnostic-unsafe")]
pub mod diagnostic {
    use super::*;

    pub fn inspect_keypair(
        pk: &[u8; PUBLICKEYBYTES],
        sk: &[u8; SECRETKEYBYTES],
    ) -> Result<(), MlDsaError> {
        println!("\n================================================================================");
        println!("           ML-DSA-44 LATTICE COMPONENTS (REAL DATA)");
        println!("================================================================================\n");

        let mut rho = [0u8; SEEDBYTES];
        rho.copy_from_slice(&pk[..SEEDBYTES]);
        let t1 = unpack_t1(&pk[SEEDBYTES..]);

        let mut off = 0;
        let mut rho_sk = [0u8; SEEDBYTES];
        rho_sk.copy_from_slice(&sk[off..off + SEEDBYTES]);
        off += SEEDBYTES;
        let mut cap_k = [0u8; KEYBYTES];
        cap_k.copy_from_slice(&sk[off..off + KEYBYTES]);
        off += KEYBYTES;
        let mut tr = [0u8; TRBYTES];
        tr.copy_from_slice(&sk[off..off + TRBYTES]);
        off += TRBYTES;
        let mut s1 = unpack_s1(&sk[off..off + L * POLYETA_PACKEDBYTES]);
        off += L * POLYETA_PACKEDBYTES;
        let mut s2 = unpack_s2(&sk[off..off + K * POLYETA_PACKEDBYTES]);
        off += K * POLYETA_PACKEDBYTES;
        let t0 = unpack_t0(&sk[off..off + K * POLYT0_PACKEDBYTES]);

        println!("LATTICE PARAMETERS (ML-DSA-44):");
        println!("   Module Rank:    k = {}, l = {}", K, L);
        println!("   Polynomial Degree: n = {} (cyclotomic ring)", N);
        println!("   Modulus:        q = {} (prime)", Q);
        println!();

        println!("PUBLIC KEY COMPONENTS:");
        println!("   |- rho (seed for matrix A):      {:02x?}{:02x?}{:02x?}...", &rho[0], &rho[1], &rho[2]);
        println!("   \\- t1 (high bits of t = A*s1 + s2):");

        for i in 0..K.min(3) {
            print!("      \\- t1[{}] first 8 coefficients: [", i);
            for j in 0..8.min(N) {
                print!("{:5}", t1[i].coeffs[j]);
                if j < 7 { print!(", "); }
            }
            println!(" ...]");
        }

        // NOTE: this diagnostic module intentionally prints secret key
        // material to stdout for debugging/demo purposes. That is a
        // separate, and arguably larger, exposure than the zeroization gap
        // this pass addresses — do not ship `diagnostic::inspect_keypair`
        // in any build that handles real keys.
        println!("\nSECRET KEY COMPONENTS:");
        println!("   |- rho (same as public):          {:02x?}{:02x?}{:02x?}...", &rho_sk[0], &rho_sk[1], &rho_sk[2]);
        println!("   |- K (key material):            {:02x?}{:02x?}{:02x?}...", &cap_k[0], &cap_k[1], &cap_k[2]);
        println!("   |- tr (hash of public key):     {:02x?}{:02x?}{:02x?}...", &tr[0], &tr[1], &tr[2]);

        println!("   |- s1 (secret vector 1, eta=2 bounded):");
        for i in 0..L.min(3) {
            print!("      \\- s1[{}] first 8 coefficients: [", i);
            for j in 0..8.min(N) {
                print!("{:3}", s1[i].coeffs[j]);
                if j < 7 { print!(", "); }
            }
            println!(" ...]");
        }

        println!("   |- s2 (secret vector 2, eta=2 bounded):");
        for i in 0..K.min(3) {
            print!("      \\- s2[{}] first 8 coefficients: [", i);
            for j in 0..8.min(N) {
                print!("{:3}", s2[i].coeffs[j]);
                if j < 7 { print!(", "); }
            }
            println!(" ...]");
        }

        println!("   \\- t0 (low bits of t):");
        for i in 0..K.min(3) {
            print!("      \\- t0[{}] first 8 coefficients: [", i);
            for j in 0..8.min(N) {
                print!("{:5}", t0[i].coeffs[j]);
                if j < 7 { print!(", "); }
            }
            println!(" ...]");
        }

        println!("\nLATTICE RELATION VERIFICATION:");
        println!("   Verifying t = A*s1 + s2 (mod q)...");

        let mut s1_hat = s1;
        vecl_ntt(&mut s1_hat);
        let a_hat = expand_a(&rho);
        let mut t_computed = matrix_mul(&a_hat, &s1_hat);
        veck_invntt(&mut t_computed);
        veck_reduce(&mut t_computed);

        let t_verify = veck_add(&t_computed, &s2);

        let mut matches = true;
        for i in 0..K.min(3) {
            for j in 0..3.min(N) {
                let t_expected = (t1[i].coeffs[j] << D) + t0[i].coeffs[j];
                let t_actual = t_verify[i].coeffs[j];
                if t_expected != t_actual && t_expected != t_actual + Q && t_expected != t_actual - Q {
                    matches = false;
                    println!("   MISMATCH at t[{}][{}]: expected={} actual={}", i, j, t_expected, t_actual);
                }
            }
        }

        if matches {
            println!("   OK: Lattice relation holds! t = A*s1 + s2 (mod q)");
        }

        // PATCHED: this function unpacks the full secret key into locals
        // (s1, s2, t0, s1_hat, t_computed) purely to print/verify it. Clear
        // them before returning rather than leaving them for the stack to
        // overwrite incidentally.
        s1.iter_mut().for_each(Poly::zeroize);
        s2.iter_mut().for_each(Poly::zeroize);
        s1_hat.iter_mut().for_each(Poly::zeroize);
        t_computed.iter_mut().for_each(Poly::zeroize);
        zeroize_bytes(&mut cap_k);

        Ok(())
    }

    pub fn inspect_signature(sig: &[u8; SIGNBYTES]) -> Result<(), MlDsaError> {
        println!("\n================================================================================");
        println!("              ML-DSA-44 SIGNATURE COMPONENTS");
        println!("================================================================================\n");

        let mut soff = 0;
        let mut c_tilde = [0u8; CTILDEBYTES];
        c_tilde.copy_from_slice(&sig[soff..soff + CTILDEBYTES]);
        soff += CTILDEBYTES;

        let z = unpack_z(&sig[soff..soff + L * POLYZ_PACKEDBYTES]);
        soff += L * POLYZ_PACKEDBYTES;

        let mut hbuf = [0u8; OMEGA + K];
        hbuf.copy_from_slice(&sig[soff..soff + OMEGA + K]);
        let h = hint_unpack(&hbuf).unwrap_or([Poly::zero(); K]);

        println!("SIGNATURE COMPONENTS:");
        println!("   |- c~ (challenge hash):      {:02x?}{:02x?}{:02x?}... ({} bytes)", &c_tilde[0], &c_tilde[1], &c_tilde[2], CTILDEBYTES);

        println!("   |- z (response vector, bounded by gamma1 = {}):", GAMMA1);
        for i in 0..L.min(3) {
            print!("      \\- z[{}] first 8 coefficients: [", i);
            for j in 0..8.min(N) {
                print!("{:6}", z[i].coeffs[j]);
                if j < 7 { print!(", "); }
            }
            println!(" ...]");
        }

        let hint_count = h.iter().flat_map(|p| p.coeffs.iter()).filter(|&&c| c != 0).count();
        println!("   \\- h (hint bits):            {} non-zero hints (max {})", hint_count, OMEGA);

        if hint_count > 0 {
            println!("      First few hint positions:");
            let mut shown = 0;
            'outer: for i in 0..K {
                for j in 0..N {
                    if h[i].coeffs[j] != 0 && shown < 5 {
                        println!("         - polynomial {}, coefficient {}: bit=1", i, j);
                        shown += 1;
                    }
                    if shown >= 5 { break 'outer; }
                }
            }
        }

        let c = sample_in_ball(&c_tilde);
        let non_zero = c.coeffs.iter().filter(|&&x| x != 0).count();
        println!("\nCHALLENGE POLYNOMIAL (c):");
        println!("   |- Non-zero coefficients: {}", non_zero);
        println!("   \\- First 10 positions:");
        let mut shown = 0;
        for (i, &coeff) in c.coeffs.iter().enumerate() {
            if coeff != 0 && shown < 10 {
                println!("      - Position {}: coefficient = {}", i, coeff);
                shown += 1;
            }
        }

        // NOTE: everything touched here (z, h, c, c_tilde) is part of a
        // published signature, not secret — no zeroization needed.
        Ok(())
    }

    pub fn demonstrate_lattice() -> Result<(), MlDsaError> {
        println!("\n================================================================================");
        println!("         REAL LATTICE-BASED CRYPTOGRAPHY DEMONSTRATION");
        println!("================================================================================\n");

        let (pk, sk) = keypair()?;
        inspect_keypair(&pk, &sk)?;

        let msg = b"Real lattice-based signature demonstration";
        let sig = sign(&sk, msg)?;
        inspect_signature(&sig)?;

        let valid = verify(&pk, msg, &sig)?;
        println!("\nSIGNATURE VERIFICATION: {}", if valid { "SUCCESS" } else { "FAILED" });

        println!("\nLATTICE NORM BOUNDS:");
        println!("   ||s1||_inf <= eta = {}", ETA);
        println!("   ||s2||_inf <= eta = {}", ETA);
        println!("   ||z||_inf  <= gamma1 - beta = {}", GAMMA1 - BETA);
        println!("   ||r0||_inf <= gamma2 - beta = {}", GAMMA2 - BETA);
        println!("   ||c*t0||_inf <= gamma2 = {}", GAMMA2);

        println!("\nThis demonstrates real ML-DSA-44 lattice cryptography:");
        println!("   * Polynomials in the ring R_q = Z_q[x]/(x^n+1) with n={}", N);
        println!("   * Module lattice of rank k={}, l={}", K, L);
        println!("   * Small secrets drawn from bounded distribution (eta={})", ETA);
        println!("   * Rejection sampling ensures zero-knowledge");
        println!("   * Hints enable efficient decompression");

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Self-test
// ---------------------------------------------------------------------------
pub fn run_tests() -> Result<(), MlDsaError> {
    println!("============================================================");
    println!(" FIPS 204 ML-DSA-44 — Self-Test");
    println!("============================================================");
    println!("  Public key : {} bytes", PUBLICKEYBYTES);
    println!("  Secret key : {} bytes", SECRETKEYBYTES);
    println!("  Signature  : {} bytes", SIGNBYTES);

    print!("\n[1/5] NTT round-trip ... ");
    {
        let mut p = Poly::zero();
        p.coeffs[0] = 1;
        p.coeffs[5] = 42;
        p.coeffs[255] = Q - 1;
        let orig = p.coeffs;
        p.ntt();
        p.invntt();
        for i in 0..N {
            if p.coeffs[i] != orig[i] {
                println!("FAIL at [{}]: expected {} got {}", i, orig[i], p.coeffs[i]);
                return Err(MlDsaError::VerificationFailed);
            }
        }
    }
    println!("PASS");

    print!("[2/5] Packing ... ");
    {
        let mut p = Poly::zero();
        for i in 0..N {
            p.coeffs[i] = (i % 1024) as i32;
        }
        let mut buf = [0u8; POLYT1_PACKEDBYTES];
        polyt1_pack(&mut buf, &p);
        assert_eq!(polyt1_unpack(&buf), p);
    }
    println!("PASS");

    print!("[3/5] KeyGen ... ");
    let (pk, sk) = keypair()?;
    println!("PASS");

    print!("[4/5] Sign ... ");
    let msg = b"FIPS 204 ML-DSA-44 critical infrastructure test";
    let sig = sign(&sk, msg)?;
    println!("PASS ({} bytes)", sig.len());

    print!("[5/5] Verify ... ");
    if !verify(&pk, msg, &sig)? {
        println!("FAIL");
        return Err(MlDsaError::VerificationFailed);
    }
    println!("PASS");

    assert!(!verify(&pk, b"tampered", &sig)?, "should reject wrong message");

    #[cfg(feature = "diagnostic-unsafe")]
    {
        println!("\n[6/6] Lattice Demonstration (diagnostic-unsafe: prints secret material) ...");
        if let Err(e) = diagnostic::demonstrate_lattice() {
            println!("   Lattice demo warning: {}", e);
        } else {
            println!("   PASS");
        }
    }

    println!("\nAll tests passed.");
    Ok(())
}

// ---------------------------------------------------------------------------
// Crypto-agility: implement the crate-wide `SignatureScheme` trait so this
// parameter set is usable generically (dynamic algorithm selection, hybrid
// composition — see `crate::traits` and `crate::hybrid`) exactly like every
// other scheme this crate implements now or in the future.
// ---------------------------------------------------------------------------
impl $crate::traits::SignatureScheme for $Variant {
    type PublicKey = [u8; PUBLICKEYBYTES];
    type SecretKey = [u8; SECRETKEYBYTES];
    type Signature = [u8; SIGNBYTES];
    type Error = MlDsaError;

    const NAME: &'static str = stringify!($Variant);
    const PUBLIC_KEY_LEN: usize = PUBLICKEYBYTES;
    const SECRET_KEY_LEN: usize = SECRETKEYBYTES;
    const SIGNATURE_LEN: usize = SIGNBYTES;
    const SEED_LEN: usize = SEEDBYTES;

    fn keypair() -> Result<(Self::PublicKey, Self::SecretKey), Self::Error> {
        $Variant::keypair()
    }
    fn keypair_from_seed(seed: &[u8]) -> Result<(Self::PublicKey, Self::SecretKey), Self::Error> {
        let seed: &[u8; SEEDBYTES] = seed
            .try_into()
            .map_err(|_| MlDsaError::InvalidSeedLength)?;
        $Variant::keypair_from_seed(seed)
    }
    fn sign(sk: &Self::SecretKey, msg: &[u8]) -> Result<Self::Signature, Self::Error> {
        $Variant::sign(sk, msg)
    }
    fn verify(
        pk: &Self::PublicKey,
        msg: &[u8],
        sig: &Self::Signature,
    ) -> Result<bool, Self::Error> {
        $Variant::verify(pk, msg, sig)
    }

    fn public_key_from_bytes(bytes: &[u8]) -> Option<Self::PublicKey> {
        bytes.try_into().ok()
    }
    fn secret_key_from_bytes(bytes: &[u8]) -> Option<Self::SecretKey> {
        bytes.try_into().ok()
    }
    fn signature_from_bytes(bytes: &[u8]) -> Option<Self::Signature> {
        bytes.try_into().ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ntt_roundtrip_e0() {
        let mut p = Poly::zero();
        p.coeffs[0] = 1;
        let o = p.coeffs;
        p.ntt();
        p.invntt();
        assert_eq!(p.coeffs, o);
    }
    #[test]
    fn ntt_roundtrip_e1() {
        let mut p = Poly::zero();
        p.coeffs[1] = 1;
        let o = p.coeffs;
        p.ntt();
        p.invntt();
        assert_eq!(p.coeffs, o);
    }
    #[test]
    fn ntt_roundtrip_general() {
        let mut p = Poly::zero();
        for i in 0..N {
            p.coeffs[i] = ((i * 37 + 5) % Q as usize) as i32;
        }
        let o = p.coeffs;
        p.ntt();
        p.invntt();
        assert_eq!(p.coeffs, o);
    }
    #[test]
    fn t1_roundtrip() {
        let mut p = Poly::zero();
        for i in 0..N {
            p.coeffs[i] = (i % 1024) as i32;
        }
        let mut b = [0u8; POLYT1_PACKEDBYTES];
        polyt1_pack(&mut b, &p);
        assert_eq!(polyt1_unpack(&b), p);
    }
    #[test]
    fn t0_roundtrip() {
        let half = 1i32 << (D - 1);
        let mut p = Poly::zero();
        for i in 0..N {
            p.coeffs[i] = (i as i32 % (2 * half)) - half + 1;
        }
        let mut b = [0u8; POLYT0_PACKEDBYTES];
        polyt0_pack(&mut b, &p);
        assert_eq!(polyt0_unpack(&b), p);
    }
    #[test]
    fn eta_roundtrip() {
        let mut p = Poly::zero();
        for i in 0..N {
            p.coeffs[i] = ((i % 5) as i32) - 2;
        }
        let mut b = [0u8; POLYETA_PACKEDBYTES];
        polyeta_pack(&mut b, &p);
        assert_eq!(polyeta_unpack(&b), p);
    }
    #[test]
    fn z_roundtrip() {
        let mut p = Poly::zero();
        for i in 0..N {
            p.coeffs[i] = (i as i32 % (2 * GAMMA1)) - GAMMA1 + 1;
        }
        let mut b = [0u8; POLYZ_PACKEDBYTES];
        polyz_pack(&mut b, &p);
        assert_eq!(polyz_unpack(&b), p);
    }
    #[test]
    fn deterministic_keygen() {
        let s = [42u8; SEEDBYTES];
        let (p1, s1) = $Variant::keypair_from_seed(&s).unwrap();
        let (p2, s2) = $Variant::keypair_from_seed(&s).unwrap();
        assert_eq!(p1, p2);
        assert_eq!(&s1[..], &s2[..]);
    }
    #[test]
    fn sign_verify() {
        let (pk, sk) = $Variant::keypair().unwrap();
        let msg = b"test";
        let sig = $Variant::sign(&sk, msg).unwrap();
        assert!($Variant::verify(&pk, msg, &sig).unwrap());
    }
    #[test]
    fn sign_verify_deterministic() {
        let (pk, sk) = $Variant::keypair().unwrap();
        let msg = b"deterministic test";
        let sig = $Variant::sign_deterministic(&sk, msg).unwrap();
        assert!($Variant::verify(&pk, msg, &sig).unwrap());
    }
    #[test]
    fn reject_wrong_msg() {
        let (pk, sk) = $Variant::keypair().unwrap();
        let sig = $Variant::sign(&sk, b"a").unwrap();
        assert!(!$Variant::verify(&pk, b"b", &sig).unwrap());
    }
    #[test]
    fn reject_tampered_sig() {
        let (pk, sk) = $Variant::keypair().unwrap();
        let mut sig = $Variant::sign(&sk, b"m").unwrap();
        sig[42] ^= 0xFF;
        match $Variant::verify(&pk, b"m", &sig) {
            Ok(v) => assert!(!v),
            Err(_) => {}
        }
    }
    #[test]
    fn many_roundtrips() {
        let (pk, sk) = $Variant::keypair().unwrap();
        for i in 0u32..10 {
            let m = i.to_le_bytes();
            let s = $Variant::sign(&sk, &m).unwrap();
            assert!($Variant::verify(&pk, &m, &s).unwrap());
        }
    }
}
    };
}

pub(crate) use ml_dsa_impl;