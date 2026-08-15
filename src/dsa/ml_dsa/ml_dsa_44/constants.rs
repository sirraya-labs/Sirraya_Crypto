// constants.rs — FIPS 204 ML-DSA-44. Every value cited to spec page/algorithm.
// Based on FIPS 204 (August 13, 2024) - ML-DSA-44 parameter set
//
// N, Q, D and the NTT constants (QINV, MONT, ZETAS) are identical across
// every ML-DSA security level, so they live once in `common::ring` and are
// re-exported here rather than re-typed per parameter set — see that
// module's header comment. Everything below this point (K, L, ETA, TAU,
// GAMMA1, GAMMA2, OMEGA, LAMBDA and every size derived from them) genuinely
// differs per security level and belongs here.

pub use crate::common::ring::{N, Q, D, QINV, MONT, ZETAS};

// ML-DSA-44 specific parameters (Table 1)
pub const K: usize = 4; // Table 1 ML-DSA-44 (module rank)
pub const L: usize = 4; // Table 1 ML-DSA-44 (module rank)
pub const ETA: i32 = 2; // Table 1 ML-DSA-44 (bound for secrets)
pub const TAU: usize = 39; // Table 1 ML-DSA-44 (weight of challenge)
pub const BETA: i32 = 78; // Table 1: τ·η = 39 * 2
pub const GAMMA1: i32 = 1 << 17; // Table 1 ML-DSA-44 (2^17 = 131072)
pub const GAMMA2: i32 = (Q - 1) / 88; // Table 1 ML-DSA-44 = 95232
pub const OMEGA: usize = 80; // Table 1 ML-DSA-44 (max hint bits)
pub const LAMBDA: usize = 128; // Table 1 ML-DSA-44 (security level bits)

// Challenge hash size: λ/4 bytes (FIPS 204 §3.1)
pub const CTILDEBYTES: usize = LAMBDA / 4; // = 32 bytes for ML-DSA-44

// ML-DSA-44 key and signature sizes (Table 2)
pub const PUBLICKEYBYTES: usize = 1312; // Table 2: ρ(32) + t1(K×320=1280)
pub const SECRETKEYBYTES: usize = 2560; // Table 2: ρ(32)+K(32)+tr(64)+s1(384)+s2(384)+t0(1664)

pub const SIGNBYTES: usize = CTILDEBYTES + L * POLYZ_PACKEDBYTES + OMEGA + K; // = 2420

pub const SEEDBYTES: usize = 32; // Alg 6 line 1 (ρ)
pub const KEYBYTES: usize = 32; // Alg 6 line 1 (K)
pub const TRBYTES: usize = 64; // Alg 6 line 9 (tr = H(pk, 64))
pub const RNDBYTES: usize = 32; // Alg 2 line 5
pub const MUBYTES: usize = 64; // Alg 7 line 6
pub const RHO_PRIME_BYTES: usize = 64; // Alg 7 line 7

// Packing sizes - ML-DSA-44 specific
pub const POLYT1_PACKEDBYTES: usize = 320; // Alg 22: 256×10/8 (same for all)
pub const POLYT0_PACKEDBYTES: usize = 416; // Alg 24: 256×13/8 (same for all)
pub const POLYETA_PACKEDBYTES: usize = 96; // Alg 24: 256×3/8 (η=2 → 3 bits)
pub const POLYZ_PACKEDBYTES: usize = 576; // Alg 26: 256×18/8 (γ₁=2^17 → 18 bits)
pub const POLYW1_PACKEDBYTES: usize = 192; // Alg 28: 256×6/8 (γ₂=(q-1)/88 → 6 bits)


/// Size of t1 vector in bytes: K × POLYT1_PACKEDBYTES = 4 × 320 = 1280
pub const T1_BYTES: usize = K * POLYT1_PACKEDBYTES;

/// Size of t0 vector in bytes: K × POLYT0_PACKEDBYTES = 4 × 416 = 1664
pub const T0_BYTES: usize = K * POLYT0_PACKEDBYTES;

/// Size of s1 vector in bytes: L × POLYETA_PACKEDBYTES = 4 × 96 = 384
pub const S1_BYTES: usize = L * POLYETA_PACKEDBYTES;

/// Size of s2 vector in bytes: K × POLYETA_PACKEDBYTES = 4 × 96 = 384
pub const S2_BYTES: usize = K * POLYETA_PACKEDBYTES;

/// Size of z vector in bytes: L × POLYZ_PACKEDBYTES = 4 × 576 = 2304
pub const Z_BYTES: usize = L * POLYZ_PACKEDBYTES;

/// Size of packed hint vector: OMEGA + K = 80 + 4 = 84
pub const H_BYTES: usize = OMEGA + K;