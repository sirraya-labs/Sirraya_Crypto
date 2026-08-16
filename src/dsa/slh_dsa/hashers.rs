//! FIPS 205 §11.1 — SLH-DSA using SHAKE. Every one of the six functions
//! from §4.1 is SHAKE256 of the concatenated inputs, truncated/extended to
//! the required output length; §11.1 gives the exact concatenation order
//! for each.

use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::Shake256;

fn shake256_xof(parts: &[&[u8]], out_len: usize) -> Vec<u8> {
    let mut hasher = Shake256::default();
    for p in parts {
        Update::update(&mut hasher, p);
    }
    let mut reader = hasher.finalize_xof();
    let mut out = vec![0u8; out_len];
    reader.read(&mut out);
    out
}

/// H_msg(R, PK.seed, PK.root, M) — §11.1, output length m bytes (8m bits).
pub fn h_msg(r: &[u8], pk_seed: &[u8], pk_root: &[u8], m: &[u8], out_len: usize) -> Vec<u8> {
    shake256_xof(&[r, pk_seed, pk_root, m], out_len)
}

/// PRF(PK.seed, SK.seed, ADRS) — §11.1, output length n bytes.
pub fn prf(pk_seed: &[u8], sk_seed: &[u8], adrs: &[u8], n: usize) -> Vec<u8> {
    shake256_xof(&[pk_seed, adrs, sk_seed], n)
}

/// PRF_msg(SK.prf, opt_rand, M) — §11.1, output length n bytes.
pub fn prf_msg(sk_prf: &[u8], opt_rand: &[u8], m: &[u8], n: usize) -> Vec<u8> {
    shake256_xof(&[sk_prf, opt_rand, m], n)
}

/// F(PK.seed, ADRS, M1) — §11.1, output length n bytes.
pub fn f_hash(pk_seed: &[u8], adrs: &[u8], m1: &[u8], n: usize) -> Vec<u8> {
    shake256_xof(&[pk_seed, adrs, m1], n)
}

/// H(PK.seed, ADRS, M2) — §11.1, output length n bytes.
pub fn h_hash(pk_seed: &[u8], adrs: &[u8], m2: &[u8], n: usize) -> Vec<u8> {
    shake256_xof(&[pk_seed, adrs, m2], n)
}

/// T_l(PK.seed, ADRS, M_l) — §11.1, output length n bytes.
pub fn t_l(pk_seed: &[u8], adrs: &[u8], ml: &[u8], n: usize) -> Vec<u8> {
    shake256_xof(&[pk_seed, adrs, ml], n)
}

/// Algorithm 4: base_2b(X, b, out_len). Splits `x` into `out_len` big-endian
/// `b`-bit integers. `b <= 32` for every use in this crate (b is lgw=4 for
/// WOTS+ or `a` <= 22 for FORS in Table 2), so `u32` accumulation is safe
/// (spec note: "a b+7-bit unsigned integer is sufficient").
pub fn base_2b(x: &[u8], b: usize, out_len: usize) -> Vec<u32> {
    let mut input_idx = 0usize;
    let mut bits = 0usize;
    let mut total: u64 = 0;
    let mut out = Vec::with_capacity(out_len);
    for _ in 0..out_len {
        while bits < b {
            total = (total << 8) | x[input_idx] as u64;
            input_idx += 1;
            bits += 8;
        }
        bits -= b;
        let val = (total >> bits) & ((1u64 << b) - 1);
        out.push(val as u32);
    }
    out
}

/// Algorithm 2: toInt(X, n) — big-endian bytes to integer, as u64 (every
/// use in this crate fits: idx_tree needs at most h-h' <= 64 bits, per
/// `adrs::Adrs::set_tree_address`'s doc comment).
pub fn to_int_u64(bytes: &[u8]) -> u64 {
    let mut total: u64 = 0;
    for &b in bytes {
        total = (total << 8) | b as u64;
    }
    total
}
