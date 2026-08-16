//! FIPS 205 §4.4 — array/byte-string/integer conversions that don't depend
//! on which hash function instantiation (§11.1 SHAKE vs §11.2 SHA2) is in
//! use, so they live outside `hash_suite`.

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

/// Algorithm 3: toByte(x, n) — integer to big-endian byte string of exactly
/// `n` bytes. Only used here for small counters (MGF1's 4-byte C, in
/// `sha2_suite`), so `u32` input is sufficient.
pub fn to_byte(x: u32, n: usize) -> Vec<u8> {
    let full = x.to_be_bytes(); // 4 bytes
    if n >= 4 {
        let mut out = vec![0u8; n - 4];
        out.extend_from_slice(&full);
        out
    } else {
        full[4 - n..4].to_vec()
    }
}
