//! FIPS 205 §5 — Winternitz One-Time Signature Plus (WOTS+).

use super::adrs::{Adrs, WOTS_PK, WOTS_PRF};
use super::hashers::{base_2b, f_hash, prf, t_l};

/// w = 2^lgw = 16 for every parameter set (lgw = 4 fixed, §5).
const W_MINUS_1: u32 = 15;
const LGW: usize = 4;

/// Algorithm 5: chain(X, i, s, PK.seed, ADRS). Iterates F `s` times on `X`
/// starting from chain position `i`.
pub fn chain(x: &[u8], i: u32, s: u32, pk_seed: &[u8], adrs: &mut Adrs, n: usize) -> Vec<u8> {
    let mut tmp = x.to_vec();
    for j in i..(i + s) {
        adrs.set_hash_address(j);
        tmp = f_hash(pk_seed, adrs.as_bytes(), &tmp, n);
    }
    tmp
}

/// Converts an n-byte message into `len` base-w digits: `len1` message
/// digits (Algorithm 4) followed by `len2` checksum digits — the shared
/// first half of both `wots_sign` (Algorithm 7, lines 1-7) and
/// `wots_pkFromSig` (Algorithm 8, lines 1-7).
fn wots_message_digits(m: &[u8], len1: usize, len2: usize) -> Vec<u32> {
    let mut msg = base_2b(m, LGW, len1);
    let mut csum: u32 = 0;
    for &v in &msg {
        csum += W_MINUS_1 - v;
    }
    let shift = (8 - ((len2 * LGW) % 8)) % 8;
    csum <<= shift;
    let csum_byte_len = (len2 * LGW + 7) / 8;
    let csum_bytes = csum.to_be_bytes(); // 4 bytes, big-endian
    let csum_be = &csum_bytes[4 - csum_byte_len..4];
    msg.extend_from_slice(&base_2b(csum_be, LGW, len2));
    msg
}

/// Algorithm 6: wots_pkGen(SK.seed, PK.seed, ADRS). `adrs` must already
/// have type WOTS_HASH and the correct key pair address set by the caller.
pub fn wots_pk_gen(
    sk_seed: &[u8],
    pk_seed: &[u8],
    adrs: &mut Adrs,
    n: usize,
    len: usize,
) -> Vec<u8> {
    let mut sk_adrs = *adrs;
    sk_adrs.set_type_and_clear(WOTS_PRF);
    sk_adrs.set_key_pair_address(adrs.get_key_pair_address());

    let mut tmp = Vec::with_capacity(len * n);
    for i in 0..len as u32 {
        sk_adrs.set_chain_address(i);
        let sk = prf(pk_seed, sk_seed, sk_adrs.as_bytes(), n);
        adrs.set_chain_address(i);
        tmp.extend_from_slice(&chain(&sk, 0, W_MINUS_1, pk_seed, adrs, n));
    }

    let mut wotspk_adrs = *adrs;
    wotspk_adrs.set_type_and_clear(WOTS_PK);
    wotspk_adrs.set_key_pair_address(adrs.get_key_pair_address());
    t_l(pk_seed, wotspk_adrs.as_bytes(), &tmp, n)
}

/// Algorithm 7: wots_sign(M, SK.seed, PK.seed, ADRS). `adrs` preconditions
/// as in `wots_pk_gen`.
pub fn wots_sign(
    m: &[u8],
    sk_seed: &[u8],
    pk_seed: &[u8],
    adrs: &mut Adrs,
    n: usize,
    len1: usize,
    len2: usize,
) -> Vec<u8> {
    let msg = wots_message_digits(m, len1, len2);
    let len = len1 + len2;

    let mut sk_adrs = *adrs;
    sk_adrs.set_type_and_clear(WOTS_PRF);
    sk_adrs.set_key_pair_address(adrs.get_key_pair_address());

    let mut sig = Vec::with_capacity(len * n);
    for i in 0..len as u32 {
        sk_adrs.set_chain_address(i);
        let sk = prf(pk_seed, sk_seed, sk_adrs.as_bytes(), n);
        adrs.set_chain_address(i);
        sig.extend_from_slice(&chain(&sk, 0, msg[i as usize], pk_seed, adrs, n));
    }
    sig
}

/// Algorithm 8: wots_pkFromSig(sig, M, PK.seed, ADRS). `adrs` preconditions
/// as in `wots_pk_gen`.
pub fn wots_pk_from_sig(
    sig: &[u8],
    m: &[u8],
    pk_seed: &[u8],
    adrs: &mut Adrs,
    n: usize,
    len1: usize,
    len2: usize,
) -> Vec<u8> {
    let msg = wots_message_digits(m, len1, len2);
    let len = len1 + len2;

    let mut tmp = Vec::with_capacity(len * n);
    for i in 0..len as u32 {
        adrs.set_chain_address(i);
        let sig_i = &sig[(i as usize) * n..(i as usize + 1) * n];
        let steps = W_MINUS_1 - msg[i as usize];
        tmp.extend_from_slice(&chain(sig_i, msg[i as usize], steps, pk_seed, adrs, n));
    }

    let mut wotspk_adrs = *adrs;
    wotspk_adrs.set_type_and_clear(WOTS_PK);
    wotspk_adrs.set_key_pair_address(adrs.get_key_pair_address());
    t_l(pk_seed, wotspk_adrs.as_bytes(), &tmp, n)
}
