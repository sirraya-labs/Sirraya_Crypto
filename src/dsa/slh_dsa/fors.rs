//! FIPS 205 §8 — Forest of Random Subsets (FORS), the few-time signature
//! scheme SLH-DSA uses to sign the actual message digest.
//!
//! Generic over `H: HashSuite` — see `wots` module docs.

use super::adrs::{Adrs, FORS_PRF, FORS_ROOTS};
use super::hash_suite::HashSuite;
use super::util::base_2b;

/// Algorithm 14: fors_skGen(SK.seed, PK.seed, ADRS, idx). `adrs` must have
/// type FORS_TREE and the correct key pair address set by the caller.
pub fn fors_sk_gen(sk_seed: &[u8], pk_seed: &[u8], adrs: &Adrs, idx: u32, h: &impl HashSuite) -> Vec<u8> {
    let mut sk_adrs = *adrs;
    sk_adrs.set_type_and_clear(FORS_PRF);
    sk_adrs.set_key_pair_address(adrs.get_key_pair_address());
    sk_adrs.set_tree_index(idx);
    h.prf(pk_seed, sk_seed, &sk_adrs)
}

/// Algorithm 15: fors_node(SK.seed, i, z, PK.seed, ADRS).
pub fn fors_node(sk_seed: &[u8], i: u32, z: u32, pk_seed: &[u8], adrs: &mut Adrs, h: &impl HashSuite) -> Vec<u8> {
    if z == 0 {
        let sk = fors_sk_gen(sk_seed, pk_seed, adrs, i, h);
        adrs.set_tree_height(0);
        adrs.set_tree_index(i);
        h.f_hash(pk_seed, adrs, &sk)
    } else {
        let lnode = fors_node(sk_seed, 2 * i, z - 1, pk_seed, adrs, h);
        let rnode = fors_node(sk_seed, 2 * i + 1, z - 1, pk_seed, adrs, h);
        adrs.set_tree_height(z);
        adrs.set_tree_index(i);
        let mut concat = lnode;
        concat.extend_from_slice(&rnode);
        h.h_hash(pk_seed, adrs, &concat)
    }
}

/// Algorithm 16: fors_sign(md, SK.seed, PK.seed, ADRS). `adrs` must have
/// type FORS_TREE and the correct key pair address set by the caller.
pub fn fors_sign(md: &[u8], sk_seed: &[u8], pk_seed: &[u8], adrs: &mut Adrs, h: &impl HashSuite, k: usize, a: usize) -> Vec<u8> {
    let n = h.n();
    let indices = base_2b(md, a, k);
    let mut sig = Vec::with_capacity(k * (1 + a) * n);
    for (i, &idx) in indices.iter().enumerate() {
        sig.extend_from_slice(&fors_sk_gen(sk_seed, pk_seed, adrs, (i as u32) * (1u32 << a) + idx, h));
        for j in 0..a {
            let s = (idx >> j) ^ 1;
            let node_idx = (i as u32) * (1u32 << (a - j)) + s;
            sig.extend_from_slice(&fors_node(sk_seed, node_idx, j as u32, pk_seed, adrs, h));
        }
    }
    sig
}

/// Algorithm 17: fors_pkFromSig(SIG_FORS, md, PK.seed, ADRS).
pub fn fors_pk_from_sig(
    sig_fors: &[u8],
    md: &[u8],
    pk_seed: &[u8],
    adrs: &mut Adrs,
    h: &impl HashSuite,
    k: usize,
    a: usize,
) -> Vec<u8> {
    let n = h.n();
    let indices = base_2b(md, a, k);
    let elem_len = (1 + a) * n;
    let mut roots = Vec::with_capacity(k * n);

    for (i, &idx) in indices.iter().enumerate() {
        let base = i * elem_len;
        let sk = &sig_fors[base..base + n];
        adrs.set_tree_height(0);
        adrs.set_tree_index((i as u32) * (1u32 << a) + idx);
        let mut node = h.f_hash(pk_seed, adrs, sk);

        let auth = &sig_fors[base + n..base + elem_len];
        for j in 0..a {
            adrs.set_tree_height((j + 1) as u32);
            let auth_j = &auth[j * n..(j + 1) * n];
            let combined = if (idx >> j) % 2 == 0 {
                let new_idx = adrs.get_tree_index() / 2;
                adrs.set_tree_index(new_idx);
                let mut c = node.clone();
                c.extend_from_slice(auth_j);
                c
            } else {
                let new_idx = (adrs.get_tree_index() - 1) / 2;
                adrs.set_tree_index(new_idx);
                let mut c = auth_j.to_vec();
                c.extend_from_slice(&node);
                c
            };
            node = h.h_hash(pk_seed, adrs, &combined);
        }
        roots.extend_from_slice(&node);
    }

    let mut forspk_adrs = *adrs;
    forspk_adrs.set_type_and_clear(FORS_ROOTS);
    forspk_adrs.set_key_pair_address(adrs.get_key_pair_address());
    h.t_l(pk_seed, &forspk_adrs, &roots)
}
