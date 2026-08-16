//! FIPS 205 §7 — the SLH-DSA hypertree: a tree of `d` XMSS trees, each of
//! height `h' = h/d`.

use super::adrs::Adrs;
use super::xmss::{xmss_pk_from_sig, xmss_sign};

/// Algorithm 12: ht_sign(M, SK.seed, PK.seed, idx_tree, idx_leaf).
#[allow(clippy::too_many_arguments)]
pub fn ht_sign(
    m: &[u8],
    sk_seed: &[u8],
    pk_seed: &[u8],
    idx_tree: u64,
    idx_leaf: u32,
    n: usize,
    len1: usize,
    len2: usize,
    hp: u32,
    d: u32,
) -> Vec<u8> {
    let mut adrs = Adrs::zero();
    adrs.set_tree_address(idx_tree);

    let sig_tmp = xmss_sign(m, sk_seed, idx_leaf, pk_seed, &mut adrs, n, len1, len2, hp);
    let mut sig_ht = sig_tmp.clone();
    let mut root = xmss_pk_from_sig(idx_leaf, &sig_tmp, m, pk_seed, &mut adrs, n, len1, len2, hp);

    let mut idx_tree_cur = idx_tree;
    for j in 1..d {
        let idx_leaf_cur = (idx_tree_cur & ((1u64 << hp) - 1)) as u32;
        idx_tree_cur >>= hp;
        adrs.set_layer_address(j);
        adrs.set_tree_address(idx_tree_cur);

        let sig_tmp = xmss_sign(&root, sk_seed, idx_leaf_cur, pk_seed, &mut adrs, n, len1, len2, hp);
        sig_ht.extend_from_slice(&sig_tmp);
        if j < d - 1 {
            root = xmss_pk_from_sig(idx_leaf_cur, &sig_tmp, &root, pk_seed, &mut adrs, n, len1, len2, hp);
        }
    }
    sig_ht
}

/// Algorithm 13: ht_verify(M, SIG_HT, PK.seed, idx_tree, idx_leaf, PK.root).
#[allow(clippy::too_many_arguments)]
pub fn ht_verify(
    m: &[u8],
    sig_ht: &[u8],
    pk_seed: &[u8],
    idx_tree: u64,
    idx_leaf: u32,
    pk_root: &[u8],
    n: usize,
    len1: usize,
    len2: usize,
    hp: u32,
    d: u32,
) -> bool {
    let mut adrs = Adrs::zero();
    adrs.set_tree_address(idx_tree);
    let xmss_sig_len = (len1 + len2) * n + hp as usize * n;
    if sig_ht.len() != xmss_sig_len * d as usize {
        return false;
    }

    let sig_tmp = &sig_ht[0..xmss_sig_len];
    let mut node = xmss_pk_from_sig(idx_leaf, sig_tmp, m, pk_seed, &mut adrs, n, len1, len2, hp);

    let mut idx_tree_cur = idx_tree;
    for j in 1..d {
        let idx_leaf_cur = (idx_tree_cur & ((1u64 << hp) - 1)) as u32;
        idx_tree_cur >>= hp;
        adrs.set_layer_address(j);
        adrs.set_tree_address(idx_tree_cur);

        let sig_tmp = &sig_ht[(j as usize) * xmss_sig_len..(j as usize + 1) * xmss_sig_len];
        node = xmss_pk_from_sig(idx_leaf_cur, sig_tmp, &node, pk_seed, &mut adrs, n, len1, len2, hp);
    }
    node == pk_root
}
