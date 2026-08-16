//! FIPS 205 §6 — eXtended Merkle Signature Scheme (XMSS), as used
//! internally by SLH-DSA (not the standalone stateful XMSS of RFC 8391 /
//! SP 800-208 — see the FIPS 205 footnote in §3).
//!
//! Generic over `H: HashSuite` — see `wots` module docs.

use super::adrs::{Adrs, TREE, WOTS_HASH};
use super::hash_suite::HashSuite;
use super::wots::{wots_pk_from_sig, wots_pk_gen, wots_sign};

/// Algorithm 9: xmss_node(SK.seed, i, z, PK.seed, ADRS). Recursively
/// computes the root of the height-`z` subtree rooted at index `i`.
/// `adrs` must have layer/tree address set to this XMSS tree; its type is
/// overwritten as the recursion descends.
pub fn xmss_node(sk_seed: &[u8], i: u32, z: u32, pk_seed: &[u8], adrs: &mut Adrs, h: &impl HashSuite, len: usize) -> Vec<u8> {
    if z == 0 {
        adrs.set_type_and_clear(WOTS_HASH);
        adrs.set_key_pair_address(i);
        wots_pk_gen(sk_seed, pk_seed, adrs, h, len)
    } else {
        let lnode = xmss_node(sk_seed, 2 * i, z - 1, pk_seed, adrs, h, len);
        let rnode = xmss_node(sk_seed, 2 * i + 1, z - 1, pk_seed, adrs, h, len);
        adrs.set_type_and_clear(TREE);
        adrs.set_tree_height(z);
        adrs.set_tree_index(i);
        let mut concat = lnode;
        concat.extend_from_slice(&rnode);
        h.h_hash(pk_seed, adrs, &concat)
    }
}

/// Algorithm 10: xmss_sign(M, SK.seed, idx, PK.seed, ADRS). Returns
/// WOTS+ signature || authentication path.
#[allow(clippy::too_many_arguments)]
pub fn xmss_sign(
    m: &[u8],
    sk_seed: &[u8],
    idx: u32,
    pk_seed: &[u8],
    adrs: &mut Adrs,
    h: &impl HashSuite,
    len1: usize,
    len2: usize,
    hp: u32,
) -> Vec<u8> {
    let len = len1 + len2;
    let n = h.n();
    let mut auth = Vec::with_capacity(hp as usize * n);
    for j in 0..hp {
        let k = (idx >> j) ^ 1;
        auth.extend_from_slice(&xmss_node(sk_seed, k, j, pk_seed, adrs, h, len));
    }
    adrs.set_type_and_clear(WOTS_HASH);
    adrs.set_key_pair_address(idx);
    let mut out = wots_sign(m, sk_seed, pk_seed, adrs, h, len1, len2);
    out.extend_from_slice(&auth);
    out
}

/// Algorithm 11: xmss_pkFromSig(idx, SIG_XMSS, M, PK.seed, ADRS). Computes
/// the candidate XMSS root from a signature and message.
#[allow(clippy::too_many_arguments)]
pub fn xmss_pk_from_sig(
    idx: u32,
    sig_xmss: &[u8],
    m: &[u8],
    pk_seed: &[u8],
    adrs: &mut Adrs,
    h: &impl HashSuite,
    len1: usize,
    len2: usize,
    hp: u32,
) -> Vec<u8> {
    let len = len1 + len2;
    let n = h.n();
    adrs.set_type_and_clear(WOTS_HASH);
    adrs.set_key_pair_address(idx);
    let wots_sig_len = len * n;
    let sig = &sig_xmss[0..wots_sig_len];
    let auth = &sig_xmss[wots_sig_len..wots_sig_len + hp as usize * n];

    let mut node = wots_pk_from_sig(sig, m, pk_seed, adrs, h, len1, len2);

    adrs.set_type_and_clear(TREE);
    adrs.set_tree_index(idx);
    for k in 0..hp {
        adrs.set_tree_height(k + 1);
        let auth_k = &auth[(k as usize) * n..(k as usize + 1) * n];
        let combined = if (idx >> k) % 2 == 0 {
            let new_idx = adrs.get_tree_index() / 2;
            adrs.set_tree_index(new_idx);
            let mut c = node.clone();
            c.extend_from_slice(auth_k);
            c
        } else {
            let new_idx = (adrs.get_tree_index() - 1) / 2;
            adrs.set_tree_index(new_idx);
            let mut c = auth_k.to_vec();
            c.extend_from_slice(&node);
            c
        };
        node = h.h_hash(pk_seed, adrs, &combined);
    }
    node
}
