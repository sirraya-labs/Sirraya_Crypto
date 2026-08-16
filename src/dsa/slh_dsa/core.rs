//! FIPS 205 §9 (internal functions) and §10 (external functions).
//!
//! Generic over `H: HashSuite` (see `hash_suite` module docs), so this
//! same code implements both the SHAKE (§11.1) and SHA2 (§11.2)
//! parameter sets — see `mod.rs` for where a concrete `ShakeSuite` or
//! `Sha2Suite` gets plugged in per variant.
//!
//! Covers Algorithms 18-22 and 24 (key generation, internal sign/verify,
//! external "pure" sign/verify). Algorithms 23/25 (pre-hash / HashSLH-DSA)
//! are in the sibling `prehash` module — this file builds `M'` for the
//! *pure* interface only (Algorithm 22/24's `toByte(0,1) || ...`).

use super::adrs::{Adrs, FORS_TREE};
use super::fors::{fors_pk_from_sig, fors_sign};
use super::hash_suite::HashSuite;
use super::ht::{ht_sign, ht_verify};
use super::params::{ceil_div, SlhDsaParams};
use super::util::to_int_u64;
use super::xmss::xmss_node;
use rand_core::{OsRng, RngCore};

/// SLH-DSA private key (Figure 15): SK.seed || SK.prf || PK.seed || PK.root.
#[derive(Clone)]
pub struct SlhDsaSecretKey {
    pub sk_seed: Vec<u8>,
    pub sk_prf: Vec<u8>,
    pub pk_seed: Vec<u8>,
    pub pk_root: Vec<u8>,
}

/// SLH-DSA public key (Figure 16): PK.seed || PK.root.
#[derive(Clone)]
pub struct SlhDsaPublicKey {
    pub pk_seed: Vec<u8>,
    pub pk_root: Vec<u8>,
}

impl SlhDsaSecretKey {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v = self.sk_seed.clone();
        v.extend_from_slice(&self.sk_prf);
        v.extend_from_slice(&self.pk_seed);
        v.extend_from_slice(&self.pk_root);
        v
    }
    pub fn from_bytes(b: &[u8], n: usize) -> Option<Self> {
        if b.len() != 4 * n {
            return None;
        }
        Some(SlhDsaSecretKey {
            sk_seed: b[0..n].to_vec(),
            sk_prf: b[n..2 * n].to_vec(),
            pk_seed: b[2 * n..3 * n].to_vec(),
            pk_root: b[3 * n..4 * n].to_vec(),
        })
    }
}

impl SlhDsaPublicKey {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v = self.pk_seed.clone();
        v.extend_from_slice(&self.pk_root);
        v
    }
    pub fn from_bytes(b: &[u8], n: usize) -> Option<Self> {
        if b.len() != 2 * n {
            return None;
        }
        Some(SlhDsaPublicKey {
            pk_seed: b[0..n].to_vec(),
            pk_root: b[n..2 * n].to_vec(),
        })
    }
}

#[derive(Debug)]
pub enum SlhDsaError {
    ContextTooLong,
    InvalidKeyLength,
    InvalidSignatureLength,
    RandomnessFailure,
}

impl core::fmt::Display for SlhDsaError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            SlhDsaError::ContextTooLong => write!(f, "context string exceeds 255 bytes"),
            SlhDsaError::InvalidKeyLength => write!(f, "key has wrong length for this parameter set"),
            SlhDsaError::InvalidSignatureLength => write!(f, "signature has wrong length for this parameter set"),
            SlhDsaError::RandomnessFailure => write!(f, "OS random number generator failed"),
        }
    }
}
impl std::error::Error for SlhDsaError {}

/// Algorithm 18: slh_keygen_internal(SK.seed, SK.prf, PK.seed).
pub fn slh_keygen_internal(
    sk_seed: &[u8],
    sk_prf: &[u8],
    pk_seed: &[u8],
    p: &SlhDsaParams,
    h: &impl HashSuite,
) -> (SlhDsaSecretKey, SlhDsaPublicKey) {
    let mut adrs = Adrs::zero();
    adrs.set_layer_address(p.d as u32 - 1);
    let pk_root = xmss_node(sk_seed, 0, p.hp() as u32, pk_seed, &mut adrs, h, p.wots_len());
    (
        SlhDsaSecretKey {
            sk_seed: sk_seed.to_vec(),
            sk_prf: sk_prf.to_vec(),
            pk_seed: pk_seed.to_vec(),
            pk_root: pk_root.clone(),
        },
        SlhDsaPublicKey { pk_seed: pk_seed.to_vec(), pk_root },
    )
}

/// Splits the FIPS 205 §9 message digest into (md, idx_tree, idx_leaf) per
/// the unnumbered equation before §9.1 and Algorithm 19 lines 6-10 /
/// Algorithm 20 lines 9-13.
fn split_digest<'a>(digest: &'a [u8], p: &SlhDsaParams) -> (&'a [u8], u64, u32) {
    let ka_bytes = ceil_div(p.k * p.a, 8);
    let hhp_bytes = ceil_div(p.h - p.hp(), 8);
    let hp_bytes = ceil_div(p.hp(), 8);

    let md = &digest[0..ka_bytes];
    let tmp_idx_tree = &digest[ka_bytes..ka_bytes + hhp_bytes];
    let tmp_idx_leaf = &digest[ka_bytes + hhp_bytes..ka_bytes + hhp_bytes + hp_bytes];

    let idx_tree = if p.h - p.hp() >= 64 {
        to_int_u64(tmp_idx_tree) // exactly 64 bits: mod 2^64 is a no-op
    } else {
        to_int_u64(tmp_idx_tree) % (1u64 << (p.h - p.hp()))
    };
    let idx_leaf = (to_int_u64(tmp_idx_leaf) % (1u64 << p.hp())) as u32;
    (md, idx_tree, idx_leaf)
}

/// Algorithm 19: slh_sign_internal(M, SK, addrnd). `addrnd = None` selects
/// the deterministic variant (opt_rand = PK.seed); `Some(r)` is the hedged
/// variant with `r` as the fresh n-byte randomness.
pub fn slh_sign_internal(m: &[u8], sk: &SlhDsaSecretKey, addrnd: Option<&[u8]>, p: &SlhDsaParams, h: &impl HashSuite) -> Vec<u8> {
    let opt_rand: &[u8] = addrnd.unwrap_or(&sk.pk_seed);
    let r = h.prf_msg(&sk.sk_prf, opt_rand, m);

    let mut sig = r.clone();
    let digest = h.h_msg(&r, &sk.pk_seed, &sk.pk_root, m, p.m());
    let (md, idx_tree, idx_leaf) = split_digest(&digest, p);

    let mut adrs = Adrs::zero();
    adrs.set_tree_address(idx_tree);
    adrs.set_type_and_clear(FORS_TREE);
    adrs.set_key_pair_address(idx_leaf);

    let sig_fors = fors_sign(md, &sk.sk_seed, &sk.pk_seed, &mut adrs, h, p.k, p.a);
    sig.extend_from_slice(&sig_fors);

    let pk_fors = fors_pk_from_sig(&sig_fors, md, &sk.pk_seed, &mut adrs, h, p.k, p.a);
    let sig_ht = ht_sign(
        &pk_fors, &sk.sk_seed, &sk.pk_seed, idx_tree, idx_leaf,
        h, p.n * 2, 3, p.hp() as u32, p.d as u32,
    );
    sig.extend_from_slice(&sig_ht);
    sig
}

/// Algorithm 20: slh_verify_internal(M, SIG, PK).
pub fn slh_verify_internal(m: &[u8], sig: &[u8], pk: &SlhDsaPublicKey, p: &SlhDsaParams, h: &impl HashSuite) -> bool {
    if sig.len() != p.sig_bytes() {
        return false;
    }
    let n = p.n;
    let r = &sig[0..n];
    let sig_fors_len = p.k * (1 + p.a) * n;
    let sig_fors = &sig[n..n + sig_fors_len];
    let sig_ht = &sig[n + sig_fors_len..];

    let digest = h.h_msg(r, &pk.pk_seed, &pk.pk_root, m, p.m());
    let (md, idx_tree, idx_leaf) = split_digest(&digest, p);

    let mut adrs = Adrs::zero();
    adrs.set_tree_address(idx_tree);
    adrs.set_type_and_clear(FORS_TREE);
    adrs.set_key_pair_address(idx_leaf);

    let pk_fors = fors_pk_from_sig(sig_fors, md, &pk.pk_seed, &mut adrs, h, p.k, p.a);
    ht_verify(
        &pk_fors, sig_ht, &pk.pk_seed, idx_tree, idx_leaf, &pk.pk_root,
        h, n * 2, 3, p.hp() as u32, p.d as u32,
    )
}

fn fresh_bytes(n: usize) -> Result<Vec<u8>, SlhDsaError> {
    let mut b = vec![0u8; n];
    // OsRng::fill_bytes doesn't fail on any platform this crate targets;
    // kept as a Result for symmetry with the rest of this crate's fallible
    // keygen/sign API and in case a future no_std RNG backend can fail.
    OsRng.fill_bytes(&mut b);
    Ok(b)
}

/// Algorithm 21: slh_keygen(). Generates SK.seed, SK.prf, PK.seed fresh
/// from the OS RNG.
pub fn slh_keygen(p: &SlhDsaParams, h: &impl HashSuite) -> Result<(SlhDsaSecretKey, SlhDsaPublicKey), SlhDsaError> {
    let sk_seed = fresh_bytes(p.n)?;
    let sk_prf = fresh_bytes(p.n)?;
    let pk_seed = fresh_bytes(p.n)?;
    Ok(slh_keygen_internal(&sk_seed, &sk_prf, &pk_seed, p, h))
}

/// Builds M' for the pure interface (Algorithm 22 line 8 / Algorithm 24
/// line 4): toByte(0,1) || toByte(|ctx|,1) || ctx || M.
pub fn pure_message_prime(ctx: &[u8], m: &[u8]) -> Result<Vec<u8>, SlhDsaError> {
    if ctx.len() > 255 {
        return Err(SlhDsaError::ContextTooLong);
    }
    let mut mp = Vec::with_capacity(2 + ctx.len() + m.len());
    mp.push(0u8);
    mp.push(ctx.len() as u8);
    mp.extend_from_slice(ctx);
    mp.extend_from_slice(m);
    Ok(mp)
}

/// Algorithm 22: slh_sign(M, ctx, SK) — pure SLH-DSA signing.
/// `hedged = true` is the default/recommended variant (fresh randomness
/// per signature); `hedged = false` is the deterministic variant.
pub fn slh_sign(m: &[u8], ctx: &[u8], sk: &SlhDsaSecretKey, p: &SlhDsaParams, h: &impl HashSuite, hedged: bool) -> Result<Vec<u8>, SlhDsaError> {
    let mp = pure_message_prime(ctx, m)?;
    if hedged {
        let addrnd = fresh_bytes(p.n)?;
        Ok(slh_sign_internal(&mp, sk, Some(&addrnd), p, h))
    } else {
        Ok(slh_sign_internal(&mp, sk, None, p, h))
    }
}

/// Algorithm 24: slh_verify(M, SIG, ctx, PK) — pure SLH-DSA verification.
pub fn slh_verify(m: &[u8], sig: &[u8], ctx: &[u8], pk: &SlhDsaPublicKey, p: &SlhDsaParams, h: &impl HashSuite) -> bool {
    if ctx.len() > 255 {
        return false;
    }
    match pure_message_prime(ctx, m) {
        Ok(mp) => slh_verify_internal(&mp, sig, pk, p, h),
        Err(_) => false,
    }
}
