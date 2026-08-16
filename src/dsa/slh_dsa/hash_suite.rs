//! The `HashSuite` trait abstracts over FIPS 205's two approved hash
//! function instantiations — SHAKE (§11.1, this file) and SHA2 (§11.2,
//! `sha2_suite`) — so `wots`, `xmss`, `ht`, `fors`, and `core` are written
//! once against the six abstract functions of §4.1 and never need to know
//! which concrete hash function is underneath. This is the mechanism that
//! makes it possible to add the SHA2 parameter sets without duplicating
//! any tree/signature logic: only a new `HashSuite` impl was needed.

use super::adrs::Adrs;

/// The six hash/PRF functions of FIPS 205 §4.1, plus the security
/// parameter `n` they're keyed to. Every method takes the *full* 32-byte
/// `Adrs` (Table 1) — compressing it to the SHA2 instantiation's 22-byte
/// `ADRSc` (Table 3), if needed, is the implementor's job, not the
/// caller's (see `sha2_suite`).
pub trait HashSuite {
    fn n(&self) -> usize;

    /// H_msg(R, PK.seed, PK.root, M) → `out_len` bytes.
    fn h_msg(&self, r: &[u8], pk_seed: &[u8], pk_root: &[u8], m: &[u8], out_len: usize) -> Vec<u8>;
    /// PRF(PK.seed, SK.seed, ADRS) → n bytes.
    fn prf(&self, pk_seed: &[u8], sk_seed: &[u8], adrs: &Adrs) -> Vec<u8>;
    /// PRF_msg(SK.prf, opt_rand, M) → n bytes.
    fn prf_msg(&self, sk_prf: &[u8], opt_rand: &[u8], m: &[u8]) -> Vec<u8>;
    /// F(PK.seed, ADRS, M1) → n bytes.
    fn f_hash(&self, pk_seed: &[u8], adrs: &Adrs, m1: &[u8]) -> Vec<u8>;
    /// H(PK.seed, ADRS, M2) → n bytes.
    fn h_hash(&self, pk_seed: &[u8], adrs: &Adrs, m2: &[u8]) -> Vec<u8>;
    /// T_l(PK.seed, ADRS, M_l) → n bytes.
    fn t_l(&self, pk_seed: &[u8], adrs: &Adrs, ml: &[u8]) -> Vec<u8>;
}

/// FIPS 205 §11.1 — SLH-DSA using SHAKE. Every one of the six functions is
/// SHAKE256 of the concatenated inputs; §11.1 gives the exact
/// concatenation order for each.
pub struct ShakeSuite {
    pub n: usize,
}

fn shake256_xof(parts: &[&[u8]], out_len: usize) -> Vec<u8> {
    use sha3::digest::{ExtendableOutput, Update, XofReader};
    use sha3::Shake256;
    let mut hasher = Shake256::default();
    for p in parts {
        Update::update(&mut hasher, p);
    }
    let mut reader = hasher.finalize_xof();
    let mut out = vec![0u8; out_len];
    reader.read(&mut out);
    out
}

impl HashSuite for ShakeSuite {
    fn n(&self) -> usize {
        self.n
    }
    fn h_msg(&self, r: &[u8], pk_seed: &[u8], pk_root: &[u8], m: &[u8], out_len: usize) -> Vec<u8> {
        shake256_xof(&[r, pk_seed, pk_root, m], out_len)
    }
    fn prf(&self, pk_seed: &[u8], sk_seed: &[u8], adrs: &Adrs) -> Vec<u8> {
        shake256_xof(&[pk_seed, adrs.as_bytes(), sk_seed], self.n)
    }
    fn prf_msg(&self, sk_prf: &[u8], opt_rand: &[u8], m: &[u8]) -> Vec<u8> {
        shake256_xof(&[sk_prf, opt_rand, m], self.n)
    }
    fn f_hash(&self, pk_seed: &[u8], adrs: &Adrs, m1: &[u8]) -> Vec<u8> {
        shake256_xof(&[pk_seed, adrs.as_bytes(), m1], self.n)
    }
    fn h_hash(&self, pk_seed: &[u8], adrs: &Adrs, m2: &[u8]) -> Vec<u8> {
        shake256_xof(&[pk_seed, adrs.as_bytes(), m2], self.n)
    }
    fn t_l(&self, pk_seed: &[u8], adrs: &Adrs, ml: &[u8]) -> Vec<u8> {
        shake256_xof(&[pk_seed, adrs.as_bytes(), ml], self.n)
    }
}
