//! FIPS 205 §10.2.2 / §10.3 — HashSLH-DSA (pre-hash signing and
//! verification, Algorithms 23 and 25).
//!
//! The pre-hash function `PH` here is independent of which `HashSuite`
//! (SHAKE or SHA2) backs the SLH-DSA parameter set being used to sign —
//! the spec explicitly allows any combination ("hash_slh_sign may be used
//! with other hash functions or XOFs"), so `PreHash` is a separate choice
//! passed alongside the signing key, not derived from it.
//!
//! Only the four `PH` options FIPS 205 gives worked examples for are
//! implemented (SHA-256, SHA-512, SHAKE128, SHAKE256) — §10.2.2 explicitly
//! allows others ("case ... other approved hash functions or XOFs") but
//! doesn't enumerate them, so there's nothing further to implement against
//! without picking an unspecified extension.

use super::core::{slh_sign_internal, slh_verify_internal, SlhDsaError, SlhDsaPublicKey, SlhDsaSecretKey};
use super::hash_suite::HashSuite;
use super::params::SlhDsaParams;
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256, Sha512};
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::{Shake128, Shake256};

/// FIPS 205 §10.2.2 "switch PH" cases.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PreHash {
    Sha256,
    Sha512,
    Shake128,
    Shake256,
}

impl PreHash {
    /// DER encoding (tag + length + OID bytes) exactly as given in
    /// Algorithm 23 lines 10/13/16/19 — these are literal spec constants,
    /// not computed.
    fn oid(&self) -> [u8; 11] {
        match self {
            PreHash::Sha256 => [0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01],
            PreHash::Sha512 => [0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03],
            PreHash::Shake128 => [0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0B],
            PreHash::Shake256 => [0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0C],
        }
    }

    /// PH_M: the pre-hash of the content to be signed.
    fn hash(&self, m: &[u8]) -> Vec<u8> {
        match self {
            PreHash::Sha256 => {
                let mut h = Sha256::new();
                Digest::update(&mut h, m);
                h.finalize().to_vec()
            }
            PreHash::Sha512 => {
                let mut h = Sha512::new();
                Digest::update(&mut h, m);
                h.finalize().to_vec()
            }
            PreHash::Shake128 => {
                let mut hasher = Shake128::default();
                Update::update(&mut hasher, m);
                let mut reader = hasher.finalize_xof();
                let mut out = vec![0u8; 32]; // SHAKE128(M, 256) — 256 bits
                reader.read(&mut out);
                out
            }
            PreHash::Shake256 => {
                let mut hasher = Shake256::default();
                Update::update(&mut hasher, m);
                let mut reader = hasher.finalize_xof();
                let mut out = vec![0u8; 64]; // SHAKE256(M, 512) — 512 bits
                reader.read(&mut out);
                out
            }
        }
    }
}

/// M' = toByte(1,1) || toByte(|ctx|,1) || ctx || OID || PH_M
/// (Algorithm 23 line 24 / Algorithm 25 line 20).
fn prehash_message_prime(ctx: &[u8], ph: PreHash, m: &[u8]) -> Result<Vec<u8>, SlhDsaError> {
    if ctx.len() > 255 {
        return Err(SlhDsaError::ContextTooLong);
    }
    let ph_m = ph.hash(m);
    let mut mp = Vec::with_capacity(2 + ctx.len() + 11 + ph_m.len());
    mp.push(1u8);
    mp.push(ctx.len() as u8);
    mp.extend_from_slice(ctx);
    mp.extend_from_slice(&ph.oid());
    mp.extend_from_slice(&ph_m);
    Ok(mp)
}

/// Algorithm 23: hash_slh_sign(M, ctx, PH, SK).
pub fn hash_slh_sign(
    m: &[u8],
    ctx: &[u8],
    ph: PreHash,
    sk: &SlhDsaSecretKey,
    p: &SlhDsaParams,
    h: &impl HashSuite,
    hedged: bool,
) -> Result<Vec<u8>, SlhDsaError> {
    let mp = prehash_message_prime(ctx, ph, m)?;
    if hedged {
        let mut addrnd = vec![0u8; p.n];
        OsRng.fill_bytes(&mut addrnd);
        Ok(slh_sign_internal(&mp, sk, Some(&addrnd), p, h))
    } else {
        Ok(slh_sign_internal(&mp, sk, None, p, h))
    }
}

/// Algorithm 25: hash_slh_verify(M, SIG, ctx, PH, PK).
pub fn hash_slh_verify(
    m: &[u8],
    sig: &[u8],
    ctx: &[u8],
    ph: PreHash,
    pk: &SlhDsaPublicKey,
    p: &SlhDsaParams,
    h: &impl HashSuite,
) -> bool {
    if ctx.len() > 255 {
        return false;
    }
    match prehash_message_prime(ctx, ph, m) {
        Ok(mp) => slh_verify_internal(&mp, sig, pk, p, h),
        Err(_) => false,
    }
}
