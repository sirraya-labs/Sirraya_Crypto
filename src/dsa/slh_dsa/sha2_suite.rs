//! FIPS 205 §11.2 — SLH-DSA using SHA2.
//!
//! Two sub-cases that share this file because the only difference is which
//! concrete hash function backs `H_msg`/`PRF_msg`/`H`/`T_l` (`PRF` and `F`
//! are SHA-256 unconditionally in *both* cases — see §11.2.1 and §11.2.2,
//! and note this is **not** a copy-paste artifact: both spec subsections
//! genuinely specify SHA-256 there):
//! - §11.2.1, security category 1 (n=16): SHA-256 throughout.
//! - §11.2.2, security categories 3/5 (n=24, n=32): SHA-512 for
//!   `H_msg`/`PRF_msg`/`H`/`T_l`, still SHA-256 for `PRF`/`F`.
//!
//! `Sha2Suite::new(n)` picks the right case from `n` alone, matching how
//! Table 2 ties `n` to security category 1:1.

use super::adrs::Adrs;
use super::hash_suite::HashSuite;
use super::util::to_byte;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256, Sha512};

/// RFC 8017 Appendix B.2.1 — MGF1, generic over the underlying hash.
/// `hash` computes one hash-function call over its input.
fn mgf1(hash: impl Fn(&[u8]) -> Vec<u8>, hash_out_len: usize, mgf_seed: &[u8], mask_len: usize) -> Vec<u8> {
    let iterations = mask_len.div_ceil(hash_out_len);
    let mut out = Vec::with_capacity(iterations * hash_out_len);
    for counter in 0..iterations as u32 {
        let mut input = mgf_seed.to_vec();
        input.extend_from_slice(&to_byte(counter, 4));
        out.extend_from_slice(&hash(&input));
    }
    out.truncate(mask_len);
    out
}

fn sha256(parts: &[&[u8]]) -> Vec<u8> {
    let mut h = Sha256::new();
    for p in parts {
        Digest::update(&mut h, p);
    }
    h.finalize().to_vec()
}

fn sha512(parts: &[&[u8]]) -> Vec<u8> {
    let mut h = Sha512::new();
    for p in parts {
        Digest::update(&mut h, p);
    }
    h.finalize().to_vec()
}

fn hmac_sha256(key: &[u8], parts: &[&[u8]]) -> Vec<u8> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key length");
    for p in parts {
        Mac::update(&mut mac, p);
    }
    mac.finalize().into_bytes().to_vec()
}

fn hmac_sha512(key: &[u8], parts: &[&[u8]]) -> Vec<u8> {
    let mut mac = Hmac::<Sha512>::new_from_slice(key).expect("HMAC accepts any key length");
    for p in parts {
        Mac::update(&mut mac, p);
    }
    mac.finalize().into_bytes().to_vec()
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Sha2Case {
    /// §11.2.1 — n = 16, security category 1.
    Category1,
    /// §11.2.2 — n = 24 or 32, security categories 3/5.
    Category3Or5,
}

pub struct Sha2Suite {
    pub n: usize,
    case: Sha2Case,
}

impl Sha2Suite {
    pub fn new(n: usize) -> Self {
        let case = if n == 16 {
            Sha2Case::Category1
        } else {
            debug_assert!(n == 24 || n == 32, "SLH-DSA SHA2 only defines n = 16, 24, 32");
            Sha2Case::Category3Or5
        };
        Sha2Suite { n, case }
    }

    fn trunc(&self, full: Vec<u8>) -> Vec<u8> {
        full[0..self.n].to_vec()
    }
}

impl HashSuite for Sha2Suite {
    fn n(&self) -> usize {
        self.n
    }

    fn h_msg(&self, r: &[u8], pk_seed: &[u8], pk_root: &[u8], m: &[u8], out_len: usize) -> Vec<u8> {
        match self.case {
            Sha2Case::Category1 => {
                let inner = sha256(&[r, pk_seed, pk_root, m]);
                let mut seed = r.to_vec();
                seed.extend_from_slice(pk_seed);
                seed.extend_from_slice(&inner);
                mgf1(sha256_1, 32, &seed, out_len)
            }
            Sha2Case::Category3Or5 => {
                let inner = sha512(&[r, pk_seed, pk_root, m]);
                let mut seed = r.to_vec();
                seed.extend_from_slice(pk_seed);
                seed.extend_from_slice(&inner);
                mgf1(sha512_1, 64, &seed, out_len)
            }
        }
    }

    fn prf(&self, pk_seed: &[u8], sk_seed: &[u8], adrs: &Adrs) -> Vec<u8> {
        // PRF is SHA-256 with toByte(0, 64-n) padding in *both* §11.2.1 and
        // §11.2.2 — see module docs.
        let pad = vec![0u8; 64 - self.n];
        let adrsc = adrs.compress();
        self.trunc(sha256(&[pk_seed, &pad, &adrsc, sk_seed]))
    }

    fn prf_msg(&self, sk_prf: &[u8], opt_rand: &[u8], m: &[u8]) -> Vec<u8> {
        match self.case {
            Sha2Case::Category1 => self.trunc(hmac_sha256(sk_prf, &[opt_rand, m])),
            Sha2Case::Category3Or5 => self.trunc(hmac_sha512(sk_prf, &[opt_rand, m])),
        }
    }

    fn f_hash(&self, pk_seed: &[u8], adrs: &Adrs, m1: &[u8]) -> Vec<u8> {
        // F is SHA-256 with toByte(0, 64-n) padding in *both* cases too.
        let pad = vec![0u8; 64 - self.n];
        let adrsc = adrs.compress();
        self.trunc(sha256(&[pk_seed, &pad, &adrsc, m1]))
    }

    fn h_hash(&self, pk_seed: &[u8], adrs: &Adrs, m2: &[u8]) -> Vec<u8> {
        let adrsc = adrs.compress();
        match self.case {
            Sha2Case::Category1 => {
                let pad = vec![0u8; 64 - self.n];
                self.trunc(sha256(&[pk_seed, &pad, &adrsc, m2]))
            }
            Sha2Case::Category3Or5 => {
                let pad = vec![0u8; 128 - self.n];
                self.trunc(sha512(&[pk_seed, &pad, &adrsc, m2]))
            }
        }
    }

    fn t_l(&self, pk_seed: &[u8], adrs: &Adrs, ml: &[u8]) -> Vec<u8> {
        let adrsc = adrs.compress();
        match self.case {
            Sha2Case::Category1 => {
                let pad = vec![0u8; 64 - self.n];
                self.trunc(sha256(&[pk_seed, &pad, &adrsc, ml]))
            }
            Sha2Case::Category3Or5 => {
                let pad = vec![0u8; 128 - self.n];
                self.trunc(sha512(&[pk_seed, &pad, &adrsc, ml]))
            }
        }
    }
}

fn sha256_1(x: &[u8]) -> Vec<u8> {
    sha256(&[x])
}
fn sha512_1(x: &[u8]) -> Vec<u8> {
    sha512(&[x])
}
