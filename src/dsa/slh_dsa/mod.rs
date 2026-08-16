//! FIPS 205 — Stateless Hash-Based Digital Signature Standard (SLH-DSA,
//! née SPHINCS+).
//!
//! A structurally different signature family from `dsa::ml_dsa`: no
//! lattice math at all, security resting entirely on hash-function
//! properties (preimage/collision resistance), built up from four
//! components per §3:
//!
//! - [`wots`] — WOTS+ one-time signatures (§5)
//! - [`xmss`] — XMSS multi-time signatures built from WOTS+ + a Merkle
//!   tree (§6)
//! - [`ht`] — the hypertree, a tree of XMSS trees (§7)
//! - [`fors`] — FORS, the few-time scheme that signs the actual message
//!   digest (§8)
//!
//! [`core`] wires these into the internal (§9) and external/pure (§10.1,
//! 10.2.1, 10.3) SLH-DSA functions; [`adrs`] is the shared 32-byte
//! addressing scheme (§4.2) every hash call in every layer above takes as
//! input; [`hashers`] is the SHAKE256 instantiation of the six abstract
//! hash functions §4.1 defines, plus `base_2b`/`toInt` (§4.4).
//!
//! # Scope of this implementation
//! - Only the **SHAKE** parameter sets (§11.1) are implemented — the six
//!   `SlhDsaShake*` types below. The **SHA2** instantiation (§11.2) is not;
//!   it needs a `sha2` dependency this crate doesn't currently have, a
//!   *different* 22-byte compressed address encoding (Table 3), and
//!   MGF1/HMAC-SHA2 wiring distinct from everything in [`hashers`]. Adding
//!   it is a new `dsa::slh_dsa::sha2` sibling to [`hashers`], not a change
//!   to anything above — see [`params`]'s module docs for why the
//!   parameter *values* (n, h, d, a, k) are already shared and reusable.
//! - Only **pure** SLH-DSA signing/verification (Algorithms 18, 19, 20, 21,
//!   22, 24) is implemented — not the **pre-hash** HashSLH-DSA variant
//!   (Algorithms 23, 25), which needs the same `sha2` dependency plus DER
//!   OID encoding for the pre-hash function identifier. See [`core`]'s
//!   module docs.
//! - **Not yet checked against NIST's ACVP known-answer test vectors.**
//!   Test coverage below is internal round-trip only (keypair → sign →
//!   verify, tamper rejection) for the same reason `dsa::ml_dsa`'s was
//!   insufficient on its own — see ARCHITECTURE.md §10 and README
//!   "Testing" for what that class of bug looks like and why it needs an
//!   independent check.

pub mod adrs;
pub mod core;
pub mod fors;
pub mod hashers;
pub mod ht;
pub mod params;
pub mod wots;
pub mod xmss;

use self::core::{slh_keygen, slh_keygen_internal, slh_sign, slh_verify, SlhDsaError, SlhDsaPublicKey, SlhDsaSecretKey};
use self::params::SlhDsaParams;
use crate::traits::SignatureScheme;

/// Generates one `SlhDsaShake*` type per parameter set. All six share
/// identical logic — the only per-invocation differences are the
/// `SlhDsaParams` value and the three array lengths, which are asserted
/// against that same `SlhDsaParams` at construction time in every
/// `keypair`/`sign` call (`debug_assert_eq!` — cheap, and turns a future
/// mismatched invocation of this macro into an immediate panic in tests
/// rather than a silent wrong-size key, the ML-DSA-44 failure mode this
/// module's docs mention).
macro_rules! slh_dsa_variant {
    ($ty:ident, $params:expr, $pk_len:expr, $sk_len:expr, $sig_len:expr, $seed_len:expr) => {
        #[doc = concat!("FIPS 205 ", stringify!($ty), " (see `params::", stringify!($params), "`).")]
        pub struct $ty;

        impl $ty {
            const P: SlhDsaParams = $params;

            fn check_sizes() {
                debug_assert_eq!(Self::P.pk_bytes(), $pk_len);
                debug_assert_eq!(Self::P.sk_bytes(), $sk_len);
                debug_assert_eq!(Self::P.sig_bytes(), $sig_len);
            }

            /// Deterministic signing (`addrnd` omitted, FIPS 205 §9.2):
            /// signing the same message twice with the same key produces
            /// the same signature. Available for platforms without a
            /// random bit generator, or for reproducible test vectors.
            pub fn sign_deterministic(
                sk: &<Self as SignatureScheme>::SecretKey,
                msg: &[u8],
            ) -> Result<<Self as SignatureScheme>::Signature, SlhDsaError> {
                Self::check_sizes();
                let sk = SlhDsaSecretKey::from_bytes(sk, Self::P.n).ok_or(SlhDsaError::InvalidKeyLength)?;
                let sig = slh_sign(msg, &[], &sk, &Self::P, false)?;
                Ok(sig.try_into().unwrap())
            }
        }

        impl SignatureScheme for $ty {
            type PublicKey = [u8; $pk_len];
            type SecretKey = [u8; $sk_len];
            type Signature = [u8; $sig_len];
            type Error = SlhDsaError;

            const NAME: &'static str = Self::P.name;
            const PUBLIC_KEY_LEN: usize = $pk_len;
            const SECRET_KEY_LEN: usize = $sk_len;
            const SIGNATURE_LEN: usize = $sig_len;
            /// SLH-DSA keygen needs three independent n-byte seeds
            /// (SK.seed, SK.prf, PK.seed — Figure 15) rather than ML-DSA's
            /// one, so `keypair_from_seed` splits a 3n-byte seed into
            /// three equal parts in that order.
            const SEED_LEN: usize = $seed_len;

            fn keypair() -> Result<(Self::PublicKey, Self::SecretKey), Self::Error> {
                Self::check_sizes();
                let (sk, pk) = slh_keygen(&Self::P)?;
                Ok((
                    pk.to_bytes().try_into().unwrap(),
                    sk.to_bytes().try_into().unwrap(),
                ))
            }

            fn keypair_from_seed(seed: &[u8]) -> Result<(Self::PublicKey, Self::SecretKey), Self::Error> {
                Self::check_sizes();
                if seed.len() != Self::SEED_LEN {
                    return Err(SlhDsaError::InvalidKeyLength);
                }
                let n = Self::P.n;
                let (sk, pk) = slh_keygen_internal(&seed[0..n], &seed[n..2 * n], &seed[2 * n..3 * n], &Self::P);
                Ok((
                    pk.to_bytes().try_into().unwrap(),
                    sk.to_bytes().try_into().unwrap(),
                ))
            }

            fn sign(sk: &Self::SecretKey, msg: &[u8]) -> Result<Self::Signature, Self::Error> {
                Self::check_sizes();
                let sk = SlhDsaSecretKey::from_bytes(sk, Self::P.n).ok_or(SlhDsaError::InvalidKeyLength)?;
                let sig = slh_sign(msg, &[], &sk, &Self::P, true)?;
                Ok(sig.try_into().unwrap())
            }

            fn verify(pk: &Self::PublicKey, msg: &[u8], sig: &Self::Signature) -> Result<bool, Self::Error> {
                Self::check_sizes();
                let pk = SlhDsaPublicKey::from_bytes(pk, Self::P.n).ok_or(SlhDsaError::InvalidKeyLength)?;
                Ok(slh_verify(msg, sig.as_ref(), &[], &pk, &Self::P))
            }

            fn public_key_from_bytes(bytes: &[u8]) -> Option<Self::PublicKey> {
                bytes.try_into().ok()
            }
            fn secret_key_from_bytes(bytes: &[u8]) -> Option<Self::SecretKey> {
                bytes.try_into().ok()
            }
            fn signature_from_bytes(bytes: &[u8]) -> Option<Self::Signature> {
                bytes.try_into().ok()
            }
        }
    };
}

slh_dsa_variant!(SlhDsaShake128s, params::SLH_DSA_SHAKE_128S, 32, 64, 7856, 48);
slh_dsa_variant!(SlhDsaShake128f, params::SLH_DSA_SHAKE_128F, 32, 64, 17088, 48);
slh_dsa_variant!(SlhDsaShake192s, params::SLH_DSA_SHAKE_192S, 48, 96, 16224, 72);
slh_dsa_variant!(SlhDsaShake192f, params::SLH_DSA_SHAKE_192F, 48, 96, 35664, 72);
slh_dsa_variant!(SlhDsaShake256s, params::SLH_DSA_SHAKE_256S, 64, 128, 29792, 96);
slh_dsa_variant!(SlhDsaShake256f, params::SLH_DSA_SHAKE_256F, 64, 128, 49856, 96);

#[cfg(test)]
mod tests {
    use super::*;

    // SLH-DSA-SHAKE-128f only: the 's' ("small signature") variants have
    // deliberately larger FORS/XMSS trees and are correspondingly much
    // slower (see module docs on why — same tree-recursion cost, more
    // leaves). Run with --release; in debug mode even 128f is noticeably
    // slower than the ML-DSA suite.
    #[test]
    fn shake_128f_roundtrip() {
        let (pk, sk) = SlhDsaShake128f::keypair().unwrap();
        let msg = b"sirraya-crypto SLH-DSA smoke test";
        let sig = SlhDsaShake128f::sign(&sk, msg).unwrap();
        assert!(SlhDsaShake128f::verify(&pk, msg, &sig).unwrap());
    }

    #[test]
    fn shake_128f_reject_wrong_message() {
        let (pk, sk) = SlhDsaShake128f::keypair().unwrap();
        let sig = SlhDsaShake128f::sign(&sk, b"original message").unwrap();
        assert!(!SlhDsaShake128f::verify(&pk, b"tampered message", &sig).unwrap());
    }

    #[test]
    fn shake_128f_reject_tampered_signature() {
        let (pk, sk) = SlhDsaShake128f::keypair().unwrap();
        let msg = b"sign me";
        let mut sig = SlhDsaShake128f::sign(&sk, msg).unwrap();
        sig[0] ^= 0xFF;
        assert!(!SlhDsaShake128f::verify(&pk, msg, &sig).unwrap());
    }

    #[test]
    fn shake_128f_deterministic_signing_is_deterministic() {
        let (_, sk) = SlhDsaShake128f::keypair().unwrap();
        let msg = b"same message, same signature";
        let sig1 = SlhDsaShake128f::sign_deterministic(&sk, msg).unwrap();
        let sig2 = SlhDsaShake128f::sign_deterministic(&sk, msg).unwrap();
        assert_eq!(sig1, sig2);
    }

    #[test]
    fn shake_128f_keypair_from_seed_is_deterministic() {
        let seed = [7u8; 48]; // SEED_LEN for the 128-bit category = 3*16
        let (pk1, sk1) = SlhDsaShake128f::keypair_from_seed(&seed).unwrap();
        let (pk2, sk2) = SlhDsaShake128f::keypair_from_seed(&seed).unwrap();
        assert_eq!(pk1, pk2);
        assert_eq!(sk1, sk2);
    }

    // Smaller/faster smoke test across every variant so the other five
    // parameter sets are known to at least execute correctly end-to-end;
    // full round-trip + tamper-rejection coverage per variant is left for
    // when this is extended alongside ACVP verification (see module docs).
    macro_rules! smoke_test {
        ($name:ident, $ty:ident) => {
            #[test]
            fn $name() {
                let (pk, sk) = $ty::keypair().unwrap();
                let msg = b"smoke test";
                let sig = $ty::sign(&sk, msg).unwrap();
                assert!($ty::verify(&pk, msg, &sig).unwrap());
            }
        };
    }
    smoke_test!(shake_128s_smoke, SlhDsaShake128s);
    smoke_test!(shake_192s_smoke, SlhDsaShake192s);
    smoke_test!(shake_192f_smoke, SlhDsaShake192f);
    smoke_test!(shake_256s_smoke, SlhDsaShake256s);
    smoke_test!(shake_256f_smoke, SlhDsaShake256f);
}
