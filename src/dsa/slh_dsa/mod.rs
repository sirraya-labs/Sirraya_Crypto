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
//! [`core`] wires these into the internal (§9) and external "pure" (§10.1,
//! 10.2.1, 10.3) SLH-DSA functions; [`prehash`] adds the "pre-hash"
//! HashSLH-DSA variant (§10.2.2, Algorithms 23/25) on top of the same
//! internal functions. [`adrs`] is the shared 32-byte addressing scheme
//! (§4.2) every hash call in every layer above takes as input.
//!
//! Every algorithm above is generic over [`hash_suite::HashSuite`], the
//! trait abstracting FIPS 205's six hash functions (§4.1) — see that
//! module's docs. [`hash_suite::ShakeSuite`] implements the SHAKE
//! instantiation (§11.1); [`sha2_suite::Sha2Suite`] implements SHA2
//! (§11.2). Neither `wots`/`xmss`/`ht`/`fors`/`core`/`prehash` know or
//! care which one is plugged in — that happens once, per variant, in the
//! `slh_dsa_variant!` macro invocations below.
//!
//! # Scope of this implementation
//! - All 12 of FIPS 205's approved parameter sets are implemented: six
//!   SHAKE (`SlhDsaShake*`) and six SHA2 (`SlhDsaSha2*`).
//! - Both signing interfaces are implemented: "pure" (`sign`/`verify`,
//!   Algorithms 22/24) and "pre-hash" HashSLH-DSA (`sign_prehash`/
//!   `verify_prehash`, Algorithms 23/25, in [`prehash`]), the latter
//!   supporting the four `PH` options FIPS 205 gives worked DER OID
//!   encodings for: SHA-256, SHA-512, SHAKE128, SHAKE256.
//! - **Not yet checked against NIST's ACVP known-answer test vectors.**
//!   Test coverage below is internal round-trip only (keypair → sign →
//!   verify, tamper rejection) for the same reason `dsa::ml_dsa`'s was
//!   insufficient on its own — see ARCHITECTURE.md §10 and README
//!   "Testing" for what that class of bug looks like and why it needs an
//!   independent check. This is the natural next step.

pub mod adrs;
pub mod core;
pub mod fors;
pub mod hash_suite;
pub mod ht;
pub mod params;
pub mod prehash;
pub mod sha2_suite;
pub mod util;
pub mod wots;
pub mod xmss;

use self::core::{slh_keygen, slh_keygen_internal, slh_sign, slh_verify, SlhDsaError, SlhDsaPublicKey, SlhDsaSecretKey};
use self::hash_suite::ShakeSuite;
use self::params::SlhDsaParams;
use self::prehash::{hash_slh_sign, hash_slh_verify, PreHash};
use self::sha2_suite::Sha2Suite;
use crate::traits::SignatureScheme;

/// Generates one SLH-DSA parameter-set type. All variants share identical
/// logic in `core`/`wots`/`xmss`/`ht`/`fors` — the only per-invocation
/// differences are the `SlhDsaParams` value, which concrete `HashSuite` to
/// construct, and the three array lengths, which are asserted against that
/// same `SlhDsaParams` at every call (`debug_assert_eq!` — cheap, and
/// turns a future mismatched invocation of this macro into an immediate
/// panic in tests rather than a silent wrong-size key, the ML-DSA-44
/// failure mode this module's docs mention).
macro_rules! slh_dsa_variant {
    ($ty:ident, $params:expr, $suite:ty, $suite_ctor:expr, $pk_len:expr, $sk_len:expr, $sig_len:expr, $seed_len:expr) => {
        #[doc = concat!("FIPS 205 ", stringify!($ty), " (see `params::", stringify!($params), "`).")]
        pub struct $ty;

        impl $ty {
            const P: SlhDsaParams = $params;

            fn suite() -> $suite {
                ($suite_ctor)(Self::P.n)
            }

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
                let sig = slh_sign(msg, &[], &sk, &Self::P, &Self::suite(), false)?;
                Ok(sig.try_into().unwrap())
            }

            /// Algorithm 23: HashSLH-DSA pre-hash signing. `ph` selects the
            /// pre-hash function (independent of this type's own SHAKE/SHA2
            /// instantiation — see `prehash` module docs).
            pub fn sign_prehash(
                sk: &<Self as SignatureScheme>::SecretKey,
                msg: &[u8],
                ctx: &[u8],
                ph: PreHash,
            ) -> Result<<Self as SignatureScheme>::Signature, SlhDsaError> {
                Self::check_sizes();
                let sk = SlhDsaSecretKey::from_bytes(sk, Self::P.n).ok_or(SlhDsaError::InvalidKeyLength)?;
                let sig = hash_slh_sign(msg, ctx, ph, &sk, &Self::P, &Self::suite(), true)?;
                Ok(sig.try_into().unwrap())
            }

            /// Algorithm 25: HashSLH-DSA pre-hash verification.
            pub fn verify_prehash(
                pk: &<Self as SignatureScheme>::PublicKey,
                msg: &[u8],
                ctx: &[u8],
                ph: PreHash,
                sig: &<Self as SignatureScheme>::Signature,
            ) -> Result<bool, SlhDsaError> {
                Self::check_sizes();
                let pk = SlhDsaPublicKey::from_bytes(pk, Self::P.n).ok_or(SlhDsaError::InvalidKeyLength)?;
                Ok(hash_slh_verify(msg, sig.as_ref(), ctx, ph, &pk, &Self::P, &Self::suite()))
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
                let (sk, pk) = slh_keygen(&Self::P, &Self::suite())?;
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
                let (sk, pk) = slh_keygen_internal(&seed[0..n], &seed[n..2 * n], &seed[2 * n..3 * n], &Self::P, &Self::suite());
                Ok((
                    pk.to_bytes().try_into().unwrap(),
                    sk.to_bytes().try_into().unwrap(),
                ))
            }

            fn sign(sk: &Self::SecretKey, msg: &[u8]) -> Result<Self::Signature, Self::Error> {
                Self::check_sizes();
                let sk = SlhDsaSecretKey::from_bytes(sk, Self::P.n).ok_or(SlhDsaError::InvalidKeyLength)?;
                let sig = slh_sign(msg, &[], &sk, &Self::P, &Self::suite(), true)?;
                Ok(sig.try_into().unwrap())
            }

            fn verify(pk: &Self::PublicKey, msg: &[u8], sig: &Self::Signature) -> Result<bool, Self::Error> {
                Self::check_sizes();
                let pk = SlhDsaPublicKey::from_bytes(pk, Self::P.n).ok_or(SlhDsaError::InvalidKeyLength)?;
                Ok(slh_verify(msg, sig.as_ref(), &[], &pk, &Self::P, &Self::suite()))
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

slh_dsa_variant!(SlhDsaShake128s, params::SLH_DSA_SHAKE_128S, ShakeSuite, |n| ShakeSuite { n }, 32, 64, 7856, 48);
slh_dsa_variant!(SlhDsaShake128f, params::SLH_DSA_SHAKE_128F, ShakeSuite, |n| ShakeSuite { n }, 32, 64, 17088, 48);
slh_dsa_variant!(SlhDsaShake192s, params::SLH_DSA_SHAKE_192S, ShakeSuite, |n| ShakeSuite { n }, 48, 96, 16224, 72);
slh_dsa_variant!(SlhDsaShake192f, params::SLH_DSA_SHAKE_192F, ShakeSuite, |n| ShakeSuite { n }, 48, 96, 35664, 72);
slh_dsa_variant!(SlhDsaShake256s, params::SLH_DSA_SHAKE_256S, ShakeSuite, |n| ShakeSuite { n }, 64, 128, 29792, 96);
slh_dsa_variant!(SlhDsaShake256f, params::SLH_DSA_SHAKE_256F, ShakeSuite, |n| ShakeSuite { n }, 64, 128, 49856, 96);

slh_dsa_variant!(SlhDsaSha2_128s, params::SLH_DSA_SHA2_128S, Sha2Suite, Sha2Suite::new, 32, 64, 7856, 48);
slh_dsa_variant!(SlhDsaSha2_128f, params::SLH_DSA_SHA2_128F, Sha2Suite, Sha2Suite::new, 32, 64, 17088, 48);
slh_dsa_variant!(SlhDsaSha2_192s, params::SLH_DSA_SHA2_192S, Sha2Suite, Sha2Suite::new, 48, 96, 16224, 72);
slh_dsa_variant!(SlhDsaSha2_192f, params::SLH_DSA_SHA2_192F, Sha2Suite, Sha2Suite::new, 48, 96, 35664, 72);
slh_dsa_variant!(SlhDsaSha2_256s, params::SLH_DSA_SHA2_256S, Sha2Suite, Sha2Suite::new, 64, 128, 29792, 96);
slh_dsa_variant!(SlhDsaSha2_256f, params::SLH_DSA_SHA2_256F, Sha2Suite, Sha2Suite::new, 64, 128, 49856, 96);

#[cfg(test)]
mod tests {
    use super::*;

    // SLH-DSA-*-128f only: the 's' ("small signature") variants have
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

    #[test]
    fn shake_128f_prehash_roundtrip_all_ph_options() {
        let (pk, sk) = SlhDsaShake128f::keypair().unwrap();
        let msg = b"pre-hash this";
        for ph in [PreHash::Sha256, PreHash::Sha512, PreHash::Shake128, PreHash::Shake256] {
            let sig = SlhDsaShake128f::sign_prehash(&sk, msg, &[], ph).unwrap();
            assert!(SlhDsaShake128f::verify_prehash(&pk, msg, &[], ph, &sig).unwrap(), "{ph:?}");
        }
    }

    #[test]
    fn shake_128f_prehash_rejects_wrong_ph_option() {
        let (pk, sk) = SlhDsaShake128f::keypair().unwrap();
        let msg = b"pre-hash mismatch test";
        let sig = SlhDsaShake128f::sign_prehash(&sk, msg, &[], PreHash::Sha256).unwrap();
        // Verifying with a different PH must fail: PH_M and the OID both
        // change, so M' no longer matches what was signed.
        assert!(!SlhDsaShake128f::verify_prehash(&pk, msg, &[], PreHash::Sha512, &sig).unwrap());
    }

    #[test]
    fn shake_128f_pure_signature_rejected_by_prehash_verify_and_vice_versa() {
        // The domain-separation byte (0 for pure, 1 for pre-hash) must
        // actually separate the two: a pure signature must not verify
        // under hash_slh_verify and vice versa.
        let (pk, sk) = SlhDsaShake128f::keypair().unwrap();
        let msg = b"domain separation check";
        let pure_sig = SlhDsaShake128f::sign(&sk, msg).unwrap();
        assert!(!SlhDsaShake128f::verify_prehash(&pk, msg, &[], PreHash::Sha256, &pure_sig).unwrap());

        let prehash_sig = SlhDsaShake128f::sign_prehash(&sk, msg, &[], PreHash::Sha256).unwrap();
        assert!(!SlhDsaShake128f::verify(&pk, msg, &prehash_sig).unwrap());
    }

    #[test]
    fn sha2_128f_roundtrip() {
        let (pk, sk) = SlhDsaSha2_128f::keypair().unwrap();
        let msg = b"SHA2 instantiation smoke test";
        let sig = SlhDsaSha2_128f::sign(&sk, msg).unwrap();
        assert!(SlhDsaSha2_128f::verify(&pk, msg, &sig).unwrap());
    }

    #[test]
    fn sha2_128f_reject_tampered_signature() {
        let (pk, sk) = SlhDsaSha2_128f::keypair().unwrap();
        let msg = b"sign me";
        let mut sig = SlhDsaSha2_128f::sign(&sk, msg).unwrap();
        sig[0] ^= 0xFF;
        assert!(!SlhDsaSha2_128f::verify(&pk, msg, &sig).unwrap());
    }

    #[test]
    fn sha2_256f_roundtrip() {
        // Exercises the §11.2.2 (SHA-512) branch, not just §11.2.1.
        let (pk, sk) = SlhDsaSha2_256f::keypair().unwrap();
        let msg = b"category 5 SHA2 smoke test";
        let sig = SlhDsaSha2_256f::sign(&sk, msg).unwrap();
        assert!(SlhDsaSha2_256f::verify(&pk, msg, &sig).unwrap());
    }

    #[test]
    fn sha2_128f_prehash_roundtrip() {
        let (pk, sk) = SlhDsaSha2_128f::keypair().unwrap();
        let msg = b"SHA2 variant, SHAKE256 prehash";
        let sig = SlhDsaSha2_128f::sign_prehash(&sk, msg, &[], PreHash::Shake256).unwrap();
        assert!(SlhDsaSha2_128f::verify_prehash(&pk, msg, &[], PreHash::Shake256, &sig).unwrap());
    }

    // Smaller/faster smoke test across every remaining variant so all 12
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
    smoke_test!(sha2_128s_smoke, SlhDsaSha2_128s);
    smoke_test!(sha2_192s_smoke, SlhDsaSha2_192s);
    smoke_test!(sha2_192f_smoke, SlhDsaSha2_192f);
    smoke_test!(sha2_256s_smoke, SlhDsaSha2_256s);
}
