//! All digital-signature algorithm families live under here, one submodule
//! per family. Today: `ml_dsa` (FIPS 204). Crypto-agility roadmap:
//!
//! - `slh_dsa` (FIPS 205, hash-based signatures) — a structurally
//!   different, non-lattice signature scheme. Add it as a sibling module
//!   here; it does not touch `ml_dsa` at all.
//! - Any future algorithm implements `crate::traits::SignatureScheme`, the
//!   same trait `ml_dsa::MlDsa44` implements, so code written generically
//!   against that trait keeps working unmodified when a new family is
//!   added.
//!
//! See `crate::hybrid` for combining two schemes from possibly different
//! families into one composite "sign with both, verify both" scheme —
//! e.g. an ML-DSA + classical-ECDSA hybrid during the PQC transition
//! period, without waiting for a bespoke hybrid algorithm to be
//! standardized.

pub mod ml_dsa;
pub mod slh_dsa;
