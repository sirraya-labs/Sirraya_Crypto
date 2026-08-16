//! sirraya-crypto — post-quantum & hybrid signature primitives (FIPS 204 ML-DSA family, more to come).
//!
//! # Layout (crypto-agility)
//! - [`traits`] — the `SignatureScheme` trait every algorithm in this crate
//!   implements. Write generic code against this instead of a concrete
//!   type when you want to be able to swap algorithms later.
//! - [`common`] — math/primitives shared across algorithm families and
//!   parameter sets (currently: the ML-DSA ring arithmetic that FIPS 204
//!   fixes identically for every security level).
//! - [`dsa`] — one submodule per algorithm family (currently: [`dsa::ml_dsa`],
//!   FIPS 204). Each family holds one submodule per parameter set.
//! - [`hybrid`] — generic composition of two `SignatureScheme`s into one
//!   "both must verify" scheme, for PQC-transition hybrid signing.
//!
//! Adding ML-DSA-65/87, or an unrelated algorithm family like SLH-DSA, is
//! additive from here — see the module docs on [`dsa`] and [`dsa::ml_dsa`].
//!
//! Not yet published, so there is exactly one API surface: the paths
//! below. Nothing aliases a flat/legacy layout.

pub mod common;
pub mod dsa;
pub mod hybrid;
pub mod traits;

pub use dsa::ml_dsa::MlDsa44;
pub use dsa::ml_dsa::MlDsa65;
pub use dsa::slh_dsa::{
    SlhDsaShake128f, SlhDsaShake128s, SlhDsaShake192f, SlhDsaShake192s, SlhDsaShake256f,
    SlhDsaShake256s,
};