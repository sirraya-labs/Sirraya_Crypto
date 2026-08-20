//! sirraya-crypto — post-quantum, classical, and hybrid signature
//! primitives: FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA), and RFC 8032
//! (Ed25519).
//!
//! # Layout (crypto-agility)
//! - [`traits`] — the `SignatureScheme` trait every algorithm in this crate
//!   implements. Write generic code against this instead of a concrete
//!   type when you want to be able to swap algorithms later.
//! - [`common`] — math/primitives shared across algorithm families and
//!   parameter sets (currently: the ML-DSA ring arithmetic that FIPS 204
//!   fixes identically for every security level).
//! - [`dsa`] — one submodule per algorithm family: [`dsa::ml_dsa`] (FIPS
//!   204), [`dsa::slh_dsa`] (FIPS 205), and [`dsa::ed25519`] (RFC 8032).
//!   Each family holds one submodule per parameter set / hash
//!   instantiation.
//! - [`hybrid`] — generic composition of two `SignatureScheme`s into one
//!   "both must verify" scheme, for PQC-transition hybrid signing — most
//!   usefully a post-quantum scheme paired with [`Ed25519`], the standard
//!   transition pattern.
//!
//! Adding ML-DSA-87, or another algorithm family entirely, is additive
//! from here — see the module docs on [`dsa`], [`dsa::ml_dsa`],
//! [`dsa::slh_dsa`], and [`dsa::ed25519`].

pub mod common;
pub mod dsa;
pub mod hybrid;
pub mod traits;

pub use dsa::ed25519::Ed25519;
pub use dsa::ml_dsa::MlDsa44;
pub use dsa::ml_dsa::MlDsa65;
pub use dsa::slh_dsa::{
    SlhDsaSha2_128f, SlhDsaSha2_128s, SlhDsaSha2_192f, SlhDsaSha2_192s, SlhDsaSha2_256f,
    SlhDsaSha2_256s, SlhDsaShake128f, SlhDsaShake128s, SlhDsaShake192f, SlhDsaShake192s,
    SlhDsaShake256f, SlhDsaShake256s,
};