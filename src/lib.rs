//! sirraya-ml-dsa-44 — FIPS 204 ML-DSA post-quantum signatures.
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
//! # Backward compatibility
//! The pre-refactor flat API (`constants_44`, `polynomial`, `mldsa44`,
//! `MlDsa44` all at the crate root) still works unchanged — see the
//! re-exports below. New code should prefer the paths under [`dsa`].

pub mod common;
pub mod dsa;
pub mod hybrid;
pub mod traits;

// ---------------------------------------------------------------------------
// Backward-compatible surface — pre-refactor call sites keep compiling.
// ---------------------------------------------------------------------------

/// Alias of [`dsa::ml_dsa::ml_dsa_44`] under its old module name.
pub use dsa::ml_dsa::ml_dsa_44 as mldsa44;
/// Alias of [`dsa::ml_dsa::ml_dsa_44::constants`] under its old module name.
pub use dsa::ml_dsa::ml_dsa_44::constants as constants_44;
/// Alias of [`common::ring`] under its old module name. Note: the
/// parameter-dependent packing/sampling functions that used to live here
/// (`polyeta_pack`, `sample_in_ball`, etc.) now live per-variant in e.g.
/// [`mldsa44`] instead of in this shared module — see `common::ring`'s and
/// `dsa::ml_dsa::core`'s module docs for why.
pub use common::ring as polynomial;

pub use dsa::ml_dsa::MlDsa44;
