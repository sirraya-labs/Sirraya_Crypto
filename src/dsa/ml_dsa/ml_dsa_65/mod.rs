//! ML-DSA-65 — FIPS 204, Category 3 (192-bit classical / 96-bit quantum).
//!
//! This module is intentionally tiny: it supplies this security level's
//! parameters (`constants`) and stamps out the shared algorithm via
//! `ml_dsa_impl!`. All the actual KeyGen/Sign/Verify logic lives once, in
//! `dsa::ml_dsa::core`, shared with every other ML-DSA parameter set.

pub mod constants;

crate::dsa::ml_dsa::core::ml_dsa_impl!(MlDsa65, crate::dsa::ml_dsa::ml_dsa_65::constants);