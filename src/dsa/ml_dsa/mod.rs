//! ML-DSA (FIPS 204) — the "Module-Lattice-Based Digital Signature
//! Algorithm" family, at every security level the crate implements.
//!
//! # Adding a new parameter set (e.g. ML-DSA-65 or ML-DSA-87)
//! 1. Create `ml_dsa_65/constants.rs` with that level's Table 1/2 values
//!    (copy `ml_dsa_44/constants.rs` and update K, L, ETA, TAU, GAMMA1,
//!    GAMMA2, OMEGA, LAMBDA and the derived sizes — keep the
//!    `pub use crate::common::ring::{N, Q, D, QINV, MONT, ZETAS};` line
//!    as-is, those never change).
//! 2. Create `ml_dsa_65/mod.rs`:
//!    ```ignore
//!    pub mod constants;
//!    crate::dsa::ml_dsa::core::ml_dsa_impl!(MlDsa65, crate::dsa::ml_dsa::ml_dsa_65::constants);
//!    ```
//! 3. Add `pub mod ml_dsa_65;` below.
//! 4. Implement `crate::traits::SignatureScheme` for `MlDsa65` the same way
//!    `ml_dsa_44/mod.rs`'s macro expansion does for `MlDsa44` (see
//!    `core.rs`'s trailing `impl SignatureScheme` block).
//!
//! Nothing about ML-DSA-44 has to change, and nothing else in the crate has
//! to know a new variant exists until something opts into using it.

pub mod core;
pub mod ml_dsa_44;

pub use ml_dsa_44::MlDsa44;
