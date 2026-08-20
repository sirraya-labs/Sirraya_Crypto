//! All digital-signature algorithm families live under here, one submodule
//! per family:
//!
//! - `ml_dsa` (FIPS 204) — lattice-based, post-quantum.
//! - `slh_dsa` (FIPS 205) — hash-based, post-quantum.
//! - `ed25519` (RFC 8032) — classical, elliptic-curve. Deliberately wraps
//!   the well-established `ed25519-dalek` rather than being hand-written
//!   from the spec the way the two families above are — see that
//!   module's own doc comment for why that's the right call specifically
//!   for this algorithm, not a shortcut.
//!
//! Any future algorithm implements `crate::traits::SignatureScheme`, the
//! same trait `ml_dsa::MlDsa44`/`slh_dsa::SlhDsaShake128s`/`ed25519::
//! Ed25519` all implement, so code written generically against that trait
//! keeps working unmodified when a new family is added.
//!
//! See `crate::hybrid` for combining two schemes from possibly different
//! families into one composite "sign with both, verify both" scheme —
//! e.g. `Hybrid<MlDsa65, Ed25519>`, the standard PQC-transition pairing
//! (a post-quantum scheme plus a classical one, so the composite stays
//! secure against a classical break even before a PQ scheme has had the
//! same decades of scrutiny), without waiting for a bespoke hybrid
//! algorithm to be standardized.

pub mod ed25519;
pub mod ml_dsa;
pub mod slh_dsa;
