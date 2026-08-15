//! Crypto-agnostic building blocks shared by every signature scheme in this
//! crate. Nothing in here knows about ML-DSA parameter sets, hybrid
//! composition, or any other algorithm-specific concept — that keeps this
//! module reusable if/when a non-lattice scheme (e.g. SLH-DSA) is added
//! alongside ML-DSA.

pub mod ring;
