//! Crypto-agility surface: one trait every signature scheme in this crate
//! implements, so calling code (and combinators like `crate::hybrid`) can be
//! written once against `SignatureScheme` instead of per-algorithm.
//!
//! Associated types (rather than a single flat `[u8; N]`) are used
//! deliberately: stable Rust cannot express an array length like
//! `K * POLYZ_PACKEDBYTES` from generic/const parameters (that needs the
//! unstable `generic_const_exprs` feature), so each concrete scheme fixes
//! its own `PublicKey`/`SecretKey`/`Signature` array sizes, and this trait
//! just requires that they can be viewed as bytes (`AsRef<[u8]>`). That
//! keeps every existing `[u8; PUBLICKEYBYTES]`-based API in this crate
//! untouched while still giving generic code something to hold onto.

/// A key-generation / signing / verification algorithm.
///
/// Implemented today by [`crate::dsa::ml_dsa::ml_dsa_44::MlDsa44`]. Adding a
/// new ML-DSA parameter set or an entirely different algorithm family (e.g.
/// SLH-DSA) means adding another `impl SignatureScheme for ...` — this
/// trait itself never needs to change, and existing implementors are
/// unaffected.
pub trait SignatureScheme {
    /// Public key type (typically `[u8; N]` for this scheme's key size).
    type PublicKey: AsRef<[u8]>;
    /// Secret key type. Also viewable/clearable as bytes so generic code
    /// can serialize it and zeroize it after use — the crate's existing
    /// `[u8; SECRETKEYBYTES]` implementors get this for free.
    type SecretKey: AsRef<[u8]> + AsMut<[u8]>;
    /// Signature type.
    type Signature: AsRef<[u8]>;
    /// This scheme's error type.
    type Error: core::fmt::Debug + core::fmt::Display;

    /// Human-readable algorithm identifier, e.g. `"MlDsa44"`.
    const NAME: &'static str;
    const PUBLIC_KEY_LEN: usize;
    const SECRET_KEY_LEN: usize;
    const SIGNATURE_LEN: usize;
    /// Seed length for [`keypair_from_seed`](Self::keypair_from_seed).
    /// 32 bytes for every ML-DSA level (FIPS 204 Alg 1); kept as an
    /// associated const rather than hardcoded so a future non-ML-DSA
    /// implementor isn't forced into that number.
    const SEED_LEN: usize;

    fn keypair() -> Result<(Self::PublicKey, Self::SecretKey), Self::Error>;
    /// Deterministic keygen from an explicit seed of length [`SEED_LEN`](Self::SEED_LEN)
    /// (e.g. for reproducible test vectors) rather than fresh system randomness.
    fn keypair_from_seed(seed: &[u8]) -> Result<(Self::PublicKey, Self::SecretKey), Self::Error>;
    fn sign(sk: &Self::SecretKey, msg: &[u8]) -> Result<Self::Signature, Self::Error>;
    fn verify(
        pk: &Self::PublicKey,
        msg: &[u8],
        sig: &Self::Signature,
    ) -> Result<bool, Self::Error>;

    /// Parse a public key from bytes read off disk/CLI/wire. `None` if
    /// `bytes.len() != PUBLIC_KEY_LEN`. Together with `secret_key_from_bytes`
    /// and `signature_from_bytes`, this is what lets calling code (e.g. a
    /// CLI) accept `--alg ml-dsa-44|ml-dsa-65` and load/save key material
    /// through one generic code path instead of one copy per variant.
    fn public_key_from_bytes(bytes: &[u8]) -> Option<Self::PublicKey>;
    /// Parse a secret key from bytes. `None` if the length doesn't match
    /// [`SECRET_KEY_LEN`](Self::SECRET_KEY_LEN).
    fn secret_key_from_bytes(bytes: &[u8]) -> Option<Self::SecretKey>;
    /// Parse a signature from bytes. `None` if the length doesn't match
    /// [`SIGNATURE_LEN`](Self::SIGNATURE_LEN).
    fn signature_from_bytes(bytes: &[u8]) -> Option<Self::Signature>;
}