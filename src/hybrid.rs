//! Generic "sign with both, require both to verify" composition of two
//! [`SignatureScheme`]s.
//!
//! This is the standard PQC-transition hybrid pattern: pair a
//! post-quantum scheme (e.g. `MlDsa44`) with a classical one (e.g. an
//! Ed25519/ECDSA `SignatureScheme` impl, once one exists in this crate or
//! is brought in and wrapped) so a signature is only accepted if *both*
//! algorithms verify it. That way the composite is only as weak as the
//! stronger assumption breaking, not the weaker one.
//!
//! `Hybrid<A, B>` is generic over any two implementors of
//! [`crate::traits::SignatureScheme`] — including two ML-DSA parameter
//! sets, or (once added) a mix of ML-DSA and SLH-DSA for algorithm
//! diversity within post-quantum signatures themselves. Nothing here is
//! ML-DSA-specific.

use crate::traits::SignatureScheme;

pub struct HybridPublicKey<A: SignatureScheme, B: SignatureScheme> {
    pub primary: A::PublicKey,
    pub secondary: B::PublicKey,
}

pub struct HybridSecretKey<A: SignatureScheme, B: SignatureScheme> {
    pub primary: A::SecretKey,
    pub secondary: B::SecretKey,
}

pub struct HybridSignature<A: SignatureScheme, B: SignatureScheme> {
    pub primary: A::Signature,
    pub secondary: B::Signature,
}

pub enum HybridError<A: SignatureScheme, B: SignatureScheme> {
    Primary(A::Error),
    Secondary(B::Error),
}

impl<A: SignatureScheme, B: SignatureScheme> core::fmt::Debug for HybridError<A, B> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            HybridError::Primary(e) => write!(f, "primary scheme error: {:?}", e),
            HybridError::Secondary(e) => write!(f, "secondary scheme error: {:?}", e),
        }
    }
}

impl<A: SignatureScheme, B: SignatureScheme> core::fmt::Display for HybridError<A, B> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            HybridError::Primary(e) => write!(f, "primary scheme error: {}", e),
            HybridError::Secondary(e) => write!(f, "secondary scheme error: {}", e),
        }
    }
}

impl<A: SignatureScheme, B: SignatureScheme> std::error::Error for HybridError<A, B> {}

/// Zero-sized marker type selecting the pair of schemes `A` and `B` to
/// combine. Construct nothing; call the associated functions directly,
/// e.g. `Hybrid::<MlDsa44, MlDsa44>::keypair()`.
pub struct Hybrid<A, B>(core::marker::PhantomData<(A, B)>);

impl<A: SignatureScheme, B: SignatureScheme> Hybrid<A, B> {
    pub fn keypair() -> Result<(HybridPublicKey<A, B>, HybridSecretKey<A, B>), HybridError<A, B>> {
        let (pa, sa) = A::keypair().map_err(HybridError::Primary)?;
        let (pb, sb) = B::keypair().map_err(HybridError::Secondary)?;
        Ok((
            HybridPublicKey { primary: pa, secondary: pb },
            HybridSecretKey { primary: sa, secondary: sb },
        ))
    }

    pub fn sign(
        sk: &HybridSecretKey<A, B>,
        msg: &[u8],
    ) -> Result<HybridSignature<A, B>, HybridError<A, B>> {
        let sa = A::sign(&sk.primary, msg).map_err(HybridError::Primary)?;
        let sb = B::sign(&sk.secondary, msg).map_err(HybridError::Secondary)?;
        Ok(HybridSignature { primary: sa, secondary: sb })
    }

    /// Verifies successfully only if **both** signatures verify. A failure
    /// (or error) from either scheme fails the whole hybrid signature.
    pub fn verify(
        pk: &HybridPublicKey<A, B>,
        msg: &[u8],
        sig: &HybridSignature<A, B>,
    ) -> Result<bool, HybridError<A, B>> {
        let va = A::verify(&pk.primary, msg, &sig.primary).map_err(HybridError::Primary)?;
        let vb = B::verify(&pk.secondary, msg, &sig.secondary).map_err(HybridError::Secondary)?;
        Ok(va && vb)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MlDsa44;

    // No second algorithm is wired in yet, but the combinator itself is
    // algorithm-agnostic — pairing ML-DSA-44 with itself here exercises the
    // exact same code path a real ML-DSA + classical hybrid would use.
    type DemoHybrid = Hybrid<MlDsa44, MlDsa44>;

    #[test]
    fn hybrid_sign_verify_roundtrip() {
        let (pk, sk) = DemoHybrid::keypair().unwrap();
        let msg = b"hybrid signature demo";
        let sig = DemoHybrid::sign(&sk, msg).unwrap();
        assert!(DemoHybrid::verify(&pk, msg, &sig).unwrap());
    }

    #[test]
    fn hybrid_rejects_if_either_fails() {
        let (pk, sk) = DemoHybrid::keypair().unwrap();
        let sig = DemoHybrid::sign(&sk, b"a").unwrap();
        assert!(!DemoHybrid::verify(&pk, b"b", &sig).unwrap());
    }
}
