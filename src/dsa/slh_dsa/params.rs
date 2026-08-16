//! FIPS 205 Table 2 parameter sets.
//!
//! Deliberately a runtime struct, not six copy-pasted `constants.rs` files
//! like `dsa::ml_dsa` uses. That macro-per-variant pattern is exactly what
//! produced the ML-DSA-44/ML-DSA-65 constants mix-up (see ARCHITECTURE.md
//! §13 / README "Contributing") — six independent files that must all stay
//! in sync by hand. SLH-DSA has *more* parameters per set (n, h, d, a, k)
//! than ML-DSA (K, L, ETA, TAU, GAMMA1, GAMMA2, OMEGA, LAMBDA), so the same
//! failure mode is even more likely here. Instead, every SHAKE parameter
//! set is one `SlhDsaParams` value below, checked against Table 2 by
//! reconstructing `m`, `pk_bytes`, and `sig_bytes` from the five primitive
//! fields and asserting they match NIST's published numbers (see the test
//! at the bottom of this file) — the crypto engine (`super::core` and
//! friends) never duplicates per-variant logic, only reads these fields.
//!
//! Only the SHAKE instantiation (§11.1) is implemented. The SHA2
//! instantiation (§11.2, six more parameter sets, a *different* address
//! compression scheme, and MGF1/HMAC-SHA2 in place of SHAKE256) is a
//! separate, non-trivial follow-up — see `dsa::slh_dsa` module docs.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SlhDsaParams {
    /// Human-readable name, e.g. "SLH-DSA-SHAKE-128s".
    pub name: &'static str,
    /// Security parameter (bytes) — length of hash outputs, key material.
    pub n: usize,
    /// Total hypertree height.
    pub h: usize,
    /// Number of hypertree layers.
    pub d: usize,
    /// FORS: height of each of the k FORS trees (t = 2^a).
    pub a: usize,
    /// FORS: number of trees.
    pub k: usize,
    /// NIST security category (1, 3, or 5).
    pub security_category: u8,
}

impl SlhDsaParams {
    /// h' = h/d: height of each individual XMSS tree in the hypertree.
    /// FIPS 205 §7 requires this to divide evenly; every Table 2 entry does.
    pub const fn hp(&self) -> usize {
        self.h / self.d
    }

    /// WOTS+ len = len1 + len2, with lgw = 4 fixed for every parameter set
    /// in this standard (§5, "lgw is 4 for all parameter sets in this
    /// standard"): len1 = ceil(8n/4) = 2n, len2 = 3 (per the worked example
    /// in §3.2 for lgw=4).
    pub const fn wots_len(&self) -> usize {
        2 * self.n + 3
    }

    /// Message digest length `m` (§9, unnumbered equation before §9.1):
    /// m = ceil((h-h')/8) + ceil(k*a/8) + ceil(h'/8).
    pub const fn m(&self) -> usize {
        ceil_div(self.h - self.hp(), 8) + ceil_div(self.k * self.a, 8) + ceil_div(self.hp(), 8)
    }

    /// Public key size: 2n bytes (Figure 16: PK.seed || PK.root).
    pub const fn pk_bytes(&self) -> usize {
        2 * self.n
    }

    /// Private key size: 4n bytes (Figure 15: SK.seed||SK.prf||PK.seed||PK.root).
    pub const fn sk_bytes(&self) -> usize {
        4 * self.n
    }

    /// Signature size (Figure 17 + §7 + §5.2):
    /// n (R) + k(1+a)n (FORS) + (h + d*len)n (HT, §7.1).
    pub const fn sig_bytes(&self) -> usize {
        (1 + self.k * (1 + self.a) + self.h + self.d * self.wots_len()) * self.n
    }
}

pub const fn ceil_div(a: usize, b: usize) -> usize {
    (a + b - 1) / b
}

// FIPS 205 Table 2, SHAKE rows only (SHA2 rows share the same n/h/d/a/k —
// only the hash instantiation in §11 differs — so these values cover both;
// only the SHAKE hash wiring is implemented, see module docs).

pub const SLH_DSA_SHAKE_128S: SlhDsaParams = SlhDsaParams {
    name: "SLH-DSA-SHAKE-128s",
    n: 16,
    h: 63,
    d: 7,
    a: 12,
    k: 14,
    security_category: 1,
};

pub const SLH_DSA_SHAKE_128F: SlhDsaParams = SlhDsaParams {
    name: "SLH-DSA-SHAKE-128f",
    n: 16,
    h: 66,
    d: 22,
    a: 6,
    k: 33,
    security_category: 1,
};

pub const SLH_DSA_SHAKE_192S: SlhDsaParams = SlhDsaParams {
    name: "SLH-DSA-SHAKE-192s",
    n: 24,
    h: 63,
    d: 7,
    a: 14,
    k: 17,
    security_category: 3,
};

pub const SLH_DSA_SHAKE_192F: SlhDsaParams = SlhDsaParams {
    name: "SLH-DSA-SHAKE-192f",
    n: 24,
    h: 66,
    d: 22,
    a: 8,
    k: 33,
    security_category: 3,
};

pub const SLH_DSA_SHAKE_256S: SlhDsaParams = SlhDsaParams {
    name: "SLH-DSA-SHAKE-256s",
    n: 32,
    h: 64,
    d: 8,
    a: 14,
    k: 22,
    security_category: 5,
};

pub const SLH_DSA_SHAKE_256F: SlhDsaParams = SlhDsaParams {
    name: "SLH-DSA-SHAKE-256f",
    n: 32,
    h: 68,
    d: 17,
    a: 9,
    k: 35,
    security_category: 5,
};

#[cfg(test)]
mod tests {
    use super::*;

    // Every (m, pk_bytes, sig_bytes) triple below is copied verbatim from
    // FIPS 205 Table 2. This test exists specifically to catch a transcription
    // error in n/h/d/a/k before it can propagate anywhere else.
    fn check(p: &SlhDsaParams, hp: usize, m: usize, pk_bytes: usize, sig_bytes: usize) {
        assert_eq!(p.hp(), hp, "{}: h'", p.name);
        assert_eq!(p.m(), m, "{}: m", p.name);
        assert_eq!(p.pk_bytes(), pk_bytes, "{}: pk_bytes", p.name);
        assert_eq!(p.sk_bytes(), pk_bytes * 2, "{}: sk_bytes", p.name);
        assert_eq!(p.sig_bytes(), sig_bytes, "{}: sig_bytes", p.name);
    }

    #[test]
    fn table_2_shake_128s() {
        check(&SLH_DSA_SHAKE_128S, 9, 30, 32, 7856);
    }
    #[test]
    fn table_2_shake_128f() {
        check(&SLH_DSA_SHAKE_128F, 3, 34, 32, 17088);
    }
    #[test]
    fn table_2_shake_192s() {
        check(&SLH_DSA_SHAKE_192S, 9, 39, 48, 16224);
    }
    #[test]
    fn table_2_shake_192f() {
        check(&SLH_DSA_SHAKE_192F, 3, 42, 48, 35664);
    }
    #[test]
    fn table_2_shake_256s() {
        check(&SLH_DSA_SHAKE_256S, 8, 47, 64, 29792);
    }
    #[test]
    fn table_2_shake_256f() {
        check(&SLH_DSA_SHAKE_256F, 4, 49, 64, 49856);
    }
}
