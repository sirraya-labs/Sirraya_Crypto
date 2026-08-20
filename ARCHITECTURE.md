# sirraya-crypto — Architecture

This document explains how `sirraya-crypto` is put together, why it's shaped
this way, and — most importantly — exactly what to touch (and what never to
touch) when extending it. If you're adding a parameter set, a new
algorithm family, or a CLI feature, the relevant section below tells you
the full list of files involved.

If something here goes stale as the crate evolves, fix the doc in the same
PR that breaks it. This file is meant to be trustworthy, not aspirational.

## 1. What this crate is

Post-quantum and hybrid digital signatures, built around FIPS 204
(ML-DSA — the NIST-standardized lattice signature scheme, formerly
CRYSTALS-Dilithium). Today it implements ML-DSA-44 and ML-DSA-65, plus a
generic two-scheme "hybrid" combinator for the PQC-transition pattern
(sign with both a classical and a post-quantum scheme; only accept if
both verify).

Two optional feature flags (`w3c`, `masking`) extend this toward
Verifiable Credentials and side-channel-hardened signing respectively —
see §9. This document focuses on the core signature engine, which is
what every feature builds on.

## 2. Design principle: split by what varies, not by what's convenient

FIPS 204 defines three parameter sets (ML-DSA-44/65/87). A large fraction
of the specification — the ring `R_q = Z_q[x]/(x^n+1)`, the NTT, the
zeta table — is **identical across every one of them**. Only a handful of
values (K, L, η, τ, γ₁, γ₂, ω, λ) and everything derived from them
actually change per level.

The crate's module boundaries follow that split exactly, not the more
obvious "one folder per algorithm" boundary:

```
src/
├── lib.rs                    crate root, re-exports
├── traits.rs                 SignatureScheme — the crypto-agility contract
├── hybrid.rs                 Hybrid<A, B> — generic "both must verify" composition
├── common/
│   ├── mod.rs
│   └── ring.rs                parameter-INVARIANT math (N, Q, D, NTT, SHAKE, zeroize)
└── dsa/
    ├── mod.rs                 one submodule per algorithm family
    └── ml_dsa/
        ├── mod.rs             family root; explains how to add a parameter set
        ├── core.rs             the ENTIRE ML-DSA algorithm, generic over a
        │                       constants module — KeyGen/Sign/Verify, packing,
        │                       sampling, the ml_dsa_impl! macro
        ├── ml_dsa_44/
        │   ├── mod.rs          one macro invocation
        │   └── constants.rs    K=4, L=4, η=2, τ=39, γ₁=2^17, γ₂=(q-1)/88, ...
        └── ml_dsa_65/
            ├── mod.rs          one macro invocation
            └── constants.rs    K=6, L=5, η=4, τ=49, γ₁=2^19, γ₂=(q-1)/32, ...
```

The consequence: adding ML-DSA-87 touches exactly two new files (a
`constants.rs` and a one-line `mod.rs`) plus one line each in
`dsa/ml_dsa/mod.rs` and `lib.rs`. It does **not** touch `common::ring`,
`core.rs`, `traits.rs`, or `hybrid.rs`. §7 walks through this precisely.

## 3. `traits.rs` — the crypto-agility contract

```rust
pub trait SignatureScheme {
    type PublicKey: AsRef<[u8]>;
    type SecretKey: AsRef<[u8]> + AsMut<[u8]>;
    type Signature: AsRef<[u8]>;
    type Error: core::fmt::Debug + core::fmt::Display;

    const NAME: &'static str;
    const PUBLIC_KEY_LEN: usize;
    const SECRET_KEY_LEN: usize;
    const SIGNATURE_LEN: usize;
    const SEED_LEN: usize;

    fn keypair() -> Result<(Self::PublicKey, Self::SecretKey), Self::Error>;
    fn keypair_from_seed(seed: &[u8]) -> Result<(Self::PublicKey, Self::SecretKey), Self::Error>;
    fn sign(sk: &Self::SecretKey, msg: &[u8]) -> Result<Self::Signature, Self::Error>;
    fn verify(pk: &Self::PublicKey, msg: &[u8], sig: &Self::Signature) -> Result<bool, Self::Error>;

    fn public_key_from_bytes(bytes: &[u8]) -> Option<Self::PublicKey>;
    fn secret_key_from_bytes(bytes: &[u8]) -> Option<Self::SecretKey>;
    fn signature_from_bytes(bytes: &[u8]) -> Option<Self::Signature>;
}
```

Every algorithm in this crate implements this once. Generic code — the
CLI, `hybrid.rs`, anything you write — is written against `T:
SignatureScheme` instead of a concrete type, so it works unmodified for
every current and future implementor.

**Why associated types instead of one flat `[u8; N]`?** Stable Rust
can't express an array length like `K * POLYZ_PACKEDBYTES` from a const
generic parameter (that needs the unstable `generic_const_exprs`
feature). So each concrete scheme fixes its own array sizes as associated
types, and the trait only requires they can be viewed as bytes.

**Why the `*_from_bytes` methods, specifically?** `AsRef<[u8]>` lets
generic code read key/signature bytes *out*. It doesn't let generic code
build the opaque associated type back *from* bytes read off disk, the
CLI, or the wire — there's no `From<&[u8]>` bound. Without
`public_key_from_bytes` etc., a CLI can print a hex-encoded key
generically but can't *parse* one back generically; you'd need one
hand-written parsing path per concrete type. These three methods are what
let `main.rs`'s `keygen`/`sign`/`verify` be written exactly once and
dispatched over `--alg` (see §8).

**Why does `keypair_from_seed` take `seed: &[u8]` rather than `&[u8;
SEED_LEN]`?** `SEED_LEN` is an associated const, not a compile-time
generic parameter usable in a fixed-size array type in the trait
signature. The macro-generated implementation validates the length and
converts internally (`seed.try_into()`), returning `Self::Error` on
mismatch rather than panicking.

## 4. `common::ring` — parameter-invariant math

Holds exactly what FIPS 204 fixes identically across every ML-DSA
security level: `N=256`, `Q=8380417`, `D=13`, the `ZETAS` table, forward/
inverse NTT (Algorithms 41/42), Montgomery reduction, the SHAKE128/256
wrappers, and `zeroize_bytes` (volatile-write zeroization for secret
buffers).

**Rule for this module: if a value or function's correctness depends on
K, L, η, τ, γ₁, γ₂, ω, or λ, it does not belong here.** It belongs in
`core.rs`, parameterized by whichever `constants` module is in scope (see
§5). This module existing at all is what let ML-DSA-65 reuse the NTT,
zeta table, and SHAKE wrappers completely unchanged — zero risk of a
second, subtly different copy of that math drifting out of sync.

## 5. `dsa/ml_dsa/core.rs` — the shared algorithm engine

This is where KeyGen, Sign, Verify, and every parameter-*dependent*
routine (packing, rejection sampling, hint generation, decompose) live —
written once, and stamped out per parameter set by the `ml_dsa_impl!`
macro. `ml_dsa_44/mod.rs` and `ml_dsa_65/mod.rs` are each a single
invocation:

```rust
crate::dsa::ml_dsa::core::ml_dsa_impl!(MlDsa65, crate::dsa::ml_dsa::ml_dsa_65::constants);
```

The macro brings the variant's `constants` module into scope (`use
$consts::*;`), which is how the same code becomes correct for different
K/L/η/γ₁/γ₂ without duplication — array sizes, loop bounds, and buffer
lengths all come from whichever constants module the invocation points
at.

### 5.1 Generic bit-packing (important — read this before touching packing code)

FIPS 204's `BitPack`/`SimpleBitPack` routines (Algorithms 24, 26, 28) all
do the same thing at different bit-widths: pack N=256 coefficients
sequentially, LSB-first, at some constant bits-per-coefficient. That
width differs by field and parameter set — η=2 needs 3 bits, η=4 needs 4;
γ₁=2^17 needs 18 bits, γ₁=2^19 needs 20; γ₂=(q-1)/88 needs 6 bits,
γ₂=(q-1)/32 needs 4 — **but it is always exactly `PACKEDBYTES * 8 / N`**
for whichever `*_PACKEDBYTES` constant governs that field, and those
constants are already correct per parameter set in each variant's
`constants.rs`.

`polyeta_pack`/`unpack`, `polyz_pack`/`unpack`, and `polyw1_pack` are
built on two small generic helpers, `bitpack_coeffs`/`bitunpack_coeffs`,
that take the bit-width as a parameter derived from the relevant
`*_PACKEDBYTES` constant:

```rust
const BITS: u32 = (POLYETA_PACKEDBYTES * 8 / N) as u32;
```

**This replaced an earlier version of this code that hand-unrolled fixed
bit-shifts for ML-DSA-44's specific widths only** (3/18/6 bits) — it
compiled and passed ML-DSA-44's own tests, but would have silently
produced cryptographically wrong output for any parameter set with
different η/γ₁/γ₂, because the bit-widths were literals, not derived
from the per-variant constants that already existed. If you're adding a
fourth parameter set and these functions look like they need per-variant
special-casing again, they shouldn't — check whether the relevant
`*_PACKEDBYTES` constant is actually correct in that variant's
`constants.rs` first.

`rej_bounded_poly` (Algorithm 31, `CoeffFromHalfByte`) is the one
routine that's a genuine algorithmic branch, not just a bit-width change
— FIPS 204 defines a different formula for η=2 (`mod 5`, reject ≥ 15)
than for η=4 (plain subtraction, reject ≥ 9). It branches explicitly on
`ETA` (`coeff_from_half_byte`) rather than pretending one formula covers
both; only η=2 and η=4 appear across ML-DSA-44/65/87, so the branch is
exhaustive and the dead arm compiles away per-variant.

`expand_mask_poly` (Algorithm 34) turned out to implement the exact same
bit-packing as `polyz_unpack` — it now squeezes the XOF into a
`POLYZ_PACKEDBYTES` buffer and calls `polyz_unpack` directly instead of
carrying a second, independently-hand-rolled copy of that logic.

### 5.2 Error type

```rust
pub enum MlDsaError {
    RngFailed,
    InvalidPublicKeyLength,
    InvalidSecretKeyLength,
    InvalidSignatureLength,
    InvalidSeedLength,
    MalformedSignature,
    VerificationFailed,
}
```

`Display` is matched exhaustively — if you add a variant, the compiler
will catch the missing arm. This is the one place a `match` on this enum
exists today; grep for `MlDsaError::` before assuming otherwise.

## 6. `hybrid.rs` — generic composition

```rust
pub struct Hybrid<A, B>(PhantomData<(A, B)>);
impl<A: SignatureScheme, B: SignatureScheme> Hybrid<A, B> {
    pub fn keypair() -> Result<(HybridPublicKey<A, B>, HybridSecretKey<A, B>), HybridError<A, B>>;
    pub fn sign(...) -> Result<HybridSignature<A, B>, HybridError<A, B>>;
    pub fn verify(...) -> Result<bool, HybridError<A, B>>;   // true only if BOTH verify
}
```

Generic over *any* two `SignatureScheme` implementors — it has no idea
whether `A` and `B` are both ML-DSA variants or one classical + one
post-quantum. The test suite currently exercises `Hybrid<MlDsa44,
MlDsa44>` purely because there's no classical scheme implemented yet to
pair with; the combinator itself has no ML-DSA-specific code, so
`Hybrid<MlDsa44, MlDsa65>` or `Hybrid<MlDsa65, Ed25519>` (once an
`Ed25519: SignatureScheme` impl exists) work with zero changes here.

## 7. Adding a new ML-DSA parameter set (e.g. ML-DSA-87)

This is copy-pasted from `dsa/ml_dsa/mod.rs`'s own doc comment —
treat that comment as the canonical source and this section as backup:

1. Create `ml_dsa_87/constants.rs`: copy `ml_dsa_44/constants.rs` (or
   `ml_dsa_65/constants.rs`), update K, L, ETA, TAU, GAMMA1, GAMMA2,
   OMEGA, LAMBDA and the derived byte sizes from FIPS 204 Table 1/2.
   Keep `pub use crate::common::ring::{N, Q, D, QINV, MONT, ZETAS};`
   as-is — those never change. **Double-check `POLYETA_PACKEDBYTES`,
   `POLYZ_PACKEDBYTES`, and `POLYW1_PACKEDBYTES`** — these three drive
   the generic bit-packer's width (§5.1), so an error here is a silent
   correctness bug, not a compile error.
2. Create `ml_dsa_87/mod.rs`:
   ```rust
   pub mod constants;
   crate::dsa::ml_dsa::core::ml_dsa_impl!(MlDsa87, crate::dsa::ml_dsa::ml_dsa_87::constants);
   ```
3. Add `pub mod ml_dsa_87;` and `pub use ml_dsa_87::MlDsa87;` to
   `dsa/ml_dsa/mod.rs`.
4. Optionally, `pub use dsa::ml_dsa::MlDsa87;` in `lib.rs` for a
   crate-root re-export, matching `MlDsa44`/`MlDsa65`.
5. If it should be reachable from the CLI: add `Algorithm::MlDsa87` and
   one match arm in `main.rs`'s `Algorithm::parse` and `main`'s
   dispatch — see §8.
6. **Verify against the FIPS 204 / ACVP known-answer test vectors**, not
   just internal roundtrip tests (see §10 — this is a known gap even for
   ML-DSA-65 today).

Nothing about ML-DSA-44 or ML-DSA-65 has to change, and nothing else in
the crate needs to know ML-DSA-87 exists until something opts into using
it.

## 8. Adding a new algorithm family (e.g. SLH-DSA)

A different signature algorithm family (hash-based SLH-DSA, or a
classical scheme like Ed25519 for real hybrid pairing) is a new top-level
module beside `dsa::ml_dsa`:

```
src/dsa/
├── ml_dsa/       (existing)
└── slh_dsa/      (new)
```

It implements `SignatureScheme` on its own terms — there's no obligation
to reuse `common::ring` unless the math genuinely overlaps (it won't, for
a hash-based scheme). Add `pub mod slh_dsa;` to `dsa/mod.rs`. The moment
`impl SignatureScheme for SlhDsaSomething` exists, `Hybrid<MlDsa65,
SlhDsaSomething>` and the CLI's generic `cmd_*<T>` functions work with it
unmodified.

## 9. Feature flags

Declared in `Cargo.toml`, not yet documented in depth here because their
implementation hasn't been reviewed as part of this document's authoring
— treat this section as a map of *what exists*, not a guarantee of *how
it's built*:

- **`std`** (default) — presumably gates `std`-only code paths in favor
  of eventual `no_std` support. Confirm what it actually gates before
  relying on `no_std` compatibility.
- **`masking`** — side-channel hardening (masked implementations), per
  the crate description. Not covered by this document; read the
  masking module's own doc comments before extending it.
- **`w3c`** — Verifiable Credentials support (`serde`, `base64`, `uuid`,
  `chrono`, `multibase` become active). Also not covered here.

If you work on either feature, please add a `§9.x` section here
summarizing its design the way §3–§7 do for the core signature engine —
that's the standard this file is trying to hold to.

## 10. Testing

`ml_dsa_impl!` generates a `#[cfg(test)] mod tests` block per invocation,
so `ml_dsa_44::tests::*` and `ml_dsa_65::tests::*` are two independently
compiled, independently run copies of the same roundtrip test suite:
`eta_roundtrip`, `z_roundtrip`, `t0_roundtrip`, `t1_roundtrip`,
`ntt_roundtrip_*`, `sign_verify`, `sign_verify_deterministic`,
`deterministic_keygen`, `reject_wrong_msg`, `reject_tampered_sig`,
`many_roundtrips`. `hybrid::tests` covers the combinator separately.
`cargo test` runs all of it — 28 tests as of ML-DSA-44 + ML-DSA-65.

**What these tests actually prove:** that packing a value and unpacking
it returns the same value, and that sign→verify round-trips and rejects
tampering. **What they do not prove:** that the wire encoding matches
the FIPS 204 spec's exact byte layout, or that this implementation
produces the same output as the reference implementation on a given
input. A self-consistent bug (e.g. every function agreeing on a wrong bit
layout) would pass every test in this suite.

**Known gap:** neither ML-DSA-44 nor ML-DSA-65 has been checked against
the official NIST ACVP or reference-implementation known-answer test
vectors. Before trusting this for anything beyond internal testing,
pull the FIPS 204 ACVP vectors and add a KAT test per variant that feeds
a known seed/message through `keypair_from_seed` → `sign_deterministic`
→ `verify` and asserts against the published expected bytes.

## 11. `main.rs` — CLI

Every subcommand (`keygen`, `sign`, `verify`, `test`) is written once as
`fn cmd_x<T: SignatureScheme>(...)`. `main()` parses `--alg
ml-dsa-44|ml-dsa-65` (default `ml-dsa-44`) out of the argument list
first, then monomorphizes over the concrete type:

```rust
match alg {
    Algorithm::MlDsa44 => run::<MlDsa44>(&args),
    Algorithm::MlDsa65 => run::<MlDsa65>(&args),
}
```

Adding a new algorithm to the CLI is one `Algorithm` enum variant and one
match arm — the command logic itself never changes.

Security-relevant behavior baked into the CLI (see the file's own header
comment for the reasoning): `sign --sk <hex>` is deprecated in favor of
`--sk-file <path>` because argv is visible via `ps`/`/proc` and lands in
shell history; `keygen` doesn't print the secret key to stdout unless
`--show-secret` is passed; `--save` writes `sk.bin` at `0600` on Unix;
every secret buffer this file touches (`sk`, decoded hex/seed bytes) is
zeroized via `common::ring::zeroize_bytes` once no longer needed.

## 12. Backward compatibility

None, deliberately. This crate has not been published yet, so there is
exactly one API surface — the module paths described above. An earlier
draft carried a flat re-export layer (`mldsa44`, `constants_44`,
`polynomial` at the crate root) to preserve a pre-refactor API; that was
removed once it was confirmed nothing depends on it. If you're reading
this after the crate has shipped a `0.1.0` to crates.io, that calculus
changes — check whether removing/renaming a public path needs a semver
bump before doing it.

## 13. Contributing checklist

Before opening a PR that touches `core.rs`, `common/ring.rs`, or
`traits.rs`:

- [ ] Does `cargo test` still pass for **every** existing variant, not
      just the one you're working on?
- [ ] If you changed a packing/sampling routine, does it still derive
      its bit-width/behavior from the constants module rather than a
      literal? (§5.1 explains why this matters — it's the exact bug
      class this crate has already hit once.)
- [ ] If you added a parameter set, did you sanity-check the derived
      sizes (`PUBLICKEYBYTES`, `SECRETKEYBYTES`, `SIGNBYTES`) against
      FIPS 204 Table 2's published values before trusting the build?
- [ ] If you touched `traits.rs`, did you check for exhaustive `match`
      statements on error enums or trait objects elsewhere that a new
      variant/method could silently need updating?
- [ ] Does the relevant section of this file still describe what you
      built, or does it need a paragraph updated?
