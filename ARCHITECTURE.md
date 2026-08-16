# sirraya-crypto — Architecture

This document explains how `sirraya-crypto` is put together, why it's shaped
this way, and — most importantly — exactly what to touch (and what never to
touch) when extending it. If you're adding a parameter set, a new
algorithm family, or a CLI feature, the relevant section below tells you
the full list of files involved.

If something here goes stale as the crate evolves, fix the doc in the same
PR that breaks it. This file is meant to be trustworthy, not aspirational.

## 1. What this crate is

Post-quantum and hybrid digital signatures, built around two
NIST-standardized families:

- **ML-DSA** (FIPS 204, Module-Lattice-Based, formerly CRYSTALS-Dilithium)
  — ML-DSA-44 and ML-DSA-65 implemented, ACVP KAT-verified (§14).
- **SLH-DSA** (FIPS 205, Stateless Hash-Based, formerly SPHINCS+) — all
  12 approved parameter sets implemented (six SHAKE, six SHA2; pure and
  pre-hash signing interfaces), internal round-trip tested but **not yet
  ACVP-verified** (§14).

Plus a generic two-scheme "hybrid" combinator for the PQC-transition
pattern (sign with both a classical and a post-quantum scheme, or two
post-quantum schemes resting on different hardness assumptions; only
accept if both verify), which works across both families with zero
family-specific code.

Two optional feature flags (`w3c`, `masking`) extend this toward
Verifiable Credentials and side-channel-hardened signing respectively —
see §11. This document focuses on the core signature engines, which is
what every feature builds on.

## 2. Design principle: split by what varies, not by what's convenient

FIPS 204 defines three parameter sets (ML-DSA-44/65/87). A large fraction
of the specification — the ring `R_q = Z_q[x]/(x^n+1)`, the NTT, the
zeta table — is **identical across every one of them**. Only a handful of
values (K, L, η, τ, γ₁, γ₂, ω, λ) and everything derived from them
actually change per level. ML-DSA's module boundaries follow that split
exactly.

FIPS 205 has a *different* shape entirely: no shared ring arithmetic at
all (it's hash-based, not lattice-based), but instead a shared
**addressing scheme** and **six abstract hash functions** whose concrete
instantiation (SHAKE vs. SHA2) is orthogonal to every tree/signature
algorithm built on top of them. §8 explains why SLH-DSA's split is
therefore a `HashSuite` trait, not ML-DSA's per-variant `constants.rs`
macro pattern — same underlying principle ("split by what varies"),
different mechanism because what varies is structurally different.

```
src/
├── lib.rs                    crate root, re-exports
├── traits.rs                 SignatureScheme — the crypto-agility contract
├── hybrid.rs                 Hybrid<A, B> — generic "both must verify" composition
├── common/
│   ├── mod.rs
│   └── ring.rs                parameter-INVARIANT math (N, Q, D, NTT, SHAKE, zeroize)
│                               — ML-DSA only; SLH-DSA has no equivalent, see §8
└── dsa/
    ├── mod.rs                 one submodule per algorithm family
    ├── ml_dsa/
    │   ├── mod.rs             family root; explains how to add a parameter set
    │   ├── core.rs             the ENTIRE ML-DSA algorithm, generic over a
    │   │                       constants module — KeyGen/Sign/Verify, packing,
    │   │                       sampling, the ml_dsa_impl! macro
    │   ├── ml_dsa_44/
    │   │   ├── mod.rs          one macro invocation
    │   │   └── constants.rs    K=4, L=4, η=2, τ=39, γ₁=2^17, γ₂=(q-1)/88, ...
    │   └── ml_dsa_65/
    │       ├── mod.rs          one macro invocation
    │       └── constants.rs    K=6, L=5, η=4, τ=49, γ₁=2^19, γ₂=(q-1)/32, ...
    └── slh_dsa/
        ├── mod.rs             family root + the slh_dsa_variant! macro (12 invocations)
        ├── params.rs           SlhDsaParams struct + all 12 Table 2 parameter sets
        ├── adrs.rs             the 32-byte ADRS structure (§4.2) + Table 3 compression
        ├── hash_suite.rs       HashSuite trait + ShakeSuite (§11.1)
        ├── sha2_suite.rs       Sha2Suite (§11.2) — MGF1, HMAC, the two SHA2 sub-cases
        ├── util.rs             base_2b, toInt, toByte (§4.4) — suite-independent
        ├── wots.rs             WOTS+ (§5), generic over HashSuite
        ├── xmss.rs             XMSS (§6), generic over HashSuite
        ├── ht.rs                hypertree (§7), generic over HashSuite
        ├── fors.rs             FORS (§8), generic over HashSuite
        ├── core.rs             internal + external "pure" functions (§9, §10.1-10.3)
        └── prehash.rs          HashSLH-DSA pre-hash signing (§10.2.2, Algorithms 23/25)
```

The consequence for ML-DSA: adding ML-DSA-87 touches exactly two new
files (a `constants.rs` and a one-line `mod.rs`) plus one line each in
`dsa/ml_dsa/mod.rs` and `lib.rs`. It does **not** touch `common::ring`,
`core.rs`, `traits.rs`, or `hybrid.rs`. §7 walks through this precisely.

The consequence for SLH-DSA: adding a 13th parameter set (if NIST ever
approves one) touches exactly one new `SlhDsaParams` value in `params.rs`
and one new `slh_dsa_variant!` invocation in `mod.rs`. It does **not**
touch `wots.rs`, `xmss.rs`, `ht.rs`, `fors.rs`, `core.rs`, `hash_suite.rs`,
or `sha2_suite.rs`. §9 walks through this precisely.

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

Every algorithm in this crate implements this once — ML-DSA-44/65 and all
12 SLH-DSA parameter sets alike. Generic code — the CLI, `hybrid.rs`,
anything you write — is written against `T: SignatureScheme` instead of a
concrete type, so it works unmodified for every current and future
implementor, in either family.

**Why associated types instead of one flat `[u8; N]`?** Stable Rust
can't express an array length like `K * POLYZ_PACKEDBYTES` (ML-DSA) or
`k * (1 + a) * n` (SLH-DSA's signature length) from a const generic
parameter (that needs the unstable `generic_const_exprs` feature). So
each concrete scheme fixes its own array sizes as associated types, and
the trait only requires they can be viewed as bytes.

**Why the `*_from_bytes` methods, specifically?** `AsRef<[u8]>` lets
generic code read key/signature bytes *out*. It doesn't let generic code
build the opaque associated type back *from* bytes read off disk, the
CLI, or the wire — there's no `From<&[u8]>` bound. Without
`public_key_from_bytes` etc., a CLI can print a hex-encoded key
generically but can't *parse* one back generically; you'd need one
hand-written parsing path per concrete type. These three methods are what
let `main.rs`'s `keygen`/`sign`/`verify` be written exactly once and
dispatched over `--alg` (see §12) — today only for ML-DSA (SLH-DSA isn't
wired into the CLI yet, see §12).

**Why does `keypair_from_seed` take `seed: &[u8]` rather than `&[u8;
SEED_LEN]`?** `SEED_LEN` is an associated const, not a compile-time
generic parameter usable in a fixed-size array type in the trait
signature. Each implementation validates the length and converts
internally (`seed.try_into()`), returning `Self::Error` on mismatch
rather than panicking. Note `SEED_LEN` means something structurally
different per family: for ML-DSA it's one seed of `SEEDBYTES`; for
SLH-DSA it's **three independent n-byte seeds concatenated**
(SK.seed || SK.prf || PK.seed, FIPS 205 Figure 15) — `SlhDsaParams::n *
3`, not `n`. See §8.

**What the trait deliberately does *not* cover:** SLH-DSA's pre-hash
interface (`sign_prehash`/`verify_prehash`, needing a `PH` selection) and
context-string support (`ctx: &[u8]`, which SLH-DSA's `sign`/`verify`
take but this trait's `sign`/`verify` don't) live as inherent methods on
each concrete `SlhDsa*` type instead, not on `SignatureScheme` itself —
adding either to the trait would force every ML-DSA implementor to grow a
parameter it doesn't need (ML-DSA's own pre-hash/HashML-DSA variant isn't
implemented at all — see the README's ML-DSA Testing section). If a
second algorithm family needs pre-hash or context strings, revisit
whether these belong on the trait at that point.

## 4. `common::ring` — parameter-invariant math (ML-DSA only)

Holds exactly what FIPS 204 fixes identically across every ML-DSA
security level: `N=256`, `Q=8380417`, `D=13`, the `ZETAS` table, forward/
inverse NTT (Algorithms 41/42), Montgomery reduction, the SHAKE128/256
wrappers, and `zeroize_bytes` (volatile-write zeroization for secret
buffers).

**Rule for this module: if a value or function's correctness depends on
K, L, η, τ, γ₁, γ₂, ω, or λ, it does not belong here.** It belongs in
`ml_dsa/core.rs`, parameterized by whichever `constants` module is in
scope (see §5). This module existing at all is what let ML-DSA-65 reuse
the NTT, zeta table, and SHAKE wrappers completely unchanged — zero risk
of a second, subtly different copy of that math drifting out of sync.

This module has **no SLH-DSA equivalent** — SLH-DSA's parameter-invariant
material (the `Adrs` addressing scheme, `base_2b`/`toInt`/`toByte`) lives
in `dsa/slh_dsa/adrs.rs` and `dsa/slh_dsa/util.rs` instead, inside the
family's own directory rather than a shared `common/` module, because
none of it is shared *with ML-DSA* — only within SLH-DSA itself. `common/`
is for math genuinely shared *across families*; nothing currently is.

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

**This is also exactly the mechanism that produced the ML-DSA-44/65 bug
that motivated §8's very different design for SLH-DSA** (see §13/§16):
`ml_dsa_44/constants.rs` was, for one published release, a byte-for-byte
copy of `ml_dsa_65/constants.rs`. The macro pattern itself isn't at
fault — it did exactly what it was told, correctly, for whichever
constants module was in scope — but *six independent hand-maintained
files that must all agree with FIPS 204's tables* is a design that makes
that specific mistake easy to make and easy to miss (every routine stays
internally self-consistent, so round-trip tests still pass). ML-DSA's
ACVP KAT pass (§14) is what actually caught it. Keep this in mind if
you're using this section as a template for a *third* macro-per-variant
family — §8 explains the alternative and why SLH-DSA uses it instead.

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

### 5.3 Known gap: no context-string support

`sign()`/`sign_deterministic()`/`verify()` hard-code an empty FIPS 204
context string internally (`mp.push(0u8); mp.push(0u8);` with no `ctx`
bytes at all) — there is currently no way to sign or verify with a
context string through ML-DSA's public API. `sign_internal`/
`verify_internal` are public and do accept a caller-built `M'`, which is
how the ACVP KAT suite (§14) exercises the "external, pure" interface
with non-empty context vectors, but that's a workaround, not a supported
path. Contrast with SLH-DSA (§8, §9), whose `sign`/`verify` take `ctx:
&[u8]` directly — this wasn't an oversight there, it was designed in from
the start once the gap here was already known.

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
whether `A` and `B` are both ML-DSA variants, both SLH-DSA variants, one
of each, or (once implemented) one classical scheme. The test suite
currently exercises same-family pairings only (`Hybrid<MlDsa44,
MlDsa44>`, chosen because there's no classical scheme implemented yet to
pair with); the combinator itself has no family-specific code, so
`Hybrid<MlDsa65, SlhDsaShake256s>` — a lattice scheme and a hash-based
scheme, resting on genuinely different hardness assumptions, arguably the
most interesting pairing this crate can currently express — compiles and
works with zero changes here. It just hasn't had a test written for it
yet; see the README Roadmap.

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
   correctness bug, not a compile error. **Also double-check every field
   against the *other* variant's file, not just against FIPS 204's
   table** — diff the new file against both existing `constants.rs`
   files before trusting it; §5's note on the ML-DSA-44/65 history is the
   reason this step is explicit here and not assumed.
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
   dispatch — see §12.
6. **Verify against the FIPS 204 / ACVP known-answer test vectors**
   (`tests/acvp_kat.rs`), not just internal roundtrip tests — extend the
   existing harness rather than writing a new one; it already dispatches
   per `parameterSet` string, so adding `"ML-DSA-87"` to each vector
   category's match arms and re-running the vector extraction script
   (§14) against the ML-DSA-87 test groups is the whole job.

Nothing about ML-DSA-44 or ML-DSA-65 has to change, and nothing else in
the crate needs to know ML-DSA-87 exists until something opts into using
it.

## 8. `dsa/slh_dsa` — the SLH-DSA family

FIPS 205 has more per-parameter-set values than ML-DSA (n, h, d, a, k —
five, versus ML-DSA's eight but with more cross-dependencies) and, unlike
ML-DSA, the thing that actually varies *by instantiation* (SHAKE vs. SHA2,
§11.1 vs §11.2) is not the parameter values at all — every SHAKE
parameter set shares its n/h/d/a/k with its SHA2 counterpart exactly
(Table 2 literally lists them on the same row). What varies is which
concrete hash function computes six abstract operations (§4.1). That's a
qualitatively different shape than ML-DSA's "eight numbers change per
security level," so this family uses a different mechanism to split by
what varies:

- **`SlhDsaParams`** (`params.rs`) — a runtime struct (`name`, `n`, `h`,
  `d`, `a`, `k`, `security_category`), not six copy-pasted `constants.rs`
  files. `hp()` (h'), `wots_len()`, `m()`, `pk_bytes()`, `sk_bytes()`,
  `sig_bytes()` are `const fn` methods derived from those five fields —
  every one of Table 2's published sizes is *computed*, never
  hand-transcribed, and a test in this file (`table_2_shake_*`)
  reconstructs all of them from n/h/d/a/k for every parameter set and
  asserts against NIST's published numbers. This is deliberately the
  opposite of ML-DSA's per-variant files specifically because that
  pattern already produced one bug (§5) — see §13/§16 for the fuller
  argument.
- **`HashSuite`** (`hash_suite.rs`) — a trait abstracting FIPS 205's six
  hash functions (`h_msg`, `prf`, `prf_msg`, `f_hash`, `h_hash`, `t_l`).
  `wots.rs`/`xmss.rs`/`ht.rs`/`fors.rs`/`core.rs` are written once,
  generic over `H: impl HashSuite`, and never know or care which concrete
  hash function is underneath. `ShakeSuite` (same file) implements §11.1;
  `Sha2Suite` (`sha2_suite.rs`) implements §11.2. Adding SHA2 support
  after SHAKE was already implemented touched **zero** lines in
  `wots.rs`/`xmss.rs`/`ht.rs`/`fors.rs`/`core.rs` — only a new struct
  implementing the trait, and new `slh_dsa_variant!` invocations in
  `mod.rs`. That's the payoff of this design: it's the same "split by
  what varies" principle as §2, just recognizing that for SLH-DSA the
  hash instantiation is the axis that varies independently of the tree
  structure, not the parameter values.
- **`Adrs`** (`adrs.rs`) — the 32-byte addressing structure (§4.2, Table
  1) every hash call takes as input, used identically by both hash
  suites. `Adrs::compress()` produces the SHA2 instantiation's 22-byte
  Table 3 form on demand, but only `sha2_suite.rs` ever calls it — the
  tree/signature algorithms above always build and mutate the full
  32-byte form, regardless of which suite is in use underneath.
- **`prehash.rs`** — Algorithms 23/25 (HashSLH-DSA). Built on the same
  `slh_sign_internal`/`slh_verify_internal` as the pure interface
  (`core.rs`), just with a different `M'` construction (pre-hash the
  message, prepend a DER OID and a `1` domain-separation byte instead of
  a `0`). The pre-hash function (`PreHash::Sha256/Sha512/Shake128/
  Shake256`) is a parameter independent of which `HashSuite` the
  `SlhDsa*` type itself uses — FIPS 205 explicitly permits any
  combination, so e.g. `SlhDsaSha2_256s::sign_prehash(..., PreHash::Shake256, ...)`
  is valid and tested.
- **`mod.rs`**'s `slh_dsa_variant!` macro — the only place per-variant
  *code* (as opposed to per-variant *data*, which is just a
  `SlhDsaParams` value) gets generated: it wires one `SlhDsaParams`
  constant, one concrete `HashSuite` type, and four derived array
  lengths (`pk_bytes`/`sk_bytes`/`sig_bytes`/`seed_len`) into a
  `SignatureScheme` impl plus the `sign_deterministic`/`sign_prehash`/
  `verify_prehash` inherent methods. Every invocation calls
  `debug_assert_eq!` against `SlhDsaParams`'s own derived sizes at every
  `keypair`/`sign`/`verify` call — if a future invocation's literal
  `$pk_len`/`$sk_len`/`$sig_len` arguments ever drift from what
  `SlhDsaParams` computes, tests catch it immediately rather than
  producing a silently wrong-sized key. Twelve invocations exist today
  (six `ShakeSuite`, six `Sha2Suite`) — §9 covers adding a 13th.

## 9. Adding a new SLH-DSA parameter set or hash instantiation

**A 13th parameter set** (all values FIPS 205 currently approves are
already implemented, but hypothetically, per §8):

1. Add one `SlhDsaParams` value to `params.rs` with the five values
   (`n`, `h`, `d`, `a`, `k`) and `security_category` from the spec's
   table. Add a `check(...)` call in that file's `#[cfg(test)]` block
   asserting the derived `m`/`pk_bytes`/`sig_bytes` against the
   spec's published numbers for that row — this is the check that
   would catch a transcription error before it reaches anything else,
   same role as the ACVP pass plays at a different layer (§13, §14).
2. Add one `slh_dsa_variant!` invocation in `mod.rs`, picking `ShakeSuite`
   or `Sha2Suite` per the spec's naming (or both, if the new set is
   approved for both instantiations, as every current one is).
3. Nothing in `wots.rs`/`xmss.rs`/`ht.rs`/`fors.rs`/`core.rs`/
   `hash_suite.rs`/`sha2_suite.rs`/`prehash.rs` changes.

**A third hash instantiation** (hypothetically — FIPS 205 only approves
SHAKE and SHA2 today): implement `HashSuite` for a new struct in a new
sibling module to `hash_suite.rs`/`sha2_suite.rs`, following whichever
spec section defines it. Nothing in `wots.rs`/`xmss.rs`/`ht.rs`/
`fors.rs`/`core.rs`/`prehash.rs` changes — that's the entire point of
routing everything through the trait.

## 10. Adding a brand new algorithm family entirely

A structurally different signature algorithm (a classical scheme like
Ed25519, for real hybrid pairing, since today's `Hybrid` test only pairs
ML-DSA with itself — see §6) is a new top-level module beside
`dsa::ml_dsa` and `dsa::slh_dsa`:

```
src/dsa/
├── ml_dsa/       (existing)
├── slh_dsa/      (existing)
└── ed25519/      (new, hypothetically)
```

It implements `SignatureScheme` on its own terms — there's no obligation
to reuse `common::ring` (ML-DSA-specific) or `dsa::slh_dsa`'s `HashSuite`
pattern (SLH-DSA-specific) unless the math or structure genuinely
overlaps. Add `pub mod ed25519;` to `dsa/mod.rs`. The moment `impl
SignatureScheme for Ed25519` exists, `Hybrid<MlDsa65, Ed25519>` and the
CLI's generic `cmd_*<T>` functions (once SLH-DSA and any future family
are wired into the CLI the same way ML-DSA is today — see §12) work with
it unmodified.

Before choosing a design for the new family's *internal* module split
(one shared engine + per-variant constants, like ML-DSA; or one shared
engine + a trait abstracting the axis that varies, like SLH-DSA; or
something else entirely), read §2's framing and pick based on what
actually varies within the new family — don't default to copying
ML-DSA's macro pattern just because it's the first example in this file.

## 11. Feature flags

Declared in `Cargo.toml`, not yet documented in depth here because their
implementation hasn't been reviewed as part of this document's authoring
— treat this section as a map of *what exists*, not a guarantee of *how
it's built*:

- **`std`** (default) — presumably gates `std`-only code paths in favor
  of eventual `no_std` support. Confirm what it actually gates before
  relying on `no_std` compatibility. Note SLH-DSA's `sha2`/`hmac`
  dependencies (see §15) haven't been checked for `no_std` compatibility
  either way.
- **`masking`** — side-channel hardening (masked implementations), per
  the crate description. Not covered by this document; read the
  masking module's own doc comments before extending it. Scoped to
  ML-DSA only as of this writing — SLH-DSA has no masking work at all.
- **`w3c`** — Verifiable Credentials support (`serde`, `base64`, `uuid`,
  `chrono`, `multibase` become active). Also not covered here.

If you work on any of these, please add a `§11.x` section here
summarizing its design the way §3–§9 do for the core signature engines —
that's the standard this file is trying to hold to.

## 12. `main.rs` — CLI

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

**SLH-DSA is not reachable from the CLI yet** — `Algorithm` and its
`parse`/dispatch match only know about the two ML-DSA variants. Adding a
parameter set to the CLI is one `Algorithm` enum variant and one match
arm — the command logic itself (`cmd_x<T>`) never changes, since it's
already generic over `SignatureScheme`. Adding *all twelve* SLH-DSA
variants this way is mechanical but repetitive; consider whether
`Algorithm` should instead carry a family + variant pair (e.g. `--alg
slh-dsa --variant shake-128s`) before doing it, rather than twelve near-
identical match arms — that's a design decision for whoever picks this
up, not dictated by anything already built. Note also that
`sign_prehash`/`verify_prehash` and context-string support aren't part
of `SignatureScheme` (§3), so wiring those into the CLI needs its own
non-generic path per family that has them, the same way `cmd_x<T>`
can't reach them today even for ML-DSA (which doesn't have pre-hash at
all) — this is a real design gap to resolve, not just an omission.

Security-relevant behavior baked into the CLI (see the file's own header
comment for the reasoning): `sign --sk <hex>` is deprecated in favor of
`--sk-file <path>` because argv is visible via `ps`/`/proc` and lands in
shell history; `keygen` doesn't print the secret key to stdout unless
`--show-secret` is passed; `--save` writes `sk.bin` at `0600` on Unix;
every secret buffer this file touches (`sk`, decoded hex/seed bytes) is
zeroized via `common::ring::zeroize_bytes` once no longer needed. **This
zeroization is ML-DSA-specific plumbing** (`common::ring::zeroize_bytes`)
— SLH-DSA's secret material (`SlhDsaSecretKey`'s `Vec<u8>` fields) has no
equivalent treatment yet, in the CLI or the library itself. Track this
before SLH-DSA reaches the CLI or any secret-handling-sensitive use.

## 13. Backward compatibility

**This crate has been published to crates.io** (`0.1.0`, then `0.1.1`)
— the "not yet published" framing an earlier version of this document
carried is no longer accurate, and the calculus around removing/renaming
a public path has genuinely changed: check whether a given change needs
a semver bump before making it, the way any published crate must.

Notably, **`0.1.0` shipped with a real correctness bug** (`ml_dsa_44`'s
`constants.rs` was a byte-for-byte copy of `ml_dsa_65`'s — see §5, §14)
that `0.1.1` fixed. Anyone who ran `cargo add sirraya-crypto` against
`0.1.0` and used `MlDsa44` got ML-DSA-65-strength keys mislabeled as
ML-DSA-44. If you're doing release engineering for this crate: that's
the standing example for why the ACVP KAT pass (§14) and the
`SlhDsaParams` self-check (§8, §9) both exist as regression tests, not
just onboarding checks — they need to keep running in CI on every future
release, not just once.

An earlier draft, before the first publish, carried a flat re-export
layer (`mldsa44`, `constants_44`, `polynomial` at the crate root) to
preserve a pre-refactor API; that was removed once it was confirmed
nothing depended on it. That's now historical color, not a live
consideration — don't resurrect that pattern without a concrete reason.

## 14. Testing

### ML-DSA

`ml_dsa_impl!` generates a `#[cfg(test)] mod tests` block per invocation,
so `ml_dsa_44::tests::*` and `ml_dsa_65::tests::*` are two independently
compiled, independently run copies of the same roundtrip test suite:
`eta_roundtrip`, `z_roundtrip`, `t0_roundtrip`, `t1_roundtrip`,
`ntt_roundtrip_*`, `sign_verify`, `sign_verify_deterministic`,
`deterministic_keygen`, `reject_wrong_msg`, `reject_tampered_sig`,
`many_roundtrips`. `hybrid::tests` covers the combinator separately.
28 tests total.

**What these tests actually prove:** that packing a value and unpacking
it returns the same value, and that sign→verify round-trips and rejects
tampering. **What they do not prove:** that the wire encoding matches
the FIPS 204 spec's exact byte layout, or that this implementation
produces the same output as the reference implementation on a given
input. **This is not hypothetical for this crate** — the ML-DSA-44/65
constants bug (§5, §13) passed every test in this suite, because both
`MlDsa44` and `MlDsa65` were internally self-consistent; `MlDsa44` was
just silently running ML-DSA-65's math.

**This gap is now closed for ML-DSA-44/65**: `tests/acvp_kat.rs` (5
tests, 170 vectors from the official NIST `ML-DSA-{keyGen,sigGen,
sigVer}-FIPS204` vector files) checks byte-exact output against NIST's
reference data for the deterministic, pure/internal-interface paths.
Run it: `cargo test --release --test acvp_kat -- --nocapture`. See the
README's Testing section for exactly what's covered (KeyGen/SigGen/
SigVer, both interfaces) and what isn't (`externalMu`, pre-hash,
randomized SigGen, ML-DSA-87).

### SLH-DSA

`dsa::slh_dsa::mod`'s `#[cfg(test)]` block: full round-trip + tamper-
rejection + determinism + pre-hash coverage for `SlhDsaShake128f` and
`SlhDsaSha2_128f`/`SlhDsaSha2_256f` (chosen to exercise both hash suites
and both SHA2 sub-cases, §8's `Sha2Case::Category1`/`Category3Or5`), plus
a round-trip smoke test for the other 9 parameter sets. `dsa::slh_dsa::
params`'s `#[cfg(test)]` block separately checks every parameter set's
derived sizes against FIPS 205 Table 2 (§8, §9) — independent of whether
signing itself is correct. 27 + 6 = effectively covers all 12 variants at
some level, per the README's Testing section for the precise breakdown.

**Same caveat as ML-DSA's round-trip suite, and it matters just as
much here**: round-trip testing proves internal self-consistency, not
conformance to NIST's reference output. Concretely for SLH-DSA: a
bit-order or byte-order mistake in `Adrs`'s Table 1 encoding
(`set_tree_address`, `set_key_pair_address`, etc.) that both signer and
verifier make identically — because they're the same code — would still
pass every test above, but would produce signatures that don't match
NIST's SLH-DSA reference implementation or ACVP's expected vectors byte-
for-byte. **This has not been checked yet.** Pulling
`SLH-DSA-{keyGen,sigGen,sigVer}-FIPS205` from
[usnistgov/ACVP-Server](https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files)
and building a KAT harness the same shape as `tests/acvp_kat.rs` — a
second `#[[test]]` target, e.g. `tests/acvp_kat_slh_dsa.rs`, since the
vector JSON schema and per-parameter-set dispatch differ enough from
ML-DSA's to not obviously share one file — is the single most important
open item for this crate (see README Roadmap and Status).

## 15. Dependencies

Direct dependencies as of this writing, and which family needs each:

| Crate | Used by | Why |
|---|---|---|
| `sha3` | both | SHAKE128/256 — FIPS 204 §3.7, FIPS 205 §11.1 (`ShakeSuite`) and §10.2.2 pre-hash |
| `sha2` | SLH-DSA only | FIPS 205 §11.2 SHA2 instantiation (`Sha2Suite`) and §10.2.2 pre-hash |
| `hmac` | SLH-DSA only | `PRF_msg` under §11.2 (HMAC-SHA-256/512) |
| `rand_core` | both | `OsRng` for key generation (ML-DSA Algorithm 1, SLH-DSA Algorithm 21) |
| `hex` | CLI only | key/signature hex encoding |
| `serde`, `serde_json` (dev-only) | ML-DSA ACVP tests | parsing `tests/vectors/*.json` |

The README's "no unnecessary dependencies" framing predates `sha2`/
`hmac` — those two are genuinely required for FIPS 205 §11.2, not
speculative additions, but the dependency count did grow from three to
five adding SLH-DSA. If a future change wants to reduce this (e.g.
dropping SHA2 support to shed two dependencies), that's a real, visible
trade-off against §8's stated goal of implementing every FIPS 205
parameter set — flag it as a deliberate scope change, not a cleanup.

## 16. Contributing checklist

Before opening a PR that touches `ml_dsa/core.rs`, `common/ring.rs`,
`traits.rs`, or anything under `dsa/slh_dsa/`:

- [ ] Does `cargo test --release` still pass for **every** existing
      variant, not just the one you're working on? (Use `--release` —
      several SLH-DSA parameter sets are slow enough in debug mode that
      skipping this flag looks like a hang.)
- [ ] If you changed an ML-DSA packing/sampling routine, does it still
      derive its bit-width/behavior from the constants module rather
      than a literal? (§5.1 explains why this matters — it's the exact
      bug class this crate has already hit once.)
- [ ] If you added an ML-DSA parameter set, did you sanity-check the
      derived sizes (`PUBLICKEYBYTES`, `SECRETKEYBYTES`, `SIGNBYTES`)
      against FIPS 204 Table 2's published values, **and diff the new
      `constants.rs` against the existing ones**, before trusting the
      build? (§5, §7 — this is precisely the check that was skipped
      before `0.1.0` shipped.)
- [ ] If you added an SLH-DSA parameter set, did the `params.rs`
      self-check test (§8, §9) pass against FIPS 205 Table 2's published
      `m`/`pk_bytes`/`sig_bytes`?
- [ ] If you added or changed a `HashSuite` implementation, did you run
      the full round-trip suite for parameter sets covering *both*
      `Sha2Case` branches (§8, §14), not just one?
- [ ] If you touched `traits.rs`, did you check for exhaustive `match`
      statements on error enums or trait objects elsewhere that a new
      variant/method could silently need updating?
- [ ] **Is there an ACVP KAT test covering what you changed, or does
      this PR make an existing gap in §14/README-Status worse rather
      than better?** Round-trip-green is not sufficient evidence of
      correctness for either family, and the crate's own history (§13)
      is the reason this is now a checklist item rather than an
      assumption.
- [ ] Does the relevant section of this file still describe what you
      built, or does it need a paragraph updated?