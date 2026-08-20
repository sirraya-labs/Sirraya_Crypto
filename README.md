# sirraya-crypto

[![Crates.io](https://img.shields.io/crates/v/sirraya-crypto.svg)](https://crates.io/crates/sirraya-crypto)
[![Documentation](https://docs.rs/sirraya-crypto/badge.svg)](https://docs.rs/sirraya-crypto)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-2021_edition-orange.svg)](https://www.rust-lang.org)

**Post-quantum, classical, and hybrid digital signatures for Rust: FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA), and RFC 8032 (Ed25519).**

`sirraya-crypto` implements both NIST-standardized post-quantum signature
families — Module-Lattice-Based (ML-DSA, formerly CRYSTALS-Dilithium) and
Stateless Hash-Based (SLH-DSA, formerly SPHINCS+) — plus the classical
Ed25519 scheme those pair with during a PQC transition, with a
crypto-agile design: every parameter set, in any of the three families,
implements one shared `SignatureScheme` trait, so application code,
hybrid composition, and tooling are written once and work across all of
them.

```
[dependencies]
sirraya-crypto = "0.1"
```

---

## Status

> [!WARNING]
> **This crate has not been independently security-audited, and no
> constant-time guarantees are made in this release.** Side-channel
> hardening (masked gadgets) is scaffolded behind the `masking` feature
> flag but not yet implemented — see [Feature flags](#feature-flags).
> Correctness and audit status are separate concerns; see below for what
> is and isn't covered on the correctness side.

**ML-DSA-44 and ML-DSA-65 have been checked against the official NIST
ACVP known-answer test vectors** (`ML-DSA-{keyGen,sigGen,sigVer}-FIPS204`,
from [usnistgov/ACVP-Server](https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files)),
in addition to the crate's internal round-trip/tamper-rejection suite —
see [Testing](#testing) for exactly what that covers and doesn't.

**SLH-DSA (all 12 parameter sets) has internal round-trip testing only —
not yet ACVP-verified.** This is the same class of gap ML-DSA had before
its ACVP pass closed it, and it's the reason that pass exists: a
self-consistent implementation bug (every routine agreeing on a wrong
value) passes round-trip tests but fails a known-answer comparison
against NIST's reference output. Don't treat SLH-DSA's round-trip-green
status as equivalent to ML-DSA's ACVP-verified status — see
[Testing](#testing) and [Roadmap](#roadmap).

Either way, "checked against ACVP vectors" is **not** the same as formal
ACVP/CAVP validation, which requires going through NIST's ACVTS process
with an accredited testing lab and results in a published certificate.
This crate has not gone through that process and makes no claim to be
"ACVP-validated" in that formal sense — what's described above is NIST's
own reference test data, run locally against this implementation's
output, which is meaningful evidence of specification conformance but a
different and lesser claim.

If you find a correctness or security issue, please open an issue (or,
for anything sensitive, contact the maintainers directly) rather than a
public PR with exploit details.

## Features

- **Three signature families**, all sharing one trait:
  - **ML-DSA** (FIPS 204, post-quantum, lattice-based) — ML-DSA-44
    (Category 2) and ML-DSA-65 (Category 3); ML-DSA-87 is additive (see
    [Roadmap](#roadmap)).
  - **SLH-DSA** (FIPS 205, post-quantum, hash-based) — all 12 approved
    parameter sets: six SHAKE
    (`SlhDsaShake128s/128f/192s/192f/256s/256f`) and six SHA2
    (`SlhDsaSha2_128s/128f/192s/192f/256s/256f`), each supporting both the
    "pure" signing interface and the "pre-hash" HashSLH-DSA interface
    (SHA-256, SHA-512, SHAKE128, or SHAKE256 as the pre-hash function).
  - **Ed25519** (RFC 8032, classical, elliptic-curve) — `Ed25519`, the
    standard partner for the two families above during a PQC transition
    (see [Hybrid](#hybrid-dual-scheme-signing)). Wraps the mature,
    externally-reviewed `ed25519-dalek` rather than being hand-written —
    see [`dsa::ed25519`'s module docs](#architecture) for why that's a
    deliberate choice, not an inconsistency with the other two families.
- **One trait, every algorithm** — `SignatureScheme` is implemented
  identically by every parameter set in all three families. Generic code
  (`fn f<T: SignatureScheme>(...)`) works unmodified across all of them,
  including across families — `Hybrid<MlDsa65, Ed25519>`, the standard
  PQC-transition pairing, is implemented and tested (see
  [Hybrid](#hybrid-dual-scheme-signing)).
- **Hybrid composition** — `Hybrid<A, B>` signs and verifies with two
  independent schemes at once, accepting only if *both* verify: the
  standard construction for a PQC transition period, generic over any
  two `SignatureScheme` implementors. Both PQ+classical
  (`Hybrid<MlDsa65, Ed25519>`) and PQ+PQ algorithm-diversity pairings
  (`Hybrid<MlDsa65, SlhDsaShake192s>`) are implemented and tested — see
  the CLI's `hybrid-demo` command for a worked example of both.
- **Deterministic and randomized signing**, deterministic key generation
  from an explicit seed for reproducible test vectors, across all three
  families.
- **Zeroization** of secret key material and intermediate buffers
  (volatile writes, compiler-fence-protected) throughout the ML-DSA
  signing path and the CLI, plus `ed25519-dalek`'s own zeroize-on-drop
  for Ed25519 secret keys. (SLH-DSA's own secret handling hasn't had the
  same treatment yet — see [Roadmap](#roadmap).)
- **A hardened CLI** (`sirraya-crypto`) for key generation, signing, and
  verification, plus a `hybrid-demo` command — every parameter set in all
  three families is reachable via `--alg` (pre-hash/context-string
  options aren't exposed through the CLI yet, only the library API — see
  [CLI usage](#cli-usage) and [Roadmap](#roadmap)).
- **Six direct dependencies**: `sha3` (SHAKE128/256, required by both
  FIPS 204 and the SLH-DSA SHAKE instantiation), `sha2` + `hmac` (the
  SLH-DSA SHA2 instantiation, FIPS 205 §11.2), `ed25519-dalek` (RFC 8032,
  deliberately not hand-rolled — see above), `rand_core` (OS randomness
  for key generation), `hex` (CLI encoding). No serialization framework,
  no async runtime — but note this list grew from three (ML-DSA alone) to
  six adding SLH-DSA and Ed25519, each addition genuinely required by
  what it implements, not scope creep.

## Supported algorithms

### ML-DSA (FIPS 204)

| Algorithm  | FIPS 204 Category | Public Key | Secret Key | Signature | Status |
|------------|:---:|---:|---:|---:|---|
| ML-DSA-44  | 2 (128-bit classical / 64-bit quantum) | 1,312 B | 2,560 B | 2,420 B |  Implemented, round-trip tested, ACVP KAT-verified |
| ML-DSA-65  | 3 (192-bit classical / 96-bit quantum) | 1,952 B | 4,032 B | 3,309 B |  Implemented, round-trip tested, ACVP KAT-verified |
| ML-DSA-87  | 5 (256-bit classical / 128-bit quantum) | — | — | — |  Planned — see [Roadmap](#roadmap) |

Sizes match FIPS 204 Table 2 and are confirmed byte-exact against NIST's
ACVP KeyGen vectors — see [Testing](#testing).

### SLH-DSA (FIPS 205)

All 12 approved parameter sets, per Table 2:

| Algorithm | Category | Public Key | Secret Key | Signature | Status |
|---|:---:|---:|---:|---:|---|
| SLH-DSA-{SHAKE,SHA2}-128s | 1 | 32 B | 64 B | 7,856 B |  Implemented, round-trip tested |
| SLH-DSA-{SHAKE,SHA2}-128f | 1 | 32 B | 64 B | 17,088 B | Implemented, round-trip tested |
| SLH-DSA-{SHAKE,SHA2}-192s | 3 | 48 B | 96 B | 16,224 B | Implemented, round-trip tested |
| SLH-DSA-{SHAKE,SHA2}-192f | 3 | 48 B | 96 B | 35,664 B | Implemented, round-trip tested |
| SLH-DSA-{SHAKE,SHA2}-256s | 5 | 64 B | 128 B | 29,792 B | Implemented, round-trip tested |
| SLH-DSA-{SHAKE,SHA2}-256f | 5 | 64 B | 128 B | 49,856 B | Implemented, round-trip tested |

"s" parameter sets favor smaller signatures at the cost of slower
signing; "f" favors faster signing with a larger signature — this is
inherent to SLH-DSA, not specific to this implementation. **Run SLH-DSA
in `--release`** — an "s" keypair/sign/verify cycle involves enough hash
calls (FORS/XMSS tree recursion) that debug builds are noticeably slower
than ML-DSA's.

Sizes match FIPS 205 Table 2 exactly (checked by a test in
`dsa::slh_dsa::params` that reconstructs each published size from just
n/h/d/a/k). **Not yet checked against ACVP** — see
[Status](#status)/[Testing](#testing).

### Ed25519 (RFC 8032)

| Algorithm | Public Key | Secret Key | Signature | Status |
|---|---:|---:|---:|---|
| Ed25519 | 32 B | 32 B | 64 B |  Implemented (wraps `ed25519-dalek`), verified against RFC 8032 §7.1 test vectors |

Not hand-rolled, unlike ML-DSA/SLH-DSA — see
[Architecture](#architecture) for why that's the deliberate, credible
choice for this specific algorithm. This crate's own contribution is the
thin `SignatureScheme` adapter (byte layout, seed handling, error
mapping); that adapter is checked against RFC 8032's official TEST 1
(empty message) and TEST 2 (one-byte message) vectors byte-exact, the
same spirit as the ACVP KAT passes above, scaled to what a wrapper
actually needs checked — see [Testing](#testing).

## Quick start

### ML-DSA

```rust
use sirraya_crypto::MlDsa65;
use sirraya_crypto::traits::SignatureScheme;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Key generation
    let (pk, sk) = MlDsa65::keypair()?;

    // Sign
    let msg = b"a message worth signing";
    let sig = MlDsa65::sign(&sk, msg)?;

    // Verify
    assert!(MlDsa65::verify(&pk, msg, &sig)?);

    Ok(())
}
```

### SLH-DSA

```rust
use sirraya_crypto::SlhDsaShake128s;
use sirraya_crypto::traits::SignatureScheme;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (pk, sk) = SlhDsaShake128s::keypair()?;

    let msg = b"a message worth signing";
    let sig = SlhDsaShake128s::sign(&sk, msg)?;

    assert!(SlhDsaShake128s::verify(&pk, msg, &sig)?);

    Ok(())
}
```

Pre-hash (HashSLH-DSA) signing and an explicit context string are also
available, but through the concrete type rather than the
`SignatureScheme` trait (context strings and a `PH` selection aren't part
of that trait's minimal signature — see
[ARCHITECTURE.md](ARCHITECTURE.md) for why):

```rust
use sirraya_crypto::SlhDsaShake128s;
use sirraya_crypto::dsa::slh_dsa::prehash::PreHash;

let (pk, sk) = SlhDsaShake128s::keypair()?;
let sig = SlhDsaShake128s::sign_prehash(&sk, b"large document", b"", PreHash::Sha512)?;
assert!(SlhDsaShake128s::verify_prehash(&pk, b"large document", b"", PreHash::Sha512, &sig)?);
```

### Ed25519

```rust
use sirraya_crypto::Ed25519;
use sirraya_crypto::traits::SignatureScheme;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (pk, sk) = Ed25519::keypair()?;

    let msg = b"a message worth signing";
    let sig = Ed25519::sign(&sk, msg)?;

    assert!(Ed25519::verify(&pk, msg, &sig)?);

    Ok(())
}
```

### Writing algorithm-agnostic code

Anything you write against the `SignatureScheme` trait works for every
parameter set in either family — swap `MlDsa44` for `MlDsa65` or
`SlhDsaShake256s` (or a future algorithm) without touching this function:

```rust
use sirraya_crypto::traits::SignatureScheme;

fn sign_and_verify<T: SignatureScheme>(msg: &[u8]) -> Result<bool, T::Error> {
    let (pk, sk) = T::keypair()?;
    let sig = T::sign(&sk, msg)?;
    T::verify(&pk, msg, &sig)
}
```

### Hybrid (dual-scheme) signing

```rust
use sirraya_crypto::hybrid::Hybrid;
use sirraya_crypto::{MlDsa65, Ed25519};

type MyHybrid = Hybrid<MlDsa65, Ed25519>;

let (pk, sk) = MyHybrid::keypair()?;
let sig = MyHybrid::sign(&sk, b"belt and suspenders")?;
assert!(MyHybrid::verify(&pk, b"belt and suspenders", &sig)?); // true only if BOTH verify
```

`Hybrid<A, B>` is generic over any two `SignatureScheme` implementors —
it has no idea whether `A`/`B` are ML-DSA, SLH-DSA, Ed25519, or a future
algorithm. `Hybrid<MlDsa65, Ed25519>` (the standard PQC-transition
pairing) and `Hybrid<SlhDsaShake192s, Ed25519>` are both implemented and
round-trip tested, not just "compiles by construction" — see the CLI's
`hybrid-demo` command for a worked example with a concrete motivating
scenario (firmware signing), and [Testing](#testing) for the test suite
itself.

## CLI usage

```
cargo install sirraya-crypto
```

**ML-DSA and Ed25519 via `--alg`; SLH-DSA also supports every parameter
set through the same `--alg` flag** (see [Roadmap](#roadmap) for what
isn't wired in yet — pre-hash/context-string options specifically):

```
# Generate a keypair (ML-DSA-44 by default)
sirraya-crypto keygen --save

# Generate an ML-DSA-65 keypair instead
sirraya-crypto --alg ml-dsa-65 keygen --save

# Generate an Ed25519 keypair
sirraya-crypto --alg ed25519 keygen --save

# Sign a message (--sk-file is preferred over --sk <hex>, see warning below)
sirraya-crypto sign --sk-file sk.bin --msg "hello world" --sig sig.bin

# Verify
sirraya-crypto verify --pk pk.bin --msg "hello world" --sig sig.bin

# Run the built-in self-test
sirraya-crypto --alg ml-dsa-65 test
sirraya-crypto --alg slh-dsa-shake-192s test

# Dual-algorithm hybrid demo — ML-DSA-65 + Ed25519 by default (the
# standard PQC-transition pairing), motivated by a firmware-signing
# scenario. See `--pair` for other curated combinations.
sirraya-crypto hybrid-demo
sirraya-crypto hybrid-demo --pair mldsa65-slhdsa192f --msg "firmware v2.3.1"
```

**Secret-key handling notes** (the CLI enforces these, not just documents
them):

- `keygen` never prints the secret key to stdout unless you pass
  `--show-secret` — plain `keygen` or `keygen --save` keeps it out of
  your terminal scrollback and logs.
- `--save` writes `sk.bin` with `0600` permissions on Unix.
- `sign --sk <hex>` is supported but discouraged and prints a warning —
  it puts the key in `ps`/`/proc` output and shell history. Prefer
  `sign --sk-file <path>`.
- Every secret buffer the CLI touches is zeroized (volatile writes) once
  it's no longer needed, including intermediate hex-decode buffers.

## Feature flags

| Feature | Default | Description |
|---|:---:|---|
| `diagnostic-unsafe` | off | Exposes raw internal secret-key components (s1, s2, t0, seed, tr) for debugging. **Unconditional secret exposure** — never enable in a release build or anywhere the output could be logged or captured. |
| `masking` | off | Reserved for masked (side-channel-hardened) sampling/packing gadgets. No implementation yet — enabling it currently does nothing beyond marking intent. |

## Architecture

For module layout, the crypto-agility design (`SignatureScheme`), how
each algorithm family's shared engine is parameterized (ML-DSA's
macro-per-variant `constants.rs` vs. SLH-DSA's runtime `HashSuite`
trait — deliberately different designs, see the doc for why), and a
step-by-step guide to adding a new parameter set or algorithm family, see
**[ARCHITECTURE.md](ARCHITECTURE.md)**.

## Testing

Two independent layers, per family:

### ML-DSA

- **Internal round-trip suite** (`cargo test --release`, 28 tests) —
  pack↔unpack round-trips, sign→verify round-trips, tampered-signature and
  wrong-message rejection, for both ML-DSA-44 and ML-DSA-65.
- **ACVP known-answer tests** (`cargo test --release --test acvp_kat`,
  5 tests, 170 individual vectors) — checked against the official NIST
  vectors for `ML-DSA-keyGen-FIPS204`, `ML-DSA-sigGen-FIPS204`, and
  `ML-DSA-sigVer-FIPS204`, for both ML-DSA-44 and ML-DSA-65:
  - **KeyGen**: 50 vectors — `seed → keypair_from_seed` compared byte-exact
    against NIST's expected `pk`/`sk`.
  - **SigGen**: 60 vectors — deterministic signing (`rnd = 0`), covering
    both the "internal" interface (`sign_internal`, Algorithm 7) and the
    "external, pure" interface (`Sign`/`Verify`, Algorithm 2/3, message
    encoding built by hand since the crate's public `sign()`/`verify()`
    currently hard-code an empty context — see [Known gap](#known-gap)
    below).
  - **SigVer**: 60 vectors — same two interfaces, including NIST's
    deliberately-tampered vectors, confirming both correct acceptance and
    correct rejection.

  **Not covered**: `externalMu` vectors, pre-hash / HashML-DSA vectors
  (not implemented by ML-DSA in this crate — note this is different from
  SLH-DSA, which *does* implement pre-hash), randomized SigGen vectors,
  and ML-DSA-87.

  Run it: `cargo test --release --test acvp_kat -- --nocapture`. Vector
  files live in `tests/vectors/`, sourced from
  [usnistgov/ACVP-Server](https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files).

#### Known gap

The public `sign()`/`verify()` API has no way to pass a context string —
it's hard-coded to an empty context internally. The ACVP "external, pure"
tests work around this by calling `sign_internal`/`verify_internal`
directly with a hand-built message encoding, which is legitimate but
isn't how an application using `sign()`/`verify()` would get context
support today. (SLH-DSA does not have this gap — its `sign`/`verify` take
a context string directly, and `sign_prehash`/`verify_prehash` do too.)

### SLH-DSA

- **Internal round-trip suite** (`cargo test --release`, 27 tests) —
  keypair→sign→verify round-trips, tampered-signature rejection,
  deterministic-signing determinism, and `keypair_from_seed` determinism,
  covering:
  - Full coverage (round-trip + tamper rejection + determinism +
    pre-hash, all four `PH` options + domain-separation checks) for
    `SlhDsaShake128f` and `SlhDsaSha2_128f`/`SlhDsaSha2_256f`.
  - A round-trip smoke test for the other 9 parameter sets, confirming
    each executes correctly end-to-end without the full tamper/
    determinism suite repeated 12 times over.
  - `dsa::slh_dsa::params` additionally has a unit test per parameter set
    that reconstructs FIPS 205 Table 2's published `m`/`pk_bytes`/
    `sig_bytes` from just n/h/d/a/k, independent of the signing tests
    above — this is the check that would have caught a transcription
    error in Table 2's values before it could reach anything else.

- **No ACVP pass yet.** This is the same class of gap ML-DSA had before
  its ACVP pass — see [Status](#status). Concretely, what round-trip
  testing *cannot* catch: e.g. a bit-order or byte-order error in
  `Adrs`'s address encoding that both the signer and verifier make
  consistently (since they're the same code) would still round-trip
  clean, but would produce signatures byte-different from NIST's
  reference implementation. Track this in [Roadmap](#roadmap).

### Ed25519

- **RFC 8032 §7.1 known-answer vectors** (TEST 1: empty message; TEST 2:
  one-byte message) — checked byte-exact: derived public key, signature,
  and successful verification all match RFC 8032's published values.
  This is a smaller check than ML-DSA's 170-vector ACVP pass by design —
  see [Architecture](#architecture) for why: the curve arithmetic itself
  is `ed25519-dalek`'s responsibility, already externally reviewed: what
  this crate's own two RFC vectors confirm is that *this crate's* thin
  `SignatureScheme` adapter (byte layout, seed handling) doesn't
  introduce a bug on top of a trusted implementation.
- **Round-trip suite** — keypair→sign→verify, tampered-signature and
  wrong-message rejection, `keypair_from_seed` determinism, and a test
  confirming `Ed25519Error::InvalidPublicKey` reflects what
  `ed25519-dalek`'s point decompression actually rejects (which turned
  out, during writing this test, to be more permissive than a naive
  reading of the encoding suggests — see that test's own comment for the
  correction).

### Hybrid

- **Cross-family round-trip tests** — `Hybrid<MlDsa65, Ed25519>` (the
  standard PQC-transition pairing) and `Hybrid<SlhDsaShake192s, Ed25519>`
  (hash-based PQ + classical), plus the original same-family
  `Hybrid<MlDsa44, MlDsa44>` sanity check. Confirms the combinator
  genuinely works across families, not just "compiles by construction."

Run everything: `cargo test --release` (65 lib tests across all three
families + the hybrid combinator, plus the 5 ML-DSA ACVP tests and a
doctest).

## Minimum Supported Rust Version (MSRV)

Rust 2021 edition. No specific MSRV has been pinned or tested against
yet — track this in the crate's CI once configured. One concrete data
point: `ed25519-dalek` is pinned to `=2.1.1` and `zeroize`/`base64ct` to
specific older patches in `Cargo.toml`, purely because the toolchain used
to develop this crate predates Rust's `edition2024` (which newer patches
of those transitive dependencies require) — see the comments next to
those pins. If you're building on a current toolchain, those pins are
safe to relax; they're a development-environment artifact, not a
statement about which versions are actually correct to depend on.

## Roadmap

- [x] Verify ML-DSA-44 and ML-DSA-65 against official FIPS 204 / NIST
      ACVP known-answer test vectors — done for the deterministic,
      pure/internal-interface paths; see [Testing](#testing) for scope
- [x] Implement SLH-DSA (FIPS 205) — all 12 parameter sets (SHAKE + SHA2),
      pure and pre-hash signing interfaces
- [x] A classical `SignatureScheme` implementor for real PQ+classical
      `Hybrid` pairing — Ed25519 (RFC 8032), wrapping `ed25519-dalek`
      (see [Architecture](#architecture) for why not hand-rolled), plus a
      genuine cross-family `Hybrid<MlDsa65, Ed25519>` test, not just
      same-family pairings
- [ ] **Verify SLH-DSA against official FIPS 205 / NIST ACVP known-answer
      test vectors** — the most important open item; see
      [Status](#status)/[Testing](#testing) for why this matters as much
      here as it did for ML-DSA
- [ ] ACVP coverage for ML-DSA's `externalMu`, pre-hash (HashML-DSA), and
      randomized SigGen paths
- [ ] Zeroization of SLH-DSA secret key material and intermediate
      buffers, matching ML-DSA's existing coverage
- [ ] Context-string support in ML-DSA's public `sign()`/`verify()` API
- [ ] ML-DSA-87 (Category 5)
- [ ] ECDSA as a second classical `SignatureScheme` implementor, for
      applications that specifically need it over Ed25519
- [ ] Masked/side-channel-hardened gadgets behind the `masking` feature
- [ ] Independent security audit
- [ ] `no_std` support (if there's demand — not currently a design goal)

## Contributing

See [ARCHITECTURE.md §16](ARCHITECTURE.md#16-contributing-checklist) for
the pre-PR checklist, especially before touching either family's shared
engine (`dsa/ml_dsa/core.rs` or anything in `dsa/slh_dsa/`) — this crate
has already hit one subtle correctness bug from parameter-set-specific
logic that looked generic but wasn't (an ML-DSA-44 constants file that
was a byte-for-byte copy of ML-DSA-65's, caught only by the ACVP KAT
pass, not by the internal round-trip suite), and the checklist exists to
catch a repeat — including in SLH-DSA, which was deliberately architected
differently (a runtime `HashSuite` trait and `SlhDsaParams` struct rather
than per-variant `constants.rs` files) specifically to reduce that risk,
but hasn't had its own ACVP pass yet to confirm it.

## References

- [FIPS 204: Module-Lattice-Based Digital Signature Standard](https://csrc.nist.gov/pubs/fips/204/final) — NIST, August 2024
- [FIPS 205: Stateless Hash-Based Digital Signature Standard](https://csrc.nist.gov/pubs/fips/205/final) — NIST, August 2024
- [RFC 8032: Edwards-Curve Digital Signature Algorithm (EdDSA)](https://www.rfc-editor.org/rfc/rfc8032)
- [NIST Post-Quantum Cryptography Project](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [NIST ACVP-Server test vectors](https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files) — source for this crate's ML-DSA KAT suite (and the planned SLH-DSA one)
- [`ed25519-dalek`](https://github.com/dalek-cryptography/curve25519-dalek/tree/main/ed25519-dalek) — the Ed25519 implementation this crate wraps

## License

MIT. See [LICENSE](LICENSE) — **not yet added to this repo**; add the
standard MIT license text there before publishing (`Cargo.toml` already
declares `license = "MIT"`, which crates.io will reject at publish time
without a matching `LICENSE` file).

---

Built by [Sirraya Labs](https://github.com/sirraya-labs).