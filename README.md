# sirraya-crypto

[![Crates.io](https://img.shields.io/crates/v/sirraya-crypto.svg)](https://crates.io/crates/sirraya-crypto)
[![Documentation](https://docs.rs/sirraya-crypto/badge.svg)](https://docs.rs/sirraya-crypto)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-2021_edition-orange.svg)](https://www.rust-lang.org)

**Post-quantum digital signatures for Rust, built on FIPS 204 (ML-DSA).**

`sirraya-crypto` implements the NIST-standardized Module-Lattice-Based
Digital Signature Algorithm (ML-DSA — formerly CRYSTALS-Dilithium) with a
crypto-agile design: every parameter set and future algorithm family
implements one shared `SignatureScheme` trait, so application code,
hybrid composition, and tooling are written once and work across all of
them.

```
[dependencies]
sirraya-crypto = "0.1"
```

> **Not yet published to crates.io.** The badges above will resolve once
> the first release goes out — see [Status](#status) before depending on
> this for anything beyond evaluation.

---

## Status

> [!WARNING]
> **This crate has not been independently security-audited, and its
> output has not yet been checked against the official NIST ACVP /
> reference-implementation known-answer test vectors.** Internal test
> coverage confirms round-trip correctness (pack→unpack, sign→verify,
> tamper rejection) and matches FIPS 204's published key/signature sizes
> for each parameter set, but that does not by itself prove byte-exact
> conformance with the specification. Do not use this in a security-
> critical system until both of those gaps are closed — track progress in
> [ARCHITECTURE.md §10](ARCHITECTURE.md#10-testing) and the
> [Roadmap](#roadmap) below.
>
> **No constant-time guarantees are made in this release.** Side-channel
> hardening (masked gadgets) is scaffolded behind the `masking` feature
> flag but not yet implemented — see [Feature flags](#feature-flags).

If you find a correctness or security issue, please open an issue (or,
for anything sensitive, contact the maintainers directly) rather than a
public PR with exploit details.

## Features

- **FIPS 204 ML-DSA**, currently ML-DSA-44 (Category 2) and ML-DSA-65
  (Category 3); ML-DSA-87 is additive (see [Roadmap](#roadmap)).
- **One trait, every algorithm** — `SignatureScheme` is implemented
  identically by every parameter set and, going forward, every algorithm
  family this crate adds. Generic code (`fn f<T: SignatureScheme>(...)`)
  works unmodified across all of them.
- **Hybrid composition** — `Hybrid<A, B>` signs and verifies with two
  independent schemes at once, accepting only if *both* verify: the
  standard construction for a PQC transition period, generic over any
  two `SignatureScheme` implementors (not limited to ML-DSA).
- **Deterministic and randomized signing**, deterministic key generation
  from an explicit seed for reproducible test vectors.
- **Zeroization** of secret key material and intermediate buffers
  (volatile writes, compiler-fence-protected) throughout the signing
  path and the CLI.
- **A hardened CLI** (`sirraya-crypto`) for key generation, signing, and
  verification — with `--alg` to select the parameter set, and explicit
  guardrails against common secret-exposure mistakes (see
  [CLI](#cli-usage)).
- **No unnecessary dependencies.** Three direct dependencies total:
  `sha3` (SHAKE128/256, required by the spec), `rand_core` (OS
  randomness for key generation), `hex` (CLI encoding). No serialization
  framework, no async runtime, nothing pulled in "just in case."

## Supported algorithms

| Algorithm  | FIPS 204 Category | Public Key | Secret Key | Signature | Status |
|------------|:---:|---:|---:|---:|---|
| ML-DSA-44  | 2 (128-bit classical / 64-bit quantum) | 1,312 B | 2,560 B | 2,420 B | ✅ Implemented, round-trip tested |
| ML-DSA-65  | 3 (192-bit classical / 96-bit quantum) | 1,952 B | 4,032 B | 3,309 B | ✅ Implemented, round-trip tested |
| ML-DSA-87  | 5 (256-bit classical / 128-bit quantum) | — | — | — | 📋 Planned — see [Roadmap](#roadmap) |

Sizes match FIPS 204 Table 2. Neither variant has ACVP known-answer-test
verification yet — see [Status](#status).

## Quick start

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

### Writing algorithm-agnostic code

Anything you write against the `SignatureScheme` trait works for every
parameter set — swap `MlDsa44` for `MlDsa65` (or a future algorithm)
without touching this function:

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
use sirraya_crypto::{MlDsa44, MlDsa65};

type MyHybrid = Hybrid<MlDsa44, MlDsa65>;

let (pk, sk) = MyHybrid::keypair()?;
let sig = MyHybrid::sign(&sk, b"belt and suspenders")?;
assert!(MyHybrid::verify(&pk, b"belt and suspenders", &sig)?); // true only if BOTH verify
```

## CLI usage

```
cargo install sirraya-crypto
```

> Not yet published — until then, build from source:
> `cargo install --path .` from a checkout of this repo, or
> `cargo build --release --bin sirraya-crypto` and run the binary from
> `target/release/`.

```
# Generate a keypair (ML-DSA-44 by default)
sirraya-crypto keygen --save

# Generate an ML-DSA-65 keypair instead
sirraya-crypto --alg ml-dsa-65 keygen --save

# Sign a message (--sk-file is preferred over --sk <hex>, see warning below)
sirraya-crypto sign --sk-file sk.bin --msg "hello world" --sig sig.bin

# Verify
sirraya-crypto verify --pk pk.bin --msg "hello world" --sig sig.bin

# Run the built-in self-test
sirraya-crypto --alg ml-dsa-65 test
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

For module layout, the crypto-agility design (`SignatureScheme`), how the
shared algorithm engine is parameterized per security level, and a
step-by-step guide to adding a new parameter set or algorithm family, see
**[ARCHITECTURE.md](ARCHITECTURE.md)**.

## Minimum Supported Rust Version (MSRV)

Rust 2021 edition. No specific MSRV has been pinned or tested against
yet — track this in the crate's CI once configured.

## Roadmap

- [ ] Verify ML-DSA-44 and ML-DSA-65 against official FIPS 204 / NIST
      ACVP known-answer test vectors
- [ ] ML-DSA-87 (Category 5)
- [ ] A classical `SignatureScheme` implementor (Ed25519/ECDSA) for a
      real classical+PQ `Hybrid` pairing, not just ML-DSA-with-itself
- [ ] Masked/side-channel-hardened gadgets behind the `masking` feature
- [ ] Independent security audit
- [ ] `no_std` support (if there's demand — not currently a design goal)

## Contributing

See [ARCHITECTURE.md §13](ARCHITECTURE.md#13-contributing-checklist) for
the pre-PR checklist, especially before touching `core.rs`,
`common/ring.rs`, or `traits.rs` — this crate has already hit one subtle
correctness bug from parameter-set-specific logic that looked generic but
wasn't, and the checklist exists to catch a repeat.

## References

- [FIPS 204: Module-Lattice-Based Digital Signature Standard](https://csrc.nist.gov/pubs/fips/204/final) — NIST, August 2024
- [NIST Post-Quantum Cryptography Project](https://csrc.nist.gov/projects/post-quantum-cryptography)

## License

MIT. See [LICENSE](LICENSE) — **not yet added to this repo**; add the
standard MIT license text there before publishing (`Cargo.toml` already
declares `license = "MIT"`, which crates.io will reject at publish time
without a matching `LICENSE` file).

---

Built by [Sirraya Labs](https://github.com/sirraya-labs).