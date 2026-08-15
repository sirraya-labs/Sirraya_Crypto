//! ACVP known-answer tests for ML-DSA-44 / ML-DSA-65, run against the
//! *official* NIST test vectors published at
//! https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files
//! (ML-DSA-keyGen-FIPS204, ML-DSA-sigGen-FIPS204, ML-DSA-sigVer-FIPS204).
//!
//! This closes the gap ARCHITECTURE.md §10 calls out explicitly: the
//! existing `#[cfg(test)]` suite only proves internal self-consistency
//! (pack/unpack round-trips, sign→verify round-trips). It cannot catch a
//! bug where every routine agrees on a *wrong* value — e.g. two parameter
//! sets sharing a constants file. These tests check output bytes against
//! NIST's own reference implementation.
//!
//! # What's covered and why
//! - **keyGen**: `seed` → `keypair_from_seed` → compare `pk`/`sk` exactly.
//!   Straightforward: the crate's public API matches ACVP's KeyGen prompt
//!   shape (Algorithm 6) one-to-one.
//! - **sigGen / sigVer, "internal" interface, `externalMu: false`**: this
//!   ACVP interface hands the raw message straight to
//!   `Sign_internal(sk, M, rnd)` / `Verify_internal(pk, M, sig)` (FIPS 204
//!   Algorithms 7/8) with no `ctx` wrapping — which is exactly what this
//!   crate's `sign_internal`/`verify_internal` do. Deterministic groups
//!   fix `rnd = 0^32`, matching `sign_deterministic`'s convention, so we
//!   call `sign_internal` directly with an all-zero `rnd`.
//! - **sigGen / sigVer, "external" interface, `preHash: pure`**: this is
//!   FIPS 204 Algorithm 2/3 (`ML-DSA.Sign`/`Verify`), which forms
//!   `M' = 0x00 || len(ctx) || ctx || M` before calling the internal
//!   routine. **The crate's own `sign()`/`verify()` wrappers hard-code an
//!   empty context** (`mp.push(0u8); mp.push(0u8);` with no ctx bytes at
//!   all — see `core.rs`), so they can't be used to reproduce vectors that
//!   carry a non-empty `context`. Since `sign_internal`/`verify_internal`
//!   are public, these tests build `M'` by hand instead. This is a
//!   legitimate use of the crate's public surface, but it's also a real
//!   gap worth fixing: as published, there is no way to sign or verify
//!   with a context string through this crate's API.
//!
//! # What's intentionally NOT covered
//! - `externalMu: true` groups (crate has no entry point taking a
//!   precomputed `mu`).
//! - `preHash: preHash` (HashML-DSA) groups (crate implements pure ML-DSA
//!   only, no pre-hash wrapper).
//! - Randomized (`deterministic: false`) sigGen groups (ACVP validates
//!   these interactively against the submitted signature, not by KAT
//!   comparison against a fixed expected value; not meaningful to embed
//!   as static vectors).
//! - ML-DSA-87 (not implemented by this crate).
//!
//! Run with: `cargo test --release --test acvp_kat`

use serde::Deserialize;
use sirraya_crypto::dsa::ml_dsa::{ml_dsa_44, ml_dsa_65};

fn hex_to_vec(s: &str) -> Vec<u8> {
    hex::decode(s).expect("vector file contains invalid hex")
}

fn hex_to_array<const N: usize>(s: &str) -> [u8; N] {
    let v = hex_to_vec(s);
    v.try_into()
        .unwrap_or_else(|v: Vec<u8>| panic!("expected {N} bytes, vector had {}", v.len()))
}

/// FIPS 204 Algorithm 2/3 message encoding: M' = 0x00 || len(ctx) || ctx || M.
/// (`ctx.len()` must fit in one byte — ACVP context strings never exceed 255.)
fn encode_pure_external(ctx: &[u8], msg: &[u8]) -> Vec<u8> {
    assert!(ctx.len() <= 255, "context too long for one-byte length prefix");
    let mut mp = Vec::with_capacity(2 + ctx.len() + msg.len());
    mp.push(0u8);
    mp.push(ctx.len() as u8);
    mp.extend_from_slice(ctx);
    mp.extend_from_slice(msg);
    mp
}

// ---------------------------------------------------------------------------
// keyGen
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct KeyGenVec {
    #[serde(rename = "parameterSet")]
    parameter_set: String,
    #[serde(rename = "tcId")]
    tc_id: u32,
    seed: String,
    pk: String,
    sk: String,
}

#[test]
fn acvp_keygen() {
    let vecs: Vec<KeyGenVec> =
        serde_json::from_str(include_str!("vectors/keygen.json")).unwrap();
    assert!(!vecs.is_empty());

    let mut checked = 0usize;
    let mut failed = Vec::new();

    for v in &vecs {
        let seed: [u8; 32] = hex_to_array(&v.seed);
        let expected_pk = hex_to_vec(&v.pk);
        let expected_sk = hex_to_vec(&v.sk);

        let (pk, sk): (Vec<u8>, Vec<u8>) = match v.parameter_set.as_str() {
            "ML-DSA-44" => {
                let (pk, sk) = ml_dsa_44::keypair_from_seed(&seed)
                    .unwrap_or_else(|e| panic!("tcId {}: keypair_from_seed failed: {e}", v.tc_id));
                (pk.to_vec(), sk.to_vec())
            }
            "ML-DSA-65" => {
                let (pk, sk) = ml_dsa_65::keypair_from_seed(&seed)
                    .unwrap_or_else(|e| panic!("tcId {}: keypair_from_seed failed: {e}", v.tc_id));
                (pk.to_vec(), sk.to_vec())
            }
            other => panic!("unexpected parameterSet {other}"),
        };

        checked += 1;
        if pk.len() != expected_pk.len() {
            failed.push(format!(
                "tcId {} ({}): pk length mismatch: got {}, expected {}",
                v.tc_id, v.parameter_set, pk.len(), expected_pk.len()
            ));
            continue;
        }
        if sk.len() != expected_sk.len() {
            failed.push(format!(
                "tcId {} ({}): sk length mismatch: got {}, expected {}",
                v.tc_id, v.parameter_set, sk.len(), expected_sk.len()
            ));
            continue;
        }
        if pk != expected_pk {
            failed.push(format!("tcId {} ({}): pk mismatch", v.tc_id, v.parameter_set));
        }
        if sk != expected_sk {
            failed.push(format!("tcId {} ({}): sk mismatch", v.tc_id, v.parameter_set));
        }
    }

    println!("acvp_keygen: {checked} vectors checked, {} failed", failed.len());
    if !failed.is_empty() {
        panic!(
            "{} / {checked} ACVP keyGen vectors failed:\n{}",
            failed.len(),
            failed.join("\n")
        );
    }
}

// ---------------------------------------------------------------------------
// sigGen — internal interface, externalMu=false, deterministic (rnd = 0)
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct SigGenInternalVec {
    #[serde(rename = "parameterSet")]
    parameter_set: String,
    #[serde(rename = "tcId")]
    tc_id: u32,
    sk: String,
    message: String,
    signature: String,
}

#[test]
fn acvp_siggen_internal_deterministic() {
    let vecs: Vec<SigGenInternalVec> =
        serde_json::from_str(include_str!("vectors/siggen_internal.json")).unwrap();
    assert!(!vecs.is_empty());

    let mut failed = Vec::new();
    for v in &vecs {
        let msg = hex_to_vec(&v.message);
        let expected_sig = hex_to_vec(&v.signature);

        let sig: Vec<u8> = match v.parameter_set.as_str() {
            "ML-DSA-44" => {
                let sk: [u8; ml_dsa_44::constants::SECRETKEYBYTES] = hex_to_array(&v.sk);
                match ml_dsa_44::sign_internal(&sk, &msg, &[0u8; 32]) {
                    Ok(s) => s.to_vec(),
                    Err(e) => {
                        failed.push(format!("tcId {} (44): sign_internal errored: {e}", v.tc_id));
                        continue;
                    }
                }
            }
            "ML-DSA-65" => {
                let sk: [u8; ml_dsa_65::constants::SECRETKEYBYTES] = hex_to_array(&v.sk);
                match ml_dsa_65::sign_internal(&sk, &msg, &[0u8; 32]) {
                    Ok(s) => s.to_vec(),
                    Err(e) => {
                        failed.push(format!("tcId {} (65): sign_internal errored: {e}", v.tc_id));
                        continue;
                    }
                }
            }
            other => panic!("unexpected parameterSet {other}"),
        };

        if sig.len() != expected_sig.len() {
            failed.push(format!(
                "tcId {} ({}): signature length mismatch: got {}, expected {}",
                v.tc_id, v.parameter_set, sig.len(), expected_sig.len()
            ));
        } else if sig != expected_sig {
            failed.push(format!("tcId {} ({}): signature mismatch", v.tc_id, v.parameter_set));
        }
    }

    println!(
        "acvp_siggen_internal_deterministic: {} vectors checked, {} failed",
        vecs.len(), failed.len()
    );
    if !failed.is_empty() {
        panic!(
            "{} / {} ACVP sigGen(internal) vectors failed:\n{}",
            failed.len(), vecs.len(), failed.join("\n")
        );
    }
}

// ---------------------------------------------------------------------------
// sigGen — external interface, preHash=pure, deterministic (rnd = 0),
// M' built by hand since sign()/sign_deterministic() hard-code ctx = "".
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct SigGenExternalVec {
    #[serde(rename = "parameterSet")]
    parameter_set: String,
    #[serde(rename = "tcId")]
    tc_id: u32,
    sk: String,
    message: String,
    #[serde(default)]
    context: String,
    signature: String,
}

#[test]
fn acvp_siggen_external_pure_deterministic() {
    let vecs: Vec<SigGenExternalVec> =
        serde_json::from_str(include_str!("vectors/siggen_external.json")).unwrap();
    assert!(!vecs.is_empty());

    let mut failed = Vec::new();
    for v in &vecs {
        let msg = hex_to_vec(&v.message);
        let ctx = if v.context.is_empty() { Vec::new() } else { hex_to_vec(&v.context) };
        let mp = encode_pure_external(&ctx, &msg);
        let expected_sig = hex_to_vec(&v.signature);

        let sig: Vec<u8> = match v.parameter_set.as_str() {
            "ML-DSA-44" => {
                let sk: [u8; ml_dsa_44::constants::SECRETKEYBYTES] = hex_to_array(&v.sk);
                match ml_dsa_44::sign_internal(&sk, &mp, &[0u8; 32]) {
                    Ok(s) => s.to_vec(),
                    Err(e) => {
                        failed.push(format!("tcId {} (44): sign_internal errored: {e}", v.tc_id));
                        continue;
                    }
                }
            }
            "ML-DSA-65" => {
                let sk: [u8; ml_dsa_65::constants::SECRETKEYBYTES] = hex_to_array(&v.sk);
                match ml_dsa_65::sign_internal(&sk, &mp, &[0u8; 32]) {
                    Ok(s) => s.to_vec(),
                    Err(e) => {
                        failed.push(format!("tcId {} (65): sign_internal errored: {e}", v.tc_id));
                        continue;
                    }
                }
            }
            other => panic!("unexpected parameterSet {other}"),
        };

        if sig.len() != expected_sig.len() {
            failed.push(format!(
                "tcId {} ({}): signature length mismatch: got {}, expected {}",
                v.tc_id, v.parameter_set, sig.len(), expected_sig.len()
            ));
        } else if sig != expected_sig {
            failed.push(format!("tcId {} ({}): signature mismatch", v.tc_id, v.parameter_set));
        }
    }

    println!(
        "acvp_siggen_external_pure_deterministic: {} vectors checked, {} failed",
        vecs.len(), failed.len()
    );
    if !failed.is_empty() {
        panic!(
            "{} / {} ACVP sigGen(external, pure) vectors failed:\n{}",
            failed.len(), vecs.len(), failed.join("\n")
        );
    }
}

// ---------------------------------------------------------------------------
// sigVer — internal interface, externalMu=false
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct SigVerInternalVec {
    #[serde(rename = "parameterSet")]
    parameter_set: String,
    #[serde(rename = "tcId")]
    tc_id: u32,
    pk: String,
    message: String,
    signature: String,
    #[serde(rename = "testPassed")]
    test_passed: bool,
}

#[test]
fn acvp_sigver_internal() {
    let vecs: Vec<SigVerInternalVec> =
        serde_json::from_str(include_str!("vectors/sigver_internal.json")).unwrap();
    assert!(!vecs.is_empty());

    let mut failed = Vec::new();
    for v in &vecs {
        let msg = hex_to_vec(&v.message);
        let sig_bytes = hex_to_vec(&v.signature);

        let got_valid = match v.parameter_set.as_str() {
            "ML-DSA-44" => {
                if sig_bytes.len() != ml_dsa_44::constants::SIGNBYTES {
                    false // malformed-length signature: correct behavior is "reject"
                } else {
                    let pk: [u8; ml_dsa_44::constants::PUBLICKEYBYTES] = hex_to_array(&v.pk);
                    let sig: [u8; ml_dsa_44::constants::SIGNBYTES] = sig_bytes.try_into().unwrap();
                    ml_dsa_44::verify_internal(&pk, &msg, &sig).unwrap_or(false)
                }
            }
            "ML-DSA-65" => {
                if sig_bytes.len() != ml_dsa_65::constants::SIGNBYTES {
                    false
                } else {
                    let pk: [u8; ml_dsa_65::constants::PUBLICKEYBYTES] = hex_to_array(&v.pk);
                    let sig: [u8; ml_dsa_65::constants::SIGNBYTES] = sig_bytes.try_into().unwrap();
                    ml_dsa_65::verify_internal(&pk, &msg, &sig).unwrap_or(false)
                }
            }
            other => panic!("unexpected parameterSet {other}"),
        };

        if got_valid != v.test_passed {
            failed.push(format!(
                "tcId {} ({}): expected testPassed={}, got {}",
                v.tc_id, v.parameter_set, v.test_passed, got_valid
            ));
        }
    }

    println!("acvp_sigver_internal: {} vectors checked, {} failed", vecs.len(), failed.len());
    if !failed.is_empty() {
        panic!(
            "{} / {} ACVP sigVer(internal) vectors failed:\n{}",
            failed.len(), vecs.len(), failed.join("\n")
        );
    }
}

// ---------------------------------------------------------------------------
// sigVer — external interface, preHash=pure. M' built by hand (see sigGen
// external note above — verify()'s ctx is hard-coded empty too).
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct SigVerExternalVec {
    #[serde(rename = "parameterSet")]
    parameter_set: String,
    #[serde(rename = "tcId")]
    tc_id: u32,
    pk: String,
    message: String,
    #[serde(default)]
    context: String,
    signature: String,
    #[serde(rename = "testPassed")]
    test_passed: bool,
}

#[test]
fn acvp_sigver_external_pure() {
    let vecs: Vec<SigVerExternalVec> =
        serde_json::from_str(include_str!("vectors/sigver_external.json")).unwrap();
    assert!(!vecs.is_empty());

    let mut failed = Vec::new();
    for v in &vecs {
        let msg = hex_to_vec(&v.message);
        let ctx = if v.context.is_empty() { Vec::new() } else { hex_to_vec(&v.context) };
        let sig_bytes = hex_to_vec(&v.signature);

        // A context longer than 255 bytes can't be encoded at all — the
        // correct behavior for such a case is unconditional rejection.
        let got_valid = if ctx.len() > 255 {
            false
        } else {
            let mp = encode_pure_external(&ctx, &msg);
            match v.parameter_set.as_str() {
                "ML-DSA-44" => {
                    if sig_bytes.len() != ml_dsa_44::constants::SIGNBYTES {
                        false
                    } else {
                        let pk: [u8; ml_dsa_44::constants::PUBLICKEYBYTES] = hex_to_array(&v.pk);
                        let sig: [u8; ml_dsa_44::constants::SIGNBYTES] = sig_bytes.try_into().unwrap();
                        ml_dsa_44::verify_internal(&pk, &mp, &sig).unwrap_or(false)
                    }
                }
                "ML-DSA-65" => {
                    if sig_bytes.len() != ml_dsa_65::constants::SIGNBYTES {
                        false
                    } else {
                        let pk: [u8; ml_dsa_65::constants::PUBLICKEYBYTES] = hex_to_array(&v.pk);
                        let sig: [u8; ml_dsa_65::constants::SIGNBYTES] = sig_bytes.try_into().unwrap();
                        ml_dsa_65::verify_internal(&pk, &mp, &sig).unwrap_or(false)
                    }
                }
                other => panic!("unexpected parameterSet {other}"),
            }
        };

        if got_valid != v.test_passed {
            failed.push(format!(
                "tcId {} ({}): expected testPassed={}, got {}",
                v.tc_id, v.parameter_set, v.test_passed, got_valid
            ));
        }
    }

    println!("acvp_sigver_external_pure: {} vectors checked, {} failed", vecs.len(), failed.len());
    if !failed.is_empty() {
        panic!(
            "{} / {} ACVP sigVer(external, pure) vectors failed:\n{}",
            failed.len(), vecs.len(), failed.join("\n")
        );
    }
}
