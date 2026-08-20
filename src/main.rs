// main.rs — ML-DSA + SLH-DSA + Ed25519 CLI tool with console output.
//
// Supports every parameter set the crate implements, across all three
// algorithm families — FIPS 204 ML-DSA-44/65, all 12 FIPS 205 SLH-DSA
// parameter sets, and RFC 8032 Ed25519 — selected with `--alg`. Every
// subcommand (`keygen`/`sign`/`verify`/`test`) is written exactly once,
// generically against `SignatureScheme` (see `run`/`cmd_*` below), and
// dispatched to the concrete type in `main`. Adding ML-DSA-87, or a 13th
// SLH-DSA parameter set, later means adding one `Algorithm` variant and
// one match arm in `main` — none of the command logic changes. This is
// the crate's crypto-agility story made concrete: the exact same
// `cmd_keygen`/`cmd_sign`/`cmd_verify`/`test_all` functions below never
// needed to change to pick up a structurally different algorithm family —
// lattice-based, hash-based, or classical elliptic-curve alike — they
// only ever depend on `SignatureScheme`.
//
// `hybrid-demo` (see `run_hybrid_demo` below) is the other half of that
// story: a worked example of *why* agility matters, not just that it
// exists — signing one message with an ML-DSA/SLH-DSA pair at once via
// `Hybrid<A, B>`, so the result only verifies if both independently
// verify. `Hybrid` isn't generic-dispatched through `SignatureScheme`
// the way single algorithms are (see that command's own doc comment for
// why), so it's a separate, hand-written command rather than another
// `Algorithm` variant.
//
// HARDENED:
//  - `sign --sk <hex>` is deprecated in favor of `sign --sk-file <path>`.
//    Passing a secret key as a CLI argument puts it in `ps`/process-listing
//    output on any multi-user box and in shell history (~/.bash_history,
//    ~/.zsh_history) — both are real exposure paths, not theoretical. The
//    hex/Vec buffers used to decode it are also zeroized here, since the
//    zeroization pass in the ring/packing layer never covered this layer.
//  - `keygen` no longer prints the secret key to stdout by default; use
//    `--save` (writes sk.bin with restrictive permissions) or explicit
//    `--show-secret` if you really want it on the terminal.
//  - `hybrid-demo` zeroizes both halves of the composite secret key
//    individually (`sk.primary`/`sk.secondary`) — `HybridSecretKey` has
//    no zeroization of its own, since it's generic over two schemes with
//    no shared representation to zeroize as one buffer.
use std::env;
use std::fs;

use sirraya_crypto::common::ring::zeroize_bytes;
use sirraya_crypto::hybrid::Hybrid;
use sirraya_crypto::traits::SignatureScheme;
use sirraya_crypto::{
    Ed25519, MlDsa44, MlDsa65, SlhDsaSha2_128f, SlhDsaSha2_128s, SlhDsaSha2_192f,
    SlhDsaSha2_192s, SlhDsaSha2_256f, SlhDsaSha2_256s, SlhDsaShake128f, SlhDsaShake128s,
    SlhDsaShake192f, SlhDsaShake192s, SlhDsaShake256f, SlhDsaShake256s,
};

#[derive(Clone, Copy)]
enum Algorithm {
    MlDsa44,
    MlDsa65,
    Ed25519,
    SlhDsaShake128s,
    SlhDsaShake128f,
    SlhDsaShake192s,
    SlhDsaShake192f,
    SlhDsaShake256s,
    SlhDsaShake256f,
    SlhDsaSha2_128s,
    SlhDsaSha2_128f,
    SlhDsaSha2_192s,
    SlhDsaSha2_192f,
    SlhDsaSha2_256s,
    SlhDsaSha2_256f,
}

impl Algorithm {
    fn parse(s: &str) -> Option<Self> {
        match s {
            "ml-dsa-44" | "mldsa44" | "44" => Some(Algorithm::MlDsa44),
            "ml-dsa-65" | "mldsa65" | "65" => Some(Algorithm::MlDsa65),
            "ed25519" | "ed-25519" => Some(Algorithm::Ed25519),
            "slh-dsa-shake-128s" => Some(Algorithm::SlhDsaShake128s),
            "slh-dsa-shake-128f" => Some(Algorithm::SlhDsaShake128f),
            "slh-dsa-shake-192s" => Some(Algorithm::SlhDsaShake192s),
            "slh-dsa-shake-192f" => Some(Algorithm::SlhDsaShake192f),
            "slh-dsa-shake-256s" => Some(Algorithm::SlhDsaShake256s),
            "slh-dsa-shake-256f" => Some(Algorithm::SlhDsaShake256f),
            "slh-dsa-sha2-128s" => Some(Algorithm::SlhDsaSha2_128s),
            "slh-dsa-sha2-128f" => Some(Algorithm::SlhDsaSha2_128f),
            "slh-dsa-sha2-192s" => Some(Algorithm::SlhDsaSha2_192s),
            "slh-dsa-sha2-192f" => Some(Algorithm::SlhDsaSha2_192f),
            "slh-dsa-sha2-256s" => Some(Algorithm::SlhDsaSha2_256s),
            "slh-dsa-sha2-256f" => Some(Algorithm::SlhDsaSha2_256f),
            _ => None,
        }
    }
}

fn main() {
    let mut args: Vec<String> = env::args().collect();

    if args.len() >= 2 && args[1] == "hybrid-demo" {
        run_hybrid_demo(&args);
        return;
    }

    // Pull `--alg <name>` out of the argument list wherever it appears, so
    // subcommand parsing below never has to know about it. Defaults to
    // ML-DSA-44, matching this CLI's behavior before --alg existed.
    let mut alg = Algorithm::MlDsa44;
    if let Some(pos) = args.iter().position(|a| a == "--alg") {
        if pos + 1 >= args.len() {
            eprintln!("--alg requires a value — see `{} help` for the full list", args[0]);
            return;
        }
        match Algorithm::parse(&args[pos + 1]) {
            Some(a) => alg = a,
            None => {
                eprintln!(
                    "Unknown --alg '{}' — see `{} help` for the full list",
                    args[pos + 1], args[0]
                );
                return;
            }
        }
        args.drain(pos..=pos + 1);
    }

    if args.len() < 2 {
        print_usage(&args[0]);
        return;
    }

    match alg {
        Algorithm::MlDsa44 => run::<MlDsa44>(&args),
        Algorithm::MlDsa65 => run::<MlDsa65>(&args),
        Algorithm::Ed25519 => run::<Ed25519>(&args),
        Algorithm::SlhDsaShake128s => run::<SlhDsaShake128s>(&args),
        Algorithm::SlhDsaShake128f => run::<SlhDsaShake128f>(&args),
        Algorithm::SlhDsaShake192s => run::<SlhDsaShake192s>(&args),
        Algorithm::SlhDsaShake192f => run::<SlhDsaShake192f>(&args),
        Algorithm::SlhDsaShake256s => run::<SlhDsaShake256s>(&args),
        Algorithm::SlhDsaShake256f => run::<SlhDsaShake256f>(&args),
        Algorithm::SlhDsaSha2_128s => run::<SlhDsaSha2_128s>(&args),
        Algorithm::SlhDsaSha2_128f => run::<SlhDsaSha2_128f>(&args),
        Algorithm::SlhDsaSha2_192s => run::<SlhDsaSha2_192s>(&args),
        Algorithm::SlhDsaSha2_192f => run::<SlhDsaSha2_192f>(&args),
        Algorithm::SlhDsaSha2_256s => run::<SlhDsaSha2_256s>(&args),
        Algorithm::SlhDsaSha2_256f => run::<SlhDsaSha2_256f>(&args),
    }
}

/// Every subcommand, written once against the trait. `T` is any
/// `SignatureScheme` implementor — ML-DSA, SLH-DSA, and Ed25519 alike;
/// nothing below this line is specific to any one of them.
fn run<T: SignatureScheme>(args: &[String]) {
    match args[1].as_str() {
        "keygen" => cmd_keygen::<T>(args),
        "sign" => cmd_sign::<T>(args),
        "verify" => cmd_verify::<T>(args),
        "test" => test_all::<T>(),
        _ => print_usage(&args[0]),
    }
}

fn print_usage(prog: &str) {
    println!("sirraya-crypto — Post-Quantum, Classical & Hybrid Digital Signatures");
    println!("  (FIPS 204 ML-DSA, FIPS 205 SLH-DSA, RFC 8032 Ed25519)");
    println!();
    println!("  ML-DSA (lattice-based, PQ):  ml-dsa-44 (default), ml-dsa-65");
    println!("  SLH-DSA, SHAKE (hash-based, PQ): slh-dsa-shake-128s, slh-dsa-shake-128f,");
    println!("                               slh-dsa-shake-192s, slh-dsa-shake-192f,");
    println!("                               slh-dsa-shake-256s, slh-dsa-shake-256f");
    println!("  SLH-DSA, SHA2 (hash-based, PQ):  slh-dsa-sha2-128s,  slh-dsa-sha2-128f,");
    println!("                               slh-dsa-sha2-192s,  slh-dsa-sha2-192f,");
    println!("                               slh-dsa-sha2-256s,  slh-dsa-sha2-256f");
    println!("  Ed25519 (elliptic-curve, classical): ed25519");
    println!();
    println!("  Every algorithm above supports the exact same subcommands below —");
    println!("  that's the point: keygen/sign/verify/test are written once, generically,");
    println!("  across post-quantum AND classical algorithms alike (see this file's own");
    println!("  header comment).");
    println!();
    println!("Usage:");
    println!("  {} [--alg <name>] keygen                      Generate and print keypair", prog);
    println!("  {} [--alg <name>] keygen --save               Generate and save to files", prog);
    println!("  {} [--alg <name>] sign --sk-file <path> --msg <str>   Sign a message", prog);
    println!("  {} [--alg <name>] verify --pk <hex> --msg <str> --sig <hex>", prog);
    println!("  {} [--alg <name>] test                        Run self-test", prog);
    println!("  {} hybrid-demo [--pair <name>] [--msg <str>]  Dual-algorithm signing demo", prog);
    println!();
    println!("Examples:");
    println!("  {} keygen", prog);
    println!("  {} --alg ml-dsa-65 keygen --save", prog);
    println!("  {} --alg ed25519 keygen", prog);
    println!("  {} sign --sk-file sk.bin --msg \"hello world\"", prog);
    println!("  {} --alg slh-dsa-shake-192s test", prog);
    println!("  {} hybrid-demo", prog);
    println!("  {} hybrid-demo --pair mldsa65-ed25519 --msg \"firmware v2.3.1\"", prog);
    println!("  {} hybrid-demo --pair mldsa65-slhdsa192f", prog);
}

fn cmd_keygen<T: SignatureScheme>(args: &[String]) {
    let save_to_files = args.contains(&"--save".to_string());
    let show_secret = args.contains(&"--show-secret".to_string());

    let (pk, mut sk) = if let Some(pos) = args.iter().position(|a| a == "--seed") {
        if pos + 1 < args.len() {
            let hex_str = &args[pos + 1];
            let mut bytes = hex::decode(hex_str).expect("Invalid hex seed");
            if bytes.len() != T::SEED_LEN {
                eprintln!(
                    "Seed must be exactly {} bytes ({} hex chars) for {}",
                    T::SEED_LEN,
                    T::SEED_LEN * 2,
                    T::NAME
                );
                zeroize_bytes(&mut bytes);
                return;
            }
            let result = T::keypair_from_seed(&bytes).expect("Key generation failed");
            zeroize_bytes(&mut bytes);
            result
        } else {
            eprintln!("Missing seed value");
            return;
        }
    } else {
        T::keypair().expect("Key generation failed")
    };

    if save_to_files {
        fs::write("pk.bin", pk.as_ref()).expect("Failed to write public key");
        fs::write("sk.bin", sk.as_ref()).expect("Failed to write secret key");
        // Best-effort: restrict sk.bin to owner read/write only. On a
        // world-readable umask this file would otherwise be exposed to
        // every local user, which defeats the point of hardened storage.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions("sk.bin", fs::Permissions::from_mode(0o600));
        }
        println!("Keys saved to pk.bin and sk.bin (sk.bin restricted to 0600 on Unix)");
    }

    println!("======================================================================");
    println!("  {} KEYPAIR", T::NAME);
    println!("======================================================================");
    println!("  Algorithm: {} ({})", T::NAME, fips_label(T::NAME));
    println!();
    println!("  PUBLIC KEY ({} bytes):", T::PUBLIC_KEY_LEN);
    println!("  {}", hex_encode(pk.as_ref()));

    if show_secret {
        println!();
        println!(
            "  SECRET KEY ({} bytes) — visible because --show-secret was passed.",
            T::SECRET_KEY_LEN
        );
        println!("  This will remain in your terminal scrollback/logs. Prefer --save instead.");
        println!("  {}", hex_encode(sk.as_ref()));
    } else if !save_to_files {
        println!();
        println!("  Secret key generated but NOT printed (avoids leaving it in scrollback/logs).");
        println!("  Re-run with --save to write sk.bin, or --show-secret to print it anyway.");
    }
    println!("======================================================================");

    zeroize_bytes(sk.as_mut());
}

fn cmd_sign<T: SignatureScheme>(args: &[String]) {
    let mut sk_hex = String::new();
    let mut sk_file: Option<String> = None;
    let mut message = String::new();
    let mut sig_file = None;

    let mut i = 2;
    while i < args.len() {
        match args[i].as_str() {
            "--sk" => {
                i += 1;
                eprintln!("WARNING: --sk <hex> puts your secret key in argv (visible via `ps`,");
                eprintln!("         /proc, and shell history). Prefer --sk-file <path>.");
                sk_hex = args[i].clone();
            }
            "--sk-file" => { i += 1; sk_file = Some(args[i].clone()); }
            "--msg" => { i += 1; message = args[i].clone(); }
            "--sig" => { i += 1; sig_file = Some(args[i].clone()); }
            _ => { eprintln!("Unknown flag: {}", args[i]); return; }
        }
        i += 1;
    }

    if (sk_hex.is_empty() && sk_file.is_none()) || message.is_empty() {
        eprintln!("Usage: sign --sk-file <path> --msg <message>   (preferred)");
        eprintln!("   or: sign --sk <hex> --msg <message>          (leaks key via argv/history)");
        return;
    }

    let mut sk_bytes = if let Some(path) = sk_file {
        fs::read(&path).expect("Failed to read secret key file")
    } else {
        // The hex string itself (sk_hex, and args[i] it was cloned from)
        // still lives in the process's argv/environment for the process
        // lifetime — that's an OS-level exposure this program cannot
        // clear. We can and do clear our own decoded copy below.
        hex::decode(&sk_hex).expect("Invalid secret key hex")
    };
    if sk_bytes.len() != T::SECRET_KEY_LEN {
        eprintln!("Secret key must be exactly {} bytes for {}", T::SECRET_KEY_LEN, T::NAME);
        zeroize_bytes(&mut sk_bytes);
        return;
    }
    let mut sk = T::secret_key_from_bytes(&sk_bytes).expect("Secret key parse failed");
    zeroize_bytes(&mut sk_bytes);

    let sig = T::sign(&sk, message.as_bytes()).expect("Signing failed");
    zeroize_bytes(sk.as_mut());

    if let Some(path) = sig_file {
        fs::write(&path, sig.as_ref()).expect("Failed to write signature");
        println!("Signature saved to {}", path);
    }

    println!("======================================================================");
    println!("  {} SIGNATURE", T::NAME);
    println!("======================================================================");
    println!("  Message: \"{}\"", message);
    println!("  Signature ({} bytes):", T::SIGNATURE_LEN);
    println!("  {}", hex_encode(sig.as_ref()));
    println!("======================================================================");
}

fn cmd_verify<T: SignatureScheme>(args: &[String]) {
    let mut pk_hex = String::new();
    let mut message = String::new();
    let mut sig_hex = String::new();
    let mut pk_file = None;
    let mut msg_file = None;
    let mut sig_file = None;

    let mut i = 2;
    while i < args.len() {
        match args[i].as_str() {
            "--pk" => {
                i += 1;
                if args[i].ends_with(".bin") || args[i].ends_with(".dat") {
                    pk_file = Some(args[i].clone());
                } else {
                    pk_hex = args[i].clone();
                }
            }
            "--msg" => {
                i += 1;
                if args[i].ends_with(".txt") || args[i].ends_with(".bin") {
                    msg_file = Some(args[i].clone());
                } else {
                    message = args[i].clone();
                }
            }
            "--sig" => {
                i += 1;
                if args[i].ends_with(".bin") || args[i].ends_with(".sig") {
                    sig_file = Some(args[i].clone());
                } else {
                    sig_hex = args[i].clone();
                }
            }
            _ => { eprintln!("Unknown flag: {}", args[i]); return; }
        }
        i += 1;
    }

    let pk_bytes = if let Some(path) = pk_file {
        fs::read(&path).expect("Failed to read public key file")
    } else if !pk_hex.is_empty() {
        hex::decode(&pk_hex).expect("Invalid public key hex")
    } else {
        eprintln!("Missing public key");
        return;
    };

    let msg_bytes = if let Some(path) = msg_file {
        fs::read(&path).expect("Failed to read message file")
    } else if !message.is_empty() {
        message.as_bytes().to_vec()
    } else {
        eprintln!("Missing message");
        return;
    };

    let sig_bytes = if let Some(path) = sig_file {
        fs::read(&path).expect("Failed to read signature file")
    } else if !sig_hex.is_empty() {
        hex::decode(&sig_hex).expect("Invalid signature hex")
    } else {
        eprintln!("Missing signature");
        return;
    };

    let pk = match T::public_key_from_bytes(&pk_bytes) {
        Some(pk) => pk,
        None => {
            eprintln!(
                "Public key must be exactly {} bytes for {} (got {})",
                T::PUBLIC_KEY_LEN,
                T::NAME,
                pk_bytes.len()
            );
            return;
        }
    };
    let sig = match T::signature_from_bytes(&sig_bytes) {
        Some(sig) => sig,
        None => {
            eprintln!(
                "Signature must be exactly {} bytes for {} (got {})",
                T::SIGNATURE_LEN,
                T::NAME,
                sig_bytes.len()
            );
            return;
        }
    };

    println!("======================================================================");
    println!("  {} VERIFICATION", T::NAME);
    println!("======================================================================");

    match T::verify(&pk, &msg_bytes, &sig) {
        Ok(true) => {
            println!("  Status:  ✓ VALID");
            println!("  Message: \"{}\"", String::from_utf8_lossy(&msg_bytes));
        }
        Ok(false) => {
            println!("  Status:  ✗ INVALID - Signature does not match");
        }
        Err(e) => {
            println!("  Status:  ✗ ERROR - {}", e);
        }
    }
    println!("======================================================================");
}

/// `T::NAME` alone doesn't say which spec a scheme belongs to, or even
/// whether it's a FIPS at all; this is the one place that distinction is
/// needed (purely cosmetic, for banner text), so it's a name-prefix check
/// here rather than a new `SignatureScheme::SPEC_LABEL` const nobody else
/// needs.
fn fips_label(name: &str) -> &'static str {
    if name.starts_with("SLH-DSA") {
        "FIPS 205"
    } else if name == "Ed25519" {
        "RFC 8032"
    } else {
        "FIPS 204"
    }
}

fn hex_encode(data: &[u8]) -> String {
    data.iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .chunks(64)
        .map(|c| c.join(""))
        .collect::<Vec<_>>()
        .join("\n  ")
}

fn test_all<T: SignatureScheme>() {
    println!("======================================================================");
    println!("  {} SELF-TEST ({})", T::NAME, fips_label(T::NAME));
    println!("======================================================================");
    println!("  Public Key:  {} bytes", T::PUBLIC_KEY_LEN);
    println!("  Secret Key:  {} bytes", T::SECRET_KEY_LEN);
    println!("  Signature:   {} bytes", T::SIGNATURE_LEN);
    println!();

    println!("  [1/4] Key Generation...");
    let (pk, sk) = T::keypair().unwrap();
    println!("    ✓ Public key:  {} bytes", pk.as_ref().len());
    println!("    ✓ Secret key:  {} bytes", sk.as_ref().len());
    println!("    PK (first 32): {}...", hex_encode(&pk.as_ref()[..32]));

    println!();
    println!("  [2/4] Signing...");
    let msg = format!("{} {} test vector", T::NAME, fips_label(T::NAME));
    let sig = T::sign(&sk, msg.as_bytes()).unwrap();
    println!("    ✓ Message: \"{}\"", msg);
    println!("    ✓ Signature: {} bytes", sig.as_ref().len());
    println!("    Sig (first 32): {}...", hex_encode(&sig.as_ref()[..32]));

    println!();
    println!("  [3/4] Verification...");
    match T::verify(&pk, msg.as_bytes(), &sig) {
        Ok(true) => println!("    ✓ VALID - Signature verified successfully"),
        Ok(false) => println!("    ✗ INVALID - Verification failed"),
        Err(e) => println!("    ✗ ERROR - {}", e),
    }

    println!();
    println!("  [4/4] Tamper Detection...");
    let wrong_msg = b"tampered message";
    match T::verify(&pk, wrong_msg, &sig) {
        Ok(false) => println!("    ✓ Correctly rejected wrong message"),
        Ok(true) => println!("    ✗ FAILED - Accepted wrong message!"),
        Err(_) => println!("    ✓ Rejected with error"),
    }

    let mut bad_sig_bytes = sig.as_ref().to_vec();
    bad_sig_bytes[0] ^= 0xFF;
    let bad_sig = T::signature_from_bytes(&bad_sig_bytes).unwrap();
    match T::verify(&pk, msg.as_bytes(), &bad_sig) {
        Ok(false) => println!("    ✓ Correctly rejected tampered signature"),
        Ok(true) => println!("    ✗ FAILED - Accepted tampered signature!"),
        Err(_) => println!("    ✓ Rejected with error"),
    }

    println!();
    println!("  All tests passed! ✓");
    println!("======================================================================");
}

/// `hybrid-demo` — a worked example of pairing a post-quantum scheme with
/// a classical one (or, for the algorithm-diversity variant, two
/// different post-quantum families) via `Hybrid<A, B>`, motivated by a
/// concrete scenario rather than an abstract capability check.
///
/// **Why this pairing, and why firmware signing specifically:** the
/// default pairing, `MlDsa65` + `Ed25519`, is the standard PQC-transition
/// hybrid pattern — ML-DSA's security rests on the hardness of a lattice
/// problem (Module-LWE/Module-SIS), Ed25519's rests on elliptic-curve
/// discrete log, and a `Hybrid<MlDsa65, Ed25519>` signature only verifies
/// if *both* independently verify. That covers both directions of risk
/// during a PQC transition: Ed25519 is decades-proven against classical
/// attack but offers no quantum resistance at all; ML-DSA is quantum-
/// resistant but, as a standard, young enough that nobody claims the same
/// depth of scrutiny yet. Pairing them means an attacker needs to break
/// *both* to forge a signature, not just whichever one turns out weaker.
/// (The `*-slhdsa*` pairings further down swap the classical half for a
/// second, hash-based post-quantum scheme instead — diversity *within*
/// post-quantum assumptions, a different but also real motivation; see
/// their own comment below.) Firmware and software-update signing is the
/// case where that property is worth its cost (bigger keys, two signing
/// operations): a firmware image signed today may still be trusted,
/// unmodified, a decade from now, on devices that are hard or impossible
/// to re-flash with a new trust root if a signing algorithm is broken in
/// the meantime. That's a long enough trust horizon that hedging against
/// a single algorithm failing is a reasonable engineering call — not a
/// hypothetical one.
///
/// **Why this isn't a 15th `Algorithm` variant:** `Hybrid<A, B>` does not
/// itself implement `SignatureScheme` — `HybridPublicKey`/
/// `HybridSecretKey`/`HybridSignature` hold two heterogeneous byte arrays
/// (one per scheme) rather than one contiguous buffer, so they can't
/// satisfy `AsRef<[u8]>` the way the trait requires without picking a
/// concatenation format neither FIPS nor RFC 8032 defines. This command
/// calls `Hybrid::<A, B>::keypair/sign/verify` directly instead, generic
/// over the two concrete type parameters rather than routed through
/// `SignatureScheme` — see `hybrid.rs` for that combinator itself.
///
/// `--pair` selects one of a curated set of pairings:
///   - **PQ + classical** (the standard transition pattern):
///     `mldsa65-ed25519` (default), `mldsa44-ed25519`,
///     `slhdsa192s-ed25519`, `slhdsa128s-ed25519`
///   - **PQ + PQ** (algorithm diversity within post-quantum signatures,
///     matching NIST security categories 1:1 between the two PQ schemes —
///     no assurance benefit to a Category 5 component backing a Category
///     1 one, or vice versa): `mldsa44-slhdsa128s` / `mldsa44-slhdsa128f`
///     (Category 1), `mldsa65-slhdsa192s` / `mldsa65-slhdsa192f`
///     (Category 3)
fn run_hybrid_demo(args: &[String]) {
    let mut pair = "mldsa65-ed25519".to_string();
    let mut message = "firmware-v2.3.1 build-sha256:9f2a...c71e".to_string();

    let mut i = 2;
    while i < args.len() {
        match args[i].as_str() {
            "--pair" => { i += 1; pair = args[i].clone(); }
            "--msg" => { i += 1; message = args[i].clone(); }
            _ => { eprintln!("Unknown flag: {}", args[i]); return; }
        }
        i += 1;
    }

    println!("======================================================================");
    println!("  HYBRID SIGNING DEMO");
    println!("======================================================================");
    println!("  Scenario: signing a firmware/software update that needs to remain");
    println!("  trustworthy for years, backed by two independent hardness");
    println!("  assumptions rather than betting everything on one. A signature is");
    println!("  accepted only if BOTH algorithms independently verify.");
    println!("======================================================================");
    println!();

    match pair.as_str() {
        // The standard PQC-transition pattern: a post-quantum scheme
        // paired with the classical scheme it's meant to hedge alongside
        // (NIST SP 800-208 and most real hybrid-certificate guidance
        // describe exactly this shape — PQ + classical, not PQ + PQ).
        // Default, because this is the pairing anyone landing on this
        // command for the first time should see.
        "mldsa65-ed25519" => run_pair::<MlDsa65, Ed25519>(&message),
        "mldsa44-ed25519" => run_pair::<MlDsa44, Ed25519>(&message),
        "slhdsa192s-ed25519" => run_pair::<SlhDsaShake192s, Ed25519>(&message),
        "slhdsa128s-ed25519" => run_pair::<SlhDsaShake128s, Ed25519>(&message),
        // Algorithm diversity *within* post-quantum signatures — pairing
        // a lattice-based scheme with a hash-based one, so a break in
        // either the lattice assumption or the hash assumption alone
        // still leaves the composite standing. A real alternative to the
        // pairings above, not a lesser one — see this file's own
        // `hybrid.rs` module docs for both patterns.
        "mldsa44-slhdsa128s" => run_pair::<MlDsa44, SlhDsaShake128s>(&message),
        "mldsa44-slhdsa128f" => run_pair::<MlDsa44, SlhDsaShake128f>(&message),
        "mldsa65-slhdsa192s" => run_pair::<MlDsa65, SlhDsaShake192s>(&message),
        "mldsa65-slhdsa192f" => run_pair::<MlDsa65, SlhDsaShake192f>(&message),
        other => {
            eprintln!(
                "Unknown --pair '{}'. PQ + classical (the standard transition pattern): \
                 mldsa65-ed25519 (default), mldsa44-ed25519, slhdsa192s-ed25519, \
                 slhdsa128s-ed25519. PQ + PQ (algorithm diversity within post-quantum): \
                 mldsa44-slhdsa128s, mldsa44-slhdsa128f, mldsa65-slhdsa192s, mldsa65-slhdsa192f",
                other
            );
        }
    }
}

/// Short, human-readable category for a `SignatureScheme::NAME` — purely
/// cosmetic banner text, same spirit as `fips_label` above.
fn scheme_kind(name: &str) -> &'static str {
    if name == "Ed25519" {
        "elliptic-curve, classical"
    } else if name.starts_with("SLH-DSA") {
        "hash-based, post-quantum"
    } else {
        "lattice-based, post-quantum"
    }
}

/// The actual demo, generic over the two schemes `--pair` selected —
/// this is the part of the story that's reusable for any future
/// `SignatureScheme` pairing, not specific to today's curated list above.
fn run_pair<A: SignatureScheme, B: SignatureScheme>(message: &str) {
    println!("  Primary   ({}): {} — {} B pk / {} B sk / {} B sig",
        scheme_kind(A::NAME), A::NAME, A::PUBLIC_KEY_LEN, A::SECRET_KEY_LEN, A::SIGNATURE_LEN);
    println!("  Secondary ({}): {} — {} B pk / {} B sk / {} B sig",
        scheme_kind(B::NAME), B::NAME, B::PUBLIC_KEY_LEN, B::SECRET_KEY_LEN, B::SIGNATURE_LEN);
    println!();

    println!("  [1/4] Generating both keypairs...");
    let (pk, mut sk) = Hybrid::<A, B>::keypair().expect("hybrid keygen failed");
    println!("    ✓ {} keypair generated", A::NAME);
    println!("    ✓ {} keypair generated", B::NAME);

    println!();
    println!("  [2/4] Signing with both algorithms...");
    println!("    Message: \"{}\"", message);
    let sig = Hybrid::<A, B>::sign(&sk, message.as_bytes()).expect("hybrid signing failed");
    println!("    ✓ {} signature: {} bytes", A::NAME, sig.primary.as_ref().len());
    println!("    ✓ {} signature: {} bytes", B::NAME, sig.secondary.as_ref().len());
    println!("    Combined signature: {} bytes", sig.primary.as_ref().len() + sig.secondary.as_ref().len());

    println!();
    println!("  [3/4] Verifying (requires BOTH to pass)...");
    match Hybrid::<A, B>::verify(&pk, message.as_bytes(), &sig) {
        Ok(true) => println!("    ✓ VALID — both {} and {} independently verified", A::NAME, B::NAME),
        Ok(false) => println!("    ✗ INVALID"),
        Err(e) => println!("    ✗ ERROR - {}", e),
    }

    println!();
    println!("  [4/4] What if only one half of the signature is genuine?");
    println!("        (simulating: attacker forges/corrupts one algorithm's signature");
    println!("        without touching the other — this is the property that matters");
    println!("        if one scheme's hardness assumption is ever broken)");

    let mut primary_bytes = sig.primary.as_ref().to_vec();
    primary_bytes[0] ^= 0xFF;
    let tampered_primary = A::signature_from_bytes(&primary_bytes).expect("same length, must parse");
    let tampered_secondary = B::signature_from_bytes(sig.secondary.as_ref()).expect("same length, must parse");
    let primary_only_bad = sirraya_crypto::hybrid::HybridSignature {
        primary: tampered_primary,
        secondary: tampered_secondary,
    };
    match Hybrid::<A, B>::verify(&pk, message.as_bytes(), &primary_only_bad) {
        Ok(false) => println!(
            "    ✓ {} corrupted, {} intact → hybrid still REJECTS (as required)",
            A::NAME, B::NAME
        ),
        Ok(true) => println!("    ✗ FAILED - accepted with a corrupted primary signature!"),
        Err(_) => println!("    ✓ Rejected with error (as required)"),
    }

    let intact_primary = A::signature_from_bytes(sig.primary.as_ref()).expect("same length, must parse");
    let mut secondary_bytes = sig.secondary.as_ref().to_vec();
    secondary_bytes[0] ^= 0xFF;
    let tampered_secondary2 = B::signature_from_bytes(&secondary_bytes).expect("same length, must parse");
    let secondary_only_bad = sirraya_crypto::hybrid::HybridSignature {
        primary: intact_primary,
        secondary: tampered_secondary2,
    };
    match Hybrid::<A, B>::verify(&pk, message.as_bytes(), &secondary_only_bad) {
        Ok(false) => println!(
            "    ✓ {} intact, {} corrupted → hybrid still REJECTS (as required)",
            A::NAME, B::NAME
        ),
        Ok(true) => println!("    ✗ FAILED - accepted with a corrupted secondary signature!"),
        Err(_) => println!("    ✓ Rejected with error (as required)"),
    }

    zeroize_bytes(sk.primary.as_mut());
    zeroize_bytes(sk.secondary.as_mut());

    println!();
    println!("  Either half being wrong is enough to reject the whole signature —");
    println!("  that's what makes this a genuine hedge, not just a bigger signature.");
    println!("======================================================================");
}