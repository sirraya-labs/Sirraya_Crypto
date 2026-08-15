// main.rs — ML-DSA CLI tool with console output.
//
// Supports every FIPS 204 parameter set the crate implements — currently
// ML-DSA-44 (default) and ML-DSA-65 — selected with `--alg`. Every
// subcommand (`keygen`/`sign`/`verify`/`test`) is written exactly once,
// generically against `SignatureScheme` (see `run`/`cmd_*` below), and
// dispatched to the concrete type in `main`. Adding ML-DSA-87 later means
// adding one `Algorithm` variant and one match arm in `main` — none of the
// command logic changes, the same way adding the parameter set itself
// didn't require touching `hybrid.rs` or `common::ring`.
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
use std::env;
use std::fs;

use sirraya_crypto::common::ring::zeroize_bytes;
use sirraya_crypto::traits::SignatureScheme;
use sirraya_crypto::{MlDsa44, MlDsa65};

#[derive(Clone, Copy)]
enum Algorithm {
    MlDsa44,
    MlDsa65,
}

impl Algorithm {
    fn parse(s: &str) -> Option<Self> {
        match s {
            "ml-dsa-44" | "mldsa44" | "44" => Some(Algorithm::MlDsa44),
            "ml-dsa-65" | "mldsa65" | "65" => Some(Algorithm::MlDsa65),
            _ => None,
        }
    }
}

fn main() {
    let mut args: Vec<String> = env::args().collect();

    // Pull `--alg <name>` out of the argument list wherever it appears, so
    // subcommand parsing below never has to know about it. Defaults to
    // ML-DSA-44, matching this CLI's behavior before --alg existed.
    let mut alg = Algorithm::MlDsa44;
    if let Some(pos) = args.iter().position(|a| a == "--alg") {
        if pos + 1 >= args.len() {
            eprintln!("--alg requires a value: ml-dsa-44 or ml-dsa-65");
            return;
        }
        match Algorithm::parse(&args[pos + 1]) {
            Some(a) => alg = a,
            None => {
                eprintln!(
                    "Unknown --alg '{}': expected ml-dsa-44 or ml-dsa-65",
                    args[pos + 1]
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
    }
}

/// Every subcommand, written once against the trait. `T` is `MlDsa44` or
/// `MlDsa65` here — nothing below this line is parameter-set-specific.
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
    println!("ML-DSA (FIPS 204) - Post-Quantum Digital Signatures");
    println!("  Supported algorithms: ml-dsa-44 (default), ml-dsa-65");
    println!("  Select with: --alg ml-dsa-44 | --alg ml-dsa-65");
    println!();
    println!("Usage:");
    println!("  {} [--alg <name>] keygen                      Generate and print keypair", prog);
    println!("  {} [--alg <name>] keygen --save               Generate and save to files", prog);
    println!("  {} [--alg <name>] sign --sk-file <path> --msg <str>   Sign a message", prog);
    println!("  {} [--alg <name>] verify --pk <hex> --msg <str> --sig <hex>", prog);
    println!("  {} [--alg <name>] test                        Run self-test", prog);
    println!();
    println!("Examples:");
    println!("  {} keygen", prog);
    println!("  {} --alg ml-dsa-65 keygen --save", prog);
    println!("  {} sign --sk-file sk.bin --msg \"hello world\"", prog);
    println!("  {} --alg ml-dsa-65 test", prog);
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
    println!("  Algorithm: {} (FIPS 204)", T::NAME);
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
    println!("  {} SELF-TEST (FIPS 204)", T::NAME);
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
    let msg = format!("{} FIPS 204 test vector", T::NAME);
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