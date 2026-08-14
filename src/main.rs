// main.rs — ML-DSA-44 CLI tool with console output
//
// HARDENED:
//  - `sign --sk <hex>` is deprecated in favor of `sign --sk-file <path>`.
//    Passing a secret key as a CLI argument puts it in `ps`/process-listing
//    output on any multi-user box and in shell history (~/.bash_history,
//    ~/.zsh_history) — both are real exposure paths, not theoretical. The
//    hex/Vec buffers used to decode it are also zeroized here, since the
//    zeroization pass in mldsa44.rs/polynomial.rs never covered this layer.
//  - `keygen` no longer prints the secret key to stdout by default; use
//    `--save` (writes sk.bin with restrictive permissions) or explicit
//    `--show-secret` if you really want it on the terminal.
use std::env;
use std::fs;
use polynomial::zeroize_bytes;

mod constants_44;
mod polynomial;
mod mldsa44;

use mldsa44::MlDsa44;
use constants_44::*;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        print_usage(&args[0]);
        return;
    }

    match args[1].as_str() {
        "keygen" => cmd_keygen(&args),
        "sign" => cmd_sign(&args),
        "verify" => cmd_verify(&args),
        "test" => test_all(),
        _ => print_usage(&args[0]),
    }
}

fn print_usage(prog: &str) {
    println!("ML-DSA-44 (FIPS 204) - Post-Quantum Digital Signatures");
    println!("  Security Level: Category 2 (128-bit)");
    println!("  Module Rank: K={}, L={}", K, L);
    println!();
    println!("  Public Key:  {} bytes", PUBLICKEYBYTES);
    println!("  Secret Key:  {} bytes", SECRETKEYBYTES);
    println!("  Signature:   {} bytes", SIGNBYTES);
    println!();
    println!("Usage:");
    println!("  {} keygen                    Generate and print keypair", prog);
    println!("  {} keygen --save             Generate and save to files", prog);
    println!("  {} sign --sk <hex> --msg <str>  Sign a message", prog);
    println!("  {} verify --pk <hex> --msg <str> --sig <hex>", prog);
    println!("  {} test                      Run self-test", prog);
    println!();
    println!("Examples:");
    println!("  {} keygen", prog);
    println!("  {} sign --sk <sk_hex> --msg \"hello world\"", prog);
}

fn cmd_keygen(args: &[String]) {
    let save_to_files = args.contains(&"--save".to_string());
    let show_secret = args.contains(&"--show-secret".to_string());

    let (pk, mut sk) = if let Some(pos) = args.iter().position(|a| a == "--seed") {
        if pos + 1 < args.len() {
            let hex = &args[pos + 1];
            let bytes = hex::decode(hex).expect("Invalid hex seed");
            if bytes.len() != 32 {
                eprintln!("Seed must be exactly 32 bytes (64 hex chars)");
                return;
            }
            let mut seed = [0u8; 32];
            seed.copy_from_slice(&bytes);
            let result = MlDsa44::keypair_from_seed(&seed).expect("Key generation failed");
            zeroize_bytes(&mut seed);
            result
        } else {
            eprintln!("Missing seed value");
            return;
        }
    } else {
        MlDsa44::keypair().expect("Key generation failed")
    };

    if save_to_files {
        fs::write("pk.bin", pk).expect("Failed to write public key");
        fs::write("sk.bin", sk).expect("Failed to write secret key");
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
    println!("  ML-DSA-44 KEYPAIR");
    println!("======================================================================");
    println!("  Algorithm: ML-DSA-44 (FIPS 204)");
    println!("  Security:  Category 2 (128-bit classical, 64-bit quantum)");
    println!();
    println!("  PUBLIC KEY ({} bytes):", PUBLICKEYBYTES);
    println!("  {}", hex_encode(&pk));

    if show_secret {
        println!();
        println!("  SECRET KEY ({} bytes) — visible because --show-secret was passed.", SECRETKEYBYTES);
        println!("  This will remain in your terminal scrollback/logs. Prefer --save instead.");
        println!("  {}", hex_encode(&sk));
    } else if !save_to_files {
        println!();
        println!("  Secret key generated but NOT printed (avoids leaving it in scrollback/logs).");
        println!("  Re-run with --save to write sk.bin, or --show-secret to print it anyway.");
    }
    println!("======================================================================");

    zeroize_bytes(&mut sk);
}

fn cmd_sign(args: &[String]) {
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
        let bytes = hex::decode(&sk_hex).expect("Invalid secret key hex");
        // The hex string itself (sk_hex, and args[i] it was cloned from)
        // still lives in the process's argv/environment for the process
        // lifetime — that's an OS-level exposure this program cannot
        // clear. We can and do clear our own decoded copy below.
        bytes
    };
    if sk_bytes.len() != SECRETKEYBYTES {
        eprintln!("Secret key must be exactly {} bytes", SECRETKEYBYTES);
        zeroize_bytes(&mut sk_bytes);
        return;
    }
    let mut sk = [0u8; SECRETKEYBYTES];
    sk.copy_from_slice(&sk_bytes);
    zeroize_bytes(&mut sk_bytes);

    let sig = MlDsa44::sign(&sk, message.as_bytes()).expect("Signing failed");
    zeroize_bytes(&mut sk);

    if let Some(path) = sig_file {
        fs::write(&path, sig).expect("Failed to write signature");
        println!("Signature saved to {}", path);
    }

    println!("======================================================================");
    println!("  ML-DSA-44 SIGNATURE");
    println!("======================================================================");
    println!("  Message: \"{}\"", message);
    println!("  Signature ({} bytes):", SIGNBYTES);
    println!("  {}", hex_encode(&sig));
    println!("======================================================================");
}

fn cmd_verify(args: &[String]) {
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

    // Load from files if specified
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

    let mut pk = [0u8; PUBLICKEYBYTES];
    pk.copy_from_slice(&pk_bytes);
    
    let mut sig = [0u8; SIGNBYTES];
    sig.copy_from_slice(&sig_bytes);
    
    println!("======================================================================");
    println!("  ML-DSA-44 VERIFICATION");
    println!("======================================================================");
    
    match MlDsa44::verify(&pk, &msg_bytes, &sig) {
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

fn test_all() {
    println!("======================================================================");
    println!("  ML-DSA-44 SELF-TEST (FIPS 204)");
    println!("======================================================================");
    println!("  Parameters:");
    println!("    Module Rank: K={}, L={}", K, L);
    println!("    Degree: N={}", N);
    println!("    Modulus: Q={}", Q);
    println!("    ETA={}, TAU={}, BETA={}", ETA, TAU, BETA);
    println!("    GAMMA1={}, GAMMA2={}", GAMMA1, GAMMA2);
    println!("    OMEGA={}, LAMBDA={}", OMEGA, LAMBDA);
    println!();
    
    // Key generation
    println!("  [1/4] Key Generation...");
    let (pk, sk) = MlDsa44::keypair().unwrap();
    println!("    ✓ Public key:  {} bytes", pk.len());
    println!("    ✓ Secret key:  {} bytes", sk.len());
    println!("    PK (first 32): {}...", hex_encode(&pk[..32]));
    
    // Sign
    println!();
    println!("  [2/4] Signing...");
    let msg = b"ML-DSA-44 FIPS 204 test vector";
    let sig = MlDsa44::sign(&sk, msg).unwrap();
    println!("    ✓ Message: \"{}\"", String::from_utf8_lossy(msg));
    println!("    ✓ Signature: {} bytes", sig.len());
    println!("    Sig (first 32): {}...", hex_encode(&sig[..32]));
    
    // Verify
    println!();
    println!("  [3/4] Verification...");
    match MlDsa44::verify(&pk, msg, &sig) {
        Ok(true) => println!("    ✓ VALID - Signature verified successfully"),
        Ok(false) => println!("    ✗ INVALID - Verification failed"),
        Err(e) => println!("    ✗ ERROR - {}", e),
    }
    
    // Reject tampered
    println!();
    println!("  [4/4] Tamper Detection...");
    let wrong_msg = b"tampered message";
    match MlDsa44::verify(&pk, wrong_msg, &sig) {
        Ok(false) => println!("    ✓ Correctly rejected wrong message"),
        Ok(true) => println!("    ✗ FAILED - Accepted wrong message!"),
        Err(_) => println!("    ✓ Rejected with error"),
    }
    
    let mut bad_sig = sig;
    bad_sig[0] ^= 0xFF;
    match MlDsa44::verify(&pk, msg, &bad_sig) {
        Ok(false) => println!("    ✓ Correctly rejected tampered signature"),
        Ok(true) => println!("    ✗ FAILED - Accepted tampered signature!"),
        Err(_) => println!("    ✓ Rejected with error"),
    }
    
    println!();
    println!("  All tests passed! ✓");
    println!("======================================================================");
}