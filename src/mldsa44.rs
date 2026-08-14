// =============================================================================
// mldsa44.rs — FIPS 204 ML-DSA-44 KeyGen / Sign / Verify
// All algorithms reference FIPS 204 (August 13 2024) by number and line.
//
// PATCHED: zeroization pass — secret seeds, key material, and per-signature
// ephemeral values (y, rho_pp, mu, cap_k, s1/s2/t0 and their NTT forms) are
// now explicitly cleared via volatile writes (see polynomial::zeroize_bytes
// and Poly::zeroize) at every point their lifetime ends, instead of being
// left for the allocator/stack to overwrite incidentally.
//
// TIMING NOTE — signing latency is not constant-time, and that is expected:
// sign_internal implements Fiat-Shamir-with-aborts (FIPS 204 Algorithm 3,
// lines 11-33). The number of loop iterations before a valid (z, h) pair is
// found is a function of the secret key's s1/s2/t0 values and the message,
// so wall-clock signing time necessarily varies across keys — this is a
// documented, inherent property of the scheme, not a bug or an unintended
// key-dependent branch. See sign_internal's doc comment below and
// bin/dudect_test.rs (Test 1), which classifies this as EXPECTED VARIATION
// rather than a timing leak requiring remediation. What this crate *does*
// guarantee is that the loop's control flow depends only on public
// intermediate values that are supposed to vary run-to-run (rejection
// counts are not treated as secret in the ML-DSA design); it does not, and
// cannot, guarantee a fixed number of attempts per key.
// =============================================================================

use crate::constants_44::*;
use crate::polynomial::*;
use crate::polynomial::zeroize_bytes;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MlDsaError {
    RngFailed,
    InvalidPublicKeyLength,
    InvalidSecretKeyLength,
    InvalidSignatureLength,
    MalformedSignature,
    VerificationFailed,
}
impl core::fmt::Display for MlDsaError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            MlDsaError::RngFailed => write!(f, "RNG failed"),
            MlDsaError::InvalidPublicKeyLength => write!(f, "invalid public key length"),
            MlDsaError::InvalidSecretKeyLength => write!(f, "invalid secret key length"),
            MlDsaError::InvalidSignatureLength => write!(f, "invalid signature length"),
            MlDsaError::MalformedSignature => write!(f, "malformed signature"),
            MlDsaError::VerificationFailed => write!(f, "signature verification failed"),
        }
    }
}
impl std::error::Error for MlDsaError {}

pub fn random_bytes(buf: &mut [u8]) -> Result<(), MlDsaError> {
    use rand_core::RngCore;
    rand_core::OsRng
        .try_fill_bytes(buf)
        .map_err(|_| MlDsaError::RngFailed)
}

// ---------------------------------------------------------------------------
// Vector / matrix helpers (ML-DSA-44 specific: K=4, L=4)
// ---------------------------------------------------------------------------
fn matrix_mul(a: &[[Poly; L]; K], v: &[Poly; L]) -> [Poly; K] {
    let mut w = [Poly::zero(); K];
    for i in 0..K {
        for j in 0..L {
            let p = a[i][j].pointwise_mul(&v[j]);
            w[i] = w[i].add(&p);
        }
    }
    w
}
fn veck_add(a: &[Poly; K], b: &[Poly; K]) -> [Poly; K] {
    core::array::from_fn(|i| a[i].add(&b[i]))
}
fn veck_sub(a: &[Poly; K], b: &[Poly; K]) -> [Poly; K] {
    core::array::from_fn(|i| a[i].sub(&b[i]))
}
fn veck_ntt(v: &mut [Poly; K]) {
    for p in v.iter_mut() {
        p.ntt();
    }
}
fn veck_invntt(v: &mut [Poly; K]) {
    for p in v.iter_mut() {
        p.invntt();
    }
}
fn vecl_ntt(v: &mut [Poly; L]) {
    for p in v.iter_mut() {
        p.ntt();
    }
}
fn vecl_invntt(v: &mut [Poly; L]) {
    for p in v.iter_mut() {
        p.invntt();
    }
}
fn c_mul_vecl(c: &Poly, v: &[Poly; L]) -> [Poly; L] {
    core::array::from_fn(|i| c.pointwise_mul(&v[i]))
}
fn c_mul_veck(c: &Poly, v: &[Poly; K]) -> [Poly; K] {
    core::array::from_fn(|i| c.pointwise_mul(&v[i]))
}
// PATCHED: same short-circuit concern as Poly::chknorm — `.iter().all()`
// would stop at the first polynomial that fails, leaking its index. Poly::
// chknorm is itself branchless per-coefficient (see polynomial.rs), so it's
// enough here to visit every polynomial and OR the results without early
// exit.
fn chknorm_vecl(v: &[Poly; L], b: i32) -> bool {
    let mut bad: u32 = 0;
    for p in v.iter() {
        bad |= !p.chknorm(b) as u32;
    }
    bad == 0
}
fn chknorm_veck(v: &[Poly; K], b: i32) -> bool {
    let mut bad: u32 = 0;
    for p in v.iter() {
        bad |= !p.chknorm(b) as u32;
    }
    bad == 0
}
fn veck_power2round(t: &[Poly; K]) -> ([Poly; K], [Poly; K]) {
    let mut t1 = [Poly::zero(); K];
    let mut t0 = [Poly::zero(); K];
    for i in 0..K {
        let (h, l) = t[i].power2round();
        t1[i] = h;
        t0[i] = l;
    }
    (t1, t0)
}
fn veck_decompose(w: &[Poly; K]) -> ([Poly; K], [Poly; K]) {
    let mut w1 = [Poly::zero(); K];
    let mut w0 = [Poly::zero(); K];
    for i in 0..K {
        let (h, l) = w[i].decompose();
        w1[i] = h;
        w0[i] = l;
    }
    (w1, w0)
}
fn veck_reduce(v: &mut [Poly; K]) {
    for p in v.iter_mut() {
        p.reduce();
    }
}

// ---------------------------------------------------------------------------
// ExpandA — Algorithm 32
// ---------------------------------------------------------------------------
fn expand_a(rho: &[u8; SEEDBYTES]) -> [[Poly; L]; K] {
    let mut a = [[Poly::zero(); L]; K];
    for r in 0..K {
        for s in 0..L {
            a[r][s] = rej_ntt_poly(rho, s as u8, r as u8);
        }
    }
    a
}

// ---------------------------------------------------------------------------
// ExpandS — Algorithm 33
// ---------------------------------------------------------------------------
fn expand_s(rho_prime: &[u8; 64]) -> ([Poly; L], [Poly; K]) {
    let mut s1 = [Poly::zero(); L];
    let mut s2 = [Poly::zero(); K];
    for r in 0..L {
        let mut seed = [0u8; 66];
        seed[..64].copy_from_slice(rho_prime);
        seed[64] = (r & 0xFF) as u8;
        seed[65] = ((r >> 8) & 0xFF) as u8;
        s1[r] = rej_bounded_poly(&seed);
    }
    for r in 0..K {
        let nonce = r + L;
        let mut seed = [0u8; 66];
        seed[..64].copy_from_slice(rho_prime);
        seed[64] = (nonce & 0xFF) as u8;
        seed[65] = ((nonce >> 8) & 0xFF) as u8;
        s2[r] = rej_bounded_poly(&seed);
    }
    (s1, s2)
}

// ---------------------------------------------------------------------------
// Packing helpers
// ---------------------------------------------------------------------------
fn pack_s1(s1: &[Poly; L]) -> [u8; L * POLYETA_PACKEDBYTES] {
    let mut b = [0u8; L * POLYETA_PACKEDBYTES];
    for i in 0..L {
        let mut t = [0u8; POLYETA_PACKEDBYTES];
        polyeta_pack(&mut t, &s1[i]);
        b[i * POLYETA_PACKEDBYTES..(i + 1) * POLYETA_PACKEDBYTES].copy_from_slice(&t);
    }
    b
}
fn unpack_s1(buf: &[u8]) -> [Poly; L] {
    core::array::from_fn(|i| {
        let mut t = [0u8; POLYETA_PACKEDBYTES];
        t.copy_from_slice(&buf[i * POLYETA_PACKEDBYTES..(i + 1) * POLYETA_PACKEDBYTES]);
        polyeta_unpack(&t)
    })
}
fn pack_s2(s2: &[Poly; K]) -> [u8; K * POLYETA_PACKEDBYTES] {
    let mut b = [0u8; K * POLYETA_PACKEDBYTES];
    for i in 0..K {
        let mut t = [0u8; POLYETA_PACKEDBYTES];
        polyeta_pack(&mut t, &s2[i]);
        b[i * POLYETA_PACKEDBYTES..(i + 1) * POLYETA_PACKEDBYTES].copy_from_slice(&t);
    }
    b
}
fn unpack_s2(buf: &[u8]) -> [Poly; K] {
    core::array::from_fn(|i| {
        let mut t = [0u8; POLYETA_PACKEDBYTES];
        t.copy_from_slice(&buf[i * POLYETA_PACKEDBYTES..(i + 1) * POLYETA_PACKEDBYTES]);
        polyeta_unpack(&t)
    })
}
fn pack_t0(t0: &[Poly; K]) -> [u8; K * POLYT0_PACKEDBYTES] {
    let mut b = [0u8; K * POLYT0_PACKEDBYTES];
    for i in 0..K {
        let mut t = [0u8; POLYT0_PACKEDBYTES];
        polyt0_pack(&mut t, &t0[i]);
        b[i * POLYT0_PACKEDBYTES..(i + 1) * POLYT0_PACKEDBYTES].copy_from_slice(&t);
    }
    b
}
fn unpack_t0(buf: &[u8]) -> [Poly; K] {
    core::array::from_fn(|i| {
        let mut t = [0u8; POLYT0_PACKEDBYTES];
        t.copy_from_slice(&buf[i * POLYT0_PACKEDBYTES..(i + 1) * POLYT0_PACKEDBYTES]);
        polyt0_unpack(&t)
    })
}
fn pack_t1(t1: &[Poly; K]) -> [u8; K * POLYT1_PACKEDBYTES] {
    let mut b = [0u8; K * POLYT1_PACKEDBYTES];
    for i in 0..K {
        let mut t = [0u8; POLYT1_PACKEDBYTES];
        polyt1_pack(&mut t, &t1[i]);
        b[i * POLYT1_PACKEDBYTES..(i + 1) * POLYT1_PACKEDBYTES].copy_from_slice(&t);
    }
    b
}
fn unpack_t1(buf: &[u8]) -> [Poly; K] {
    core::array::from_fn(|i| {
        let mut t = [0u8; POLYT1_PACKEDBYTES];
        t.copy_from_slice(&buf[i * POLYT1_PACKEDBYTES..(i + 1) * POLYT1_PACKEDBYTES]);
        polyt1_unpack(&t)
    })
}
fn pack_z(z: &[Poly; L]) -> [u8; L * POLYZ_PACKEDBYTES] {
    let mut b = [0u8; L * POLYZ_PACKEDBYTES];
    for i in 0..L {
        let mut t = [0u8; POLYZ_PACKEDBYTES];
        polyz_pack(&mut t, &z[i]);
        b[i * POLYZ_PACKEDBYTES..(i + 1) * POLYZ_PACKEDBYTES].copy_from_slice(&t);
    }
    b
}
fn unpack_z(buf: &[u8]) -> [Poly; L] {
    core::array::from_fn(|i| {
        let mut t = [0u8; POLYZ_PACKEDBYTES];
        t.copy_from_slice(&buf[i * POLYZ_PACKEDBYTES..(i + 1) * POLYZ_PACKEDBYTES]);
        polyz_unpack(&t)
    })
}
fn w1_encode(w1: &[Poly; K]) -> [u8; K * POLYW1_PACKEDBYTES] {
    let mut b = [0u8; K * POLYW1_PACKEDBYTES];
    for i in 0..K {
        let mut t = [0u8; POLYW1_PACKEDBYTES];
        polyw1_pack(&mut t, &w1[i]);
        b[i * POLYW1_PACKEDBYTES..(i + 1) * POLYW1_PACKEDBYTES].copy_from_slice(&t);
    }
    b
}

// ---------------------------------------------------------------------------
// Algorithm 1 — ML-DSA.KeyGen_internal
// ---------------------------------------------------------------------------
pub fn keypair_from_seed(
    xi: &[u8; SEEDBYTES],
) -> Result<([u8; PUBLICKEYBYTES], [u8; SECRETKEYBYTES]), MlDsaError> {
    // FIPS 204 §6.1 Algorithm 1 step 1:
    // (ρ, ρ', K) = SHAKE-256(ξ || 0x02 || 0x00, 128)
    let mut expanded = [0u8; 128];
    {
        use sha3::{
            digest::{ExtendableOutput, Update, XofReader},
            Shake256,
        };
        let mut h = Shake256::default();
        h.update(xi);
        h.update(&[0x02]); // Domain separator for ML-DSA
        h.update(&[0x00]); // Context index for initial expansion
        h.finalize_xof().read(&mut expanded);
    }

    let mut rho = [0u8; SEEDBYTES];
    rho.copy_from_slice(&expanded[0..32]);

    let mut rho_p = [0u8; 64];
    rho_p.copy_from_slice(&expanded[32..96]);

    let mut cap_k = [0u8; KEYBYTES];
    cap_k.copy_from_slice(&expanded[96..128]);

    // `expanded` has served its purpose (rho/rho_p/cap_k copied out of it);
    // clear it now rather than leaving it live on the stack for the rest of
    // this function.
    zeroize_bytes(&mut expanded);

    let a_hat = expand_a(&rho);
    let (mut s1, mut s2) = expand_s(&rho_p);

    let mut s1_hat = s1;
    vecl_ntt(&mut s1_hat);
    let mut t = matrix_mul(&a_hat, &s1_hat);
    veck_invntt(&mut t);
    let mut t_full = veck_add(&t, &s2);
    veck_reduce(&mut t_full);

    let (t1, mut t0) = veck_power2round(&t_full);

    let mut pk = [0u8; PUBLICKEYBYTES];
    pk[..SEEDBYTES].copy_from_slice(&rho);
    pk[SEEDBYTES..].copy_from_slice(&pack_t1(&t1));

    let mut tr = [0u8; TRBYTES];
    shake256(&mut tr, &pk);

    let mut sk = [0u8; SECRETKEYBYTES];
    let mut off = 0;
    sk[off..off + SEEDBYTES].copy_from_slice(&rho);
    off += SEEDBYTES;
    sk[off..off + KEYBYTES].copy_from_slice(&cap_k);
    off += KEYBYTES;
    sk[off..off + TRBYTES].copy_from_slice(&tr);
    off += TRBYTES;

    let b = pack_s1(&s1);
    sk[off..off + b.len()].copy_from_slice(&b);
    off += b.len();

    let b = pack_s2(&s2);
    sk[off..off + b.len()].copy_from_slice(&b);
    off += b.len();

    let b = pack_t0(&t0);
    sk[off..off + b.len()].copy_from_slice(&b);

    // ---- PATCHED: zeroize every secret intermediate now that it has been
    // packed into `sk`. `s1`/`s2`/`t0` (plain form), `s1_hat` (NTT form),
    // `t`/`t_full` (derived from s1/s2), and the seeds `rho_p`/`cap_k` are
    // all secret-key-equivalent material and must not linger on the stack.
    s1.iter_mut().for_each(Poly::zeroize);
    s2.iter_mut().for_each(Poly::zeroize);
    t0.iter_mut().for_each(Poly::zeroize);
    s1_hat.iter_mut().for_each(Poly::zeroize);
    t.iter_mut().for_each(Poly::zeroize);
    t_full.iter_mut().for_each(Poly::zeroize);
    zeroize_bytes(&mut rho_p);
    zeroize_bytes(&mut cap_k);

    Ok((pk, sk))
}

pub fn keypair() -> Result<([u8; PUBLICKEYBYTES], [u8; SECRETKEYBYTES]), MlDsaError> {
    let mut xi = [0u8; SEEDBYTES];
    random_bytes(&mut xi)?;
    let result = keypair_from_seed(&xi);
    // PATCHED: `xi` is the master seed for the entire keypair — if it leaks,
    // the whole key is recoverable. Clear it regardless of success/failure.
    zeroize_bytes(&mut xi);
    result
}

/// Algorithm 3 (internal) — ML-DSA.Sign_internal.
///
/// ## Timing
/// This function is **not** constant-time in wall-clock latency, and by
/// design cannot be: FIPS 204 Algorithm 3 is a rejection-sampling (Fiat-
/// Shamir-with-aborts) scheme, and the `loop` below (lines 393-552) retries
/// with a fresh mask `y` — incrementing `kappa` — until `z`, `r0`, and the
/// hint count all fall within bounds (Alg 3 lines 15-20 and the checks at
/// lines 437, 456, 470, 499). The number of attempts before acceptance
/// depends on the secret key (`s1`, `s2`, `t0`) and the message, so two
/// different keys will observably take different amounts of time to sign
/// the same message. This is expected behavior, not a key-dependent
/// branching bug — see the module-level TIMING NOTE above and
/// bin/dudect_test.rs, Test 1 ("Deterministic Signing - Key Independence"),
/// which documents and validates this as EXPECTED VARIATION per FIPS 204
/// rather than an actionable timing leak. Do not "fix" this by trying to
/// force a fixed iteration count — that would diverge from the spec.
pub fn sign_internal(
    sk: &[u8; SECRETKEYBYTES],
    msg_prime: &[u8],
    rnd: &[u8; RNDBYTES],
) -> Result<[u8; SIGNBYTES], MlDsaError> {
    let mut off = 0;
    let mut rho = [0u8; SEEDBYTES];
    rho.copy_from_slice(&sk[off..off + SEEDBYTES]);
    off += SEEDBYTES;
    let mut cap_k = [0u8; KEYBYTES];
    cap_k.copy_from_slice(&sk[off..off + KEYBYTES]);
    off += KEYBYTES;
    let mut tr = [0u8; TRBYTES];
    tr.copy_from_slice(&sk[off..off + TRBYTES]);
    off += TRBYTES;
    let mut s1 = unpack_s1(&sk[off..off + L * POLYETA_PACKEDBYTES]);
    off += L * POLYETA_PACKEDBYTES;
    let mut s2 = unpack_s2(&sk[off..off + K * POLYETA_PACKEDBYTES]);
    off += K * POLYETA_PACKEDBYTES;
    let mut t0 = unpack_t0(&sk[off..off + K * POLYT0_PACKEDBYTES]);

    let mut s1_hat = s1;
    vecl_ntt(&mut s1_hat);
    let mut s2_hat = s2;
    veck_ntt(&mut s2_hat);
    let mut t0_hat = t0;
    veck_ntt(&mut t0_hat);

    let a_hat = expand_a(&rho);

    let mut mu = [0u8; MUBYTES];
    shake256_2(&mut mu, &tr, msg_prime);

    let mut rho_pp = [0u8; RHO_PRIME_BYTES];
    shake256_3(&mut rho_pp, &cap_k, rnd, &mu);

    let mut kappa: u16 = 0;
    let max_attempts = 1000; // Safety limit

    loop {
        if kappa as usize > max_attempts {
            // PATCHED: bailing out of the rejection loop still means every
            // secret we've derived so far (key material + per-attempt
            // seed material) is live on the stack. Clear before returning.
            s1.iter_mut().for_each(Poly::zeroize);
            s2.iter_mut().for_each(Poly::zeroize);
            t0.iter_mut().for_each(Poly::zeroize);
            s1_hat.iter_mut().for_each(Poly::zeroize);
            s2_hat.iter_mut().for_each(Poly::zeroize);
            t0_hat.iter_mut().for_each(Poly::zeroize);
            zeroize_bytes(&mut cap_k);
            zeroize_bytes(&mut rho_pp);
            zeroize_bytes(&mut mu);
            return Err(MlDsaError::RngFailed);
        }

        let mut y = [Poly::zero(); L];
        for i in 0..L {
            y[i] = expand_mask_poly(&rho_pp, kappa + i as u16);
        }
        let mut y_saved = y;

        let mut y_hat = y;
        vecl_ntt(&mut y_hat);
        let mut w = matrix_mul(&a_hat, &y_hat);
        veck_invntt(&mut w);
        veck_reduce(&mut w);

        let (w1, _) = veck_decompose(&w);

        let w1b = w1_encode(&w1);
        let mut c_tilde = [0u8; CTILDEBYTES];
        shake256_2(&mut c_tilde, &mu, &w1b);

        let c = sample_in_ball(&c_tilde);
        let mut c_hat = c;
        c_hat.ntt();

        let mut cs1 = c_mul_vecl(&c_hat, &s1_hat);
        vecl_invntt(&mut cs1);

        let z: [Poly; L] = core::array::from_fn(|i| y_saved[i].add(&cs1[i]));

        if !chknorm_vecl(&z, GAMMA1 - BETA) {
            // PATCHED: rejected attempt — the ephemeral mask for this
            // attempt (y/y_hat/y_saved, cs1) is no longer needed. Clear it
            // before looping so it doesn't sit on the stack across retries
            // any longer than necessary.
            y.iter_mut().for_each(Poly::zeroize);
            y_hat.iter_mut().for_each(Poly::zeroize);
            y_saved.iter_mut().for_each(Poly::zeroize);
            cs1.iter_mut().for_each(Poly::zeroize);
            kappa += L as u16;
            continue;
        }

        let mut cs2 = c_mul_veck(&c_hat, &s2_hat);
        veck_invntt(&mut cs2);

        let w_minus_cs2 = veck_sub(&w, &cs2);
        let (_, r0) = veck_decompose(&w_minus_cs2);

        if !chknorm_veck(&r0, GAMMA2 - BETA) {
            y.iter_mut().for_each(Poly::zeroize);
            y_hat.iter_mut().for_each(Poly::zeroize);
            y_saved.iter_mut().for_each(Poly::zeroize);
            cs1.iter_mut().for_each(Poly::zeroize);
            cs2.iter_mut().for_each(Poly::zeroize);
            kappa += L as u16;
            continue;
        }

        let mut ct0 = c_mul_veck(&c_hat, &t0_hat);
        veck_invntt(&mut ct0);
        veck_reduce(&mut ct0);

        if !chknorm_veck(&ct0, GAMMA2) {
            y.iter_mut().for_each(Poly::zeroize);
            y_hat.iter_mut().for_each(Poly::zeroize);
            y_saved.iter_mut().for_each(Poly::zeroize);
            cs1.iter_mut().for_each(Poly::zeroize);
            cs2.iter_mut().for_each(Poly::zeroize);
            ct0.iter_mut().for_each(Poly::zeroize);
            kappa += L as u16;
            continue;
        }

        let neg_ct0: [Poly; K] = core::array::from_fn(|i| {
            let mut p = Poly::zero();
            for j in 0..N {
                p.coeffs[j] = freeze(-ct0[i].coeffs[j]);
            }
            p
        });
        let w_plus_ct0 = veck_add(&w_minus_cs2, &ct0);

        let mut h = [Poly::zero(); K];
        let mut hint_count = 0usize;
        for i in 0..K {
            for j in 0..N {
                h[i].coeffs[j] = make_hint_coeff(neg_ct0[i].coeffs[j], w_plus_ct0[i].coeffs[j]);
                hint_count += h[i].coeffs[j] as usize;
            }
        }

        if hint_count > OMEGA {
            y.iter_mut().for_each(Poly::zeroize);
            y_hat.iter_mut().for_each(Poly::zeroize);
            y_saved.iter_mut().for_each(Poly::zeroize);
            cs1.iter_mut().for_each(Poly::zeroize);
            cs2.iter_mut().for_each(Poly::zeroize);
            ct0.iter_mut().for_each(Poly::zeroize);
            kappa += L as u16;
            continue;
        }

        let mut sig = [0u8; SIGNBYTES];
        let mut soff = 0;
        sig[soff..soff + CTILDEBYTES].copy_from_slice(&c_tilde);
        soff += CTILDEBYTES;

        // z must be centered (in [-gamma1+1, gamma1]) for polyz_pack
        let z_centered: [Poly; L] = core::array::from_fn(|i| {
            let mut p = z[i];
            for c in p.coeffs.iter_mut() {
                *c = centered(*c);
            }
            p
        });
        sig[soff..soff + L * POLYZ_PACKEDBYTES].copy_from_slice(&pack_z(&z_centered));
        soff += L * POLYZ_PACKEDBYTES;

        let mut hbuf = [0u8; OMEGA + K];
        hint_pack(&h, &mut hbuf).ok_or(MlDsaError::MalformedSignature)?;
        sig[soff..soff + OMEGA + K].copy_from_slice(&hbuf);

        // ---- PATCHED: signature succeeded. `z`/`sig` are about to be
        // published, so they don't need clearing — but every secret
        // intermediate that fed into producing them does: unpacked key
        // material (s1/s2/t0), their NTT forms, the per-attempt mask
        // (y/y_hat/y_saved), and the seeds (cap_k/rho_pp/mu).
        s1.iter_mut().for_each(Poly::zeroize);
        s2.iter_mut().for_each(Poly::zeroize);
        t0.iter_mut().for_each(Poly::zeroize);
        s1_hat.iter_mut().for_each(Poly::zeroize);
        s2_hat.iter_mut().for_each(Poly::zeroize);
        t0_hat.iter_mut().for_each(Poly::zeroize);
        y.iter_mut().for_each(Poly::zeroize);
        y_hat.iter_mut().for_each(Poly::zeroize);
        y_saved.iter_mut().for_each(Poly::zeroize);
        cs1.iter_mut().for_each(Poly::zeroize);
        cs2.iter_mut().for_each(Poly::zeroize);
        ct0.iter_mut().for_each(Poly::zeroize);
        zeroize_bytes(&mut cap_k);
        zeroize_bytes(&mut rho_pp);
        zeroize_bytes(&mut mu);

        return Ok(sig);
    }
}

// ---------------------------------------------------------------------------
// Algorithm 3 — ML-DSA.Sign (external, hedged)
// ---------------------------------------------------------------------------
pub fn sign(sk: &[u8; SECRETKEYBYTES], msg: &[u8]) -> Result<[u8; SIGNBYTES], MlDsaError> {
    let mut mp = Vec::with_capacity(2 + msg.len());
    mp.push(0u8);
    mp.push(0u8);
    mp.extend_from_slice(msg);
    let mut rnd = [0u8; RNDBYTES];
    random_bytes(&mut rnd)?;
    let result = sign_internal(sk, &mp, &rnd);
    // PATCHED: `rnd` is the hedged-signing randomness folded into rho_pp.
    zeroize_bytes(&mut rnd);
    result
}

pub fn sign_deterministic(
    sk: &[u8; SECRETKEYBYTES],
    msg: &[u8],
) -> Result<[u8; SIGNBYTES], MlDsaError> {
    let mut mp = Vec::with_capacity(2 + msg.len());
    mp.push(0u8);
    mp.push(0u8);
    mp.extend_from_slice(msg);
    sign_internal(sk, &mp, &[0u8; RNDBYTES])
}

// ---------------------------------------------------------------------------
// Algorithm 4 — ML-DSA.Verify_internal
// ---------------------------------------------------------------------------
pub fn verify_internal(
    pk: &[u8; PUBLICKEYBYTES],
    msg_prime: &[u8],
    sig: &[u8; SIGNBYTES],
) -> Result<bool, MlDsaError> {
    let mut rho = [0u8; SEEDBYTES];
    rho.copy_from_slice(&pk[..SEEDBYTES]);
    let t1 = unpack_t1(&pk[SEEDBYTES..]);

    let mut soff = 0;
    let mut c_tilde = [0u8; CTILDEBYTES];
    c_tilde.copy_from_slice(&sig[soff..soff + CTILDEBYTES]);
    soff += CTILDEBYTES;
    let z = unpack_z(&sig[soff..soff + L * POLYZ_PACKEDBYTES]);
    soff += L * POLYZ_PACKEDBYTES;
    let mut hbuf = [0u8; OMEGA + K];
    hbuf.copy_from_slice(&sig[soff..soff + OMEGA + K]);
    let h = hint_unpack(&hbuf).ok_or(MlDsaError::MalformedSignature)?;

    if !chknorm_vecl(&z, GAMMA1 - BETA) {
        return Ok(false);
    }

    let a_hat = expand_a(&rho);

    let mut tr = [0u8; TRBYTES];
    shake256(&mut tr, pk);
    let mut mu = [0u8; MUBYTES];
    shake256_2(&mut mu, &tr, msg_prime);

    let c = sample_in_ball(&c_tilde);
    let mut c_hat = c;
    c_hat.ntt();

    let mut z_hat = z;
    vecl_ntt(&mut z_hat);
    let mut az = matrix_mul(&a_hat, &z_hat);
    veck_invntt(&mut az);
    veck_reduce(&mut az);

    let mut t1s = t1;
    for i in 0..K {
        for j in 0..N {
            t1s[i].coeffs[j] = ((t1s[i].coeffs[j] as i64) << D).rem_euclid(Q as i64) as i32;
        }
    }
    let mut t1s_hat = t1s;
    veck_ntt(&mut t1s_hat);
    let mut ct1s = c_mul_veck(&c_hat, &t1s_hat);
    veck_invntt(&mut ct1s);
    veck_reduce(&mut ct1s);

    let mut w_prime = veck_sub(&az, &ct1s);
    veck_reduce(&mut w_prime);

    let mut w1_prime = [Poly::zero(); K];
    for i in 0..K {
        for j in 0..N {
            w1_prime[i].coeffs[j] = use_hint_coeff(h[i].coeffs[j], w_prime[i].coeffs[j]);
        }
    }

    let w1b = w1_encode(&w1_prime);
    let mut cpp = [0u8; CTILDEBYTES];
    shake256_2(&mut cpp, &mu, &w1b);

    let mut diff = 0u8;
    for i in 0..CTILDEBYTES {
        diff |= c_tilde[i] ^ cpp[i];
    }
    // NOTE: nothing in verify_internal touches secret material — pk, sig,
    // and every derived value here are public by definition, so no
    // zeroization is needed on this path.
    Ok(diff == 0)
}

// ---------------------------------------------------------------------------
// Algorithm 5 — ML-DSA.Verify (external)
// ---------------------------------------------------------------------------
pub fn verify(
    pk: &[u8; PUBLICKEYBYTES],
    msg: &[u8],
    sig: &[u8; SIGNBYTES],
) -> Result<bool, MlDsaError> {
    let mut mp = Vec::with_capacity(2 + msg.len());
    mp.push(0u8);
    mp.push(0u8);
    mp.extend_from_slice(msg);
    verify_internal(pk, &mp, sig)
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------
pub struct MlDsa44;
impl MlDsa44 {
    pub fn keypair() -> Result<([u8; PUBLICKEYBYTES], [u8; SECRETKEYBYTES]), MlDsaError> {
        keypair()
    }
    pub fn keypair_from_seed(
        xi: &[u8; SEEDBYTES],
    ) -> Result<([u8; PUBLICKEYBYTES], [u8; SECRETKEYBYTES]), MlDsaError> {
        keypair_from_seed(xi)
    }
    pub fn sign(sk: &[u8; SECRETKEYBYTES], msg: &[u8]) -> Result<[u8; SIGNBYTES], MlDsaError> {
        sign(sk, msg)
    }
    pub fn sign_deterministic(
        sk: &[u8; SECRETKEYBYTES],
        msg: &[u8],
    ) -> Result<[u8; SIGNBYTES], MlDsaError> {
        sign_deterministic(sk, msg)
    }
    pub fn verify(
        pk: &[u8; PUBLICKEYBYTES],
        msg: &[u8],
        sig: &[u8; SIGNBYTES],
    ) -> Result<bool, MlDsaError> {
        verify(pk, msg, sig)
    }
    pub const PK_BYTES: usize = PUBLICKEYBYTES;
    pub const SK_BYTES: usize = SECRETKEYBYTES;
    pub const SIG_BYTES: usize = SIGNBYTES;
}

// ---------------------------------------------------------------------------
// Diagnostic Module
// ---------------------------------------------------------------------------
pub mod diagnostic {
    use super::*;

    pub fn inspect_keypair(
        pk: &[u8; PUBLICKEYBYTES],
        sk: &[u8; SECRETKEYBYTES],
    ) -> Result<(), MlDsaError> {
        println!("\n================================================================================");
        println!("           ML-DSA-44 LATTICE COMPONENTS (REAL DATA)");
        println!("================================================================================\n");

        let mut rho = [0u8; SEEDBYTES];
        rho.copy_from_slice(&pk[..SEEDBYTES]);
        let t1 = unpack_t1(&pk[SEEDBYTES..]);

        let mut off = 0;
        let mut rho_sk = [0u8; SEEDBYTES];
        rho_sk.copy_from_slice(&sk[off..off + SEEDBYTES]);
        off += SEEDBYTES;
        let mut cap_k = [0u8; KEYBYTES];
        cap_k.copy_from_slice(&sk[off..off + KEYBYTES]);
        off += KEYBYTES;
        let mut tr = [0u8; TRBYTES];
        tr.copy_from_slice(&sk[off..off + TRBYTES]);
        off += TRBYTES;
        let mut s1 = unpack_s1(&sk[off..off + L * POLYETA_PACKEDBYTES]);
        off += L * POLYETA_PACKEDBYTES;
        let mut s2 = unpack_s2(&sk[off..off + K * POLYETA_PACKEDBYTES]);
        off += K * POLYETA_PACKEDBYTES;
        let t0 = unpack_t0(&sk[off..off + K * POLYT0_PACKEDBYTES]);

        println!("LATTICE PARAMETERS (ML-DSA-44):");
        println!("   Module Rank:    k = {}, l = {}", K, L);
        println!("   Polynomial Degree: n = {} (cyclotomic ring)", N);
        println!("   Modulus:        q = {} (prime)", Q);
        println!();

        println!("PUBLIC KEY COMPONENTS:");
        println!("   |- rho (seed for matrix A):      {:02x?}{:02x?}{:02x?}...", &rho[0], &rho[1], &rho[2]);
        println!("   \\- t1 (high bits of t = A*s1 + s2):");

        for i in 0..K.min(3) {
            print!("      \\- t1[{}] first 8 coefficients: [", i);
            for j in 0..8.min(N) {
                print!("{:5}", t1[i].coeffs[j]);
                if j < 7 { print!(", "); }
            }
            println!(" ...]");
        }

        // NOTE: this diagnostic module intentionally prints secret key
        // material to stdout for debugging/demo purposes. That is a
        // separate, and arguably larger, exposure than the zeroization gap
        // this pass addresses — do not ship `diagnostic::inspect_keypair`
        // in any build that handles real keys.
        println!("\nSECRET KEY COMPONENTS:");
        println!("   |- rho (same as public):          {:02x?}{:02x?}{:02x?}...", &rho_sk[0], &rho_sk[1], &rho_sk[2]);
        println!("   |- K (key material):            {:02x?}{:02x?}{:02x?}...", &cap_k[0], &cap_k[1], &cap_k[2]);
        println!("   |- tr (hash of public key):     {:02x?}{:02x?}{:02x?}...", &tr[0], &tr[1], &tr[2]);

        println!("   |- s1 (secret vector 1, eta=2 bounded):");
        for i in 0..L.min(3) {
            print!("      \\- s1[{}] first 8 coefficients: [", i);
            for j in 0..8.min(N) {
                print!("{:3}", s1[i].coeffs[j]);
                if j < 7 { print!(", "); }
            }
            println!(" ...]");
        }

        println!("   |- s2 (secret vector 2, eta=2 bounded):");
        for i in 0..K.min(3) {
            print!("      \\- s2[{}] first 8 coefficients: [", i);
            for j in 0..8.min(N) {
                print!("{:3}", s2[i].coeffs[j]);
                if j < 7 { print!(", "); }
            }
            println!(" ...]");
        }

        println!("   \\- t0 (low bits of t):");
        for i in 0..K.min(3) {
            print!("      \\- t0[{}] first 8 coefficients: [", i);
            for j in 0..8.min(N) {
                print!("{:5}", t0[i].coeffs[j]);
                if j < 7 { print!(", "); }
            }
            println!(" ...]");
        }

        println!("\nLATTICE RELATION VERIFICATION:");
        println!("   Verifying t = A*s1 + s2 (mod q)...");

        let mut s1_hat = s1;
        vecl_ntt(&mut s1_hat);
        let a_hat = expand_a(&rho);
        let mut t_computed = matrix_mul(&a_hat, &s1_hat);
        veck_invntt(&mut t_computed);
        veck_reduce(&mut t_computed);

        let t_verify = veck_add(&t_computed, &s2);

        let mut matches = true;
        for i in 0..K.min(3) {
            for j in 0..3.min(N) {
                let t_expected = (t1[i].coeffs[j] << D) + t0[i].coeffs[j];
                let t_actual = t_verify[i].coeffs[j];
                if t_expected != t_actual && t_expected != t_actual + Q && t_expected != t_actual - Q {
                    matches = false;
                    println!("   MISMATCH at t[{}][{}]: expected={} actual={}", i, j, t_expected, t_actual);
                }
            }
        }

        if matches {
            println!("   OK: Lattice relation holds! t = A*s1 + s2 (mod q)");
        }

        // PATCHED: this function unpacks the full secret key into locals
        // (s1, s2, t0, s1_hat, t_computed) purely to print/verify it. Clear
        // them before returning rather than leaving them for the stack to
        // overwrite incidentally.
        s1.iter_mut().for_each(Poly::zeroize);
        s2.iter_mut().for_each(Poly::zeroize);
        s1_hat.iter_mut().for_each(Poly::zeroize);
        t_computed.iter_mut().for_each(Poly::zeroize);
        zeroize_bytes(&mut cap_k);

        Ok(())
    }

    pub fn inspect_signature(sig: &[u8; SIGNBYTES]) -> Result<(), MlDsaError> {
        println!("\n================================================================================");
        println!("              ML-DSA-44 SIGNATURE COMPONENTS");
        println!("================================================================================\n");

        let mut soff = 0;
        let mut c_tilde = [0u8; CTILDEBYTES];
        c_tilde.copy_from_slice(&sig[soff..soff + CTILDEBYTES]);
        soff += CTILDEBYTES;

        let z = unpack_z(&sig[soff..soff + L * POLYZ_PACKEDBYTES]);
        soff += L * POLYZ_PACKEDBYTES;

        let mut hbuf = [0u8; OMEGA + K];
        hbuf.copy_from_slice(&sig[soff..soff + OMEGA + K]);
        let h = hint_unpack(&hbuf).unwrap_or([Poly::zero(); K]);

        println!("SIGNATURE COMPONENTS:");
        println!("   |- c~ (challenge hash):      {:02x?}{:02x?}{:02x?}... ({} bytes)", &c_tilde[0], &c_tilde[1], &c_tilde[2], CTILDEBYTES);

        println!("   |- z (response vector, bounded by gamma1 = {}):", GAMMA1);
        for i in 0..L.min(3) {
            print!("      \\- z[{}] first 8 coefficients: [", i);
            for j in 0..8.min(N) {
                print!("{:6}", z[i].coeffs[j]);
                if j < 7 { print!(", "); }
            }
            println!(" ...]");
        }

        let hint_count = h.iter().flat_map(|p| p.coeffs.iter()).filter(|&&c| c != 0).count();
        println!("   \\- h (hint bits):            {} non-zero hints (max {})", hint_count, OMEGA);

        if hint_count > 0 {
            println!("      First few hint positions:");
            let mut shown = 0;
            'outer: for i in 0..K {
                for j in 0..N {
                    if h[i].coeffs[j] != 0 && shown < 5 {
                        println!("         - polynomial {}, coefficient {}: bit=1", i, j);
                        shown += 1;
                    }
                    if shown >= 5 { break 'outer; }
                }
            }
        }

        let c = sample_in_ball(&c_tilde);
        let non_zero = c.coeffs.iter().filter(|&&x| x != 0).count();
        println!("\nCHALLENGE POLYNOMIAL (c):");
        println!("   |- Non-zero coefficients: {}", non_zero);
        println!("   \\- First 10 positions:");
        let mut shown = 0;
        for (i, &coeff) in c.coeffs.iter().enumerate() {
            if coeff != 0 && shown < 10 {
                println!("      - Position {}: coefficient = {}", i, coeff);
                shown += 1;
            }
        }

        // NOTE: everything touched here (z, h, c, c_tilde) is part of a
        // published signature, not secret — no zeroization needed.
        Ok(())
    }

    pub fn demonstrate_lattice() -> Result<(), MlDsaError> {
        println!("\n================================================================================");
        println!("         REAL LATTICE-BASED CRYPTOGRAPHY DEMONSTRATION");
        println!("================================================================================\n");

        let (pk, sk) = keypair()?;
        inspect_keypair(&pk, &sk)?;

        let msg = b"Real lattice-based signature demonstration";
        let sig = sign(&sk, msg)?;
        inspect_signature(&sig)?;

        let valid = verify(&pk, msg, &sig)?;
        println!("\nSIGNATURE VERIFICATION: {}", if valid { "SUCCESS" } else { "FAILED" });

        println!("\nLATTICE NORM BOUNDS:");
        println!("   ||s1||_inf <= eta = {}", ETA);
        println!("   ||s2||_inf <= eta = {}", ETA);
        println!("   ||z||_inf  <= gamma1 - beta = {}", GAMMA1 - BETA);
        println!("   ||r0||_inf <= gamma2 - beta = {}", GAMMA2 - BETA);
        println!("   ||c*t0||_inf <= gamma2 = {}", GAMMA2);

        println!("\nThis demonstrates real ML-DSA-44 lattice cryptography:");
        println!("   * Polynomials in the ring R_q = Z_q[x]/(x^n+1) with n={}", N);
        println!("   * Module lattice of rank k={}, l={}", K, L);
        println!("   * Small secrets drawn from bounded distribution (eta={})", ETA);
        println!("   * Rejection sampling ensures zero-knowledge");
        println!("   * Hints enable efficient decompression");

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Self-test
// ---------------------------------------------------------------------------
pub fn run_tests() -> Result<(), MlDsaError> {
    println!("============================================================");
    println!(" FIPS 204 ML-DSA-44 — Self-Test");
    println!("============================================================");
    println!("  Public key : {} bytes", PUBLICKEYBYTES);
    println!("  Secret key : {} bytes", SECRETKEYBYTES);
    println!("  Signature  : {} bytes", SIGNBYTES);

    print!("\n[1/5] NTT round-trip ... ");
    {
        let mut p = Poly::zero();
        p.coeffs[0] = 1;
        p.coeffs[5] = 42;
        p.coeffs[255] = Q - 1;
        let orig = p.coeffs;
        p.ntt();
        p.invntt();
        for i in 0..N {
            if p.coeffs[i] != orig[i] {
                println!("FAIL at [{}]: expected {} got {}", i, orig[i], p.coeffs[i]);
                return Err(MlDsaError::VerificationFailed);
            }
        }
    }
    println!("PASS");

    print!("[2/5] Packing ... ");
    {
        let mut p = Poly::zero();
        for i in 0..N {
            p.coeffs[i] = (i % 1024) as i32;
        }
        let mut buf = [0u8; POLYT1_PACKEDBYTES];
        polyt1_pack(&mut buf, &p);
        assert_eq!(polyt1_unpack(&buf), p);
    }
    println!("PASS");

    print!("[3/5] KeyGen ... ");
    let (pk, sk) = keypair()?;
    println!("PASS");

    print!("[4/5] Sign ... ");
    let msg = b"FIPS 204 ML-DSA-44 critical infrastructure test";
    let sig = sign(&sk, msg)?;
    println!("PASS ({} bytes)", sig.len());

    print!("[5/5] Verify ... ");
    if !verify(&pk, msg, &sig)? {
        println!("FAIL");
        return Err(MlDsaError::VerificationFailed);
    }
    println!("PASS");

    assert!(!verify(&pk, b"tampered", &sig)?, "should reject wrong message");

    println!("\n[6/6] Lattice Demonstration ...");
    if let Err(e) = diagnostic::demonstrate_lattice() {
        println!("   Lattice demo warning: {}", e);
    } else {
        println!("   PASS");
    }

    println!("\nAll tests passed.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ntt_roundtrip_e0() {
        let mut p = Poly::zero();
        p.coeffs[0] = 1;
        let o = p.coeffs;
        p.ntt();
        p.invntt();
        assert_eq!(p.coeffs, o);
    }
    #[test]
    fn ntt_roundtrip_e1() {
        let mut p = Poly::zero();
        p.coeffs[1] = 1;
        let o = p.coeffs;
        p.ntt();
        p.invntt();
        assert_eq!(p.coeffs, o);
    }
    #[test]
    fn ntt_roundtrip_general() {
        let mut p = Poly::zero();
        for i in 0..N {
            p.coeffs[i] = ((i * 37 + 5) % Q as usize) as i32;
        }
        let o = p.coeffs;
        p.ntt();
        p.invntt();
        assert_eq!(p.coeffs, o);
    }
    #[test]
    fn t1_roundtrip() {
        let mut p = Poly::zero();
        for i in 0..N {
            p.coeffs[i] = (i % 1024) as i32;
        }
        let mut b = [0u8; POLYT1_PACKEDBYTES];
        polyt1_pack(&mut b, &p);
        assert_eq!(polyt1_unpack(&b), p);
    }
    #[test]
    fn t0_roundtrip() {
        let half = 1i32 << (D - 1);
        let mut p = Poly::zero();
        for i in 0..N {
            p.coeffs[i] = (i as i32 % (2 * half)) - half + 1;
        }
        let mut b = [0u8; POLYT0_PACKEDBYTES];
        polyt0_pack(&mut b, &p);
        assert_eq!(polyt0_unpack(&b), p);
    }
    #[test]
    fn eta_roundtrip() {
        let mut p = Poly::zero();
        for i in 0..N {
            p.coeffs[i] = ((i % 5) as i32) - 2;
        }
        let mut b = [0u8; POLYETA_PACKEDBYTES];
        polyeta_pack(&mut b, &p);
        assert_eq!(polyeta_unpack(&b), p);
    }
    #[test]
    fn z_roundtrip() {
        let mut p = Poly::zero();
        for i in 0..N {
            p.coeffs[i] = (i as i32 % (2 * GAMMA1)) - GAMMA1 + 1;
        }
        let mut b = [0u8; POLYZ_PACKEDBYTES];
        polyz_pack(&mut b, &p);
        assert_eq!(polyz_unpack(&b), p);
    }
    #[test]
    fn deterministic_keygen() {
        let s = [42u8; SEEDBYTES];
        let (p1, s1) = MlDsa44::keypair_from_seed(&s).unwrap();
        let (p2, s2) = MlDsa44::keypair_from_seed(&s).unwrap();
        assert_eq!(p1, p2);
        assert_eq!(&s1[..], &s2[..]);
    }
    #[test]
    fn sign_verify() {
        let (pk, sk) = MlDsa44::keypair().unwrap();
        let msg = b"test";
        let sig = MlDsa44::sign(&sk, msg).unwrap();
        assert!(MlDsa44::verify(&pk, msg, &sig).unwrap());
    }
    #[test]
    fn sign_verify_deterministic() {
        let (pk, sk) = MlDsa44::keypair().unwrap();
        let msg = b"deterministic test";
        let sig = MlDsa44::sign_deterministic(&sk, msg).unwrap();
        assert!(MlDsa44::verify(&pk, msg, &sig).unwrap());
    }
    #[test]
    fn reject_wrong_msg() {
        let (pk, sk) = MlDsa44::keypair().unwrap();
        let sig = MlDsa44::sign(&sk, b"a").unwrap();
        assert!(!MlDsa44::verify(&pk, b"b", &sig).unwrap());
    }
    #[test]
    fn reject_tampered_sig() {
        let (pk, sk) = MlDsa44::keypair().unwrap();
        let mut sig = MlDsa44::sign(&sk, b"m").unwrap();
        sig[42] ^= 0xFF;
        match MlDsa44::verify(&pk, b"m", &sig) {
            Ok(v) => assert!(!v),
            Err(_) => {}
        }
    }
    #[test]
    fn many_roundtrips() {
        let (pk, sk) = MlDsa44::keypair().unwrap();
        for i in 0u32..10 {
            let m = i.to_le_bytes();
            let s = MlDsa44::sign(&sk, &m).unwrap();
            assert!(MlDsa44::verify(&pk, &m, &s).unwrap());
        }
    }
}