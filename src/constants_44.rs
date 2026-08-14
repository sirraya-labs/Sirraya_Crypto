// constants_44.rs — FIPS 204 ML-DSA-44. Every value cited to spec page/algorithm.
// Based on FIPS 204 (August 13, 2024) - ML-DSA-44 parameter set

pub const N: usize = 256; // Table 1 (same for all)
pub const Q: i32 = 8_380_417; // §2.3 (same for all)
pub const D: i32 = 13; // Table 1 (same for all)

// ML-DSA-44 specific parameters (Table 1)
pub const K: usize = 4; // Table 1 ML-DSA-44 (module rank)
pub const L: usize = 4; // Table 1 ML-DSA-44 (module rank)
pub const ETA: i32 = 2; // Table 1 ML-DSA-44 (bound for secrets)
pub const TAU: usize = 39; // Table 1 ML-DSA-44 (weight of challenge)
pub const BETA: i32 = 78; // Table 1: τ·η = 39 * 2
pub const GAMMA1: i32 = 1 << 17; // Table 1 ML-DSA-44 (2^17 = 131072)
pub const GAMMA2: i32 = (Q - 1) / 88; // Table 1 ML-DSA-44 = 95232
pub const OMEGA: usize = 80; // Table 1 ML-DSA-44 (max hint bits)
pub const LAMBDA: usize = 128; // Table 1 ML-DSA-44 (security level bits)

// Challenge hash size: λ/4 bytes (FIPS 204 §3.1)
pub const CTILDEBYTES: usize = LAMBDA / 4; // = 32 bytes for ML-DSA-44

// ML-DSA-44 key and signature sizes (Table 2)
pub const PUBLICKEYBYTES: usize = 1312; // Table 2: ρ(32) + t1(K×320=1280)
pub const SECRETKEYBYTES: usize = 2560; // Table 2: ρ(32)+K(32)+tr(64)+s1(384)+s2(384)+t0(1664)

pub const SIGNBYTES: usize = CTILDEBYTES + L * POLYZ_PACKEDBYTES + OMEGA + K; // = 2420

pub const SEEDBYTES: usize = 32; // Alg 6 line 1 (ρ)
pub const KEYBYTES: usize = 32; // Alg 6 line 1 (K)
pub const TRBYTES: usize = 64; // Alg 6 line 9 (tr = H(pk, 64))
pub const RNDBYTES: usize = 32; // Alg 2 line 5
pub const MUBYTES: usize = 64; // Alg 7 line 6
pub const RHO_PRIME_BYTES: usize = 64; // Alg 7 line 7

// Packing sizes - ML-DSA-44 specific
pub const POLYT1_PACKEDBYTES: usize = 320; // Alg 22: 256×10/8 (same for all)
pub const POLYT0_PACKEDBYTES: usize = 416; // Alg 24: 256×13/8 (same for all)
pub const POLYETA_PACKEDBYTES: usize = 96; // Alg 24: 256×3/8 (η=2 → 3 bits)
pub const POLYZ_PACKEDBYTES: usize = 576; // Alg 26: 256×18/8 (γ₁=2^17 → 18 bits)
pub const POLYW1_PACKEDBYTES: usize = 192; // Alg 28: 256×6/8 (γ₂=(q-1)/88 → 6 bits)

/// q⁻¹ mod 2³². Algorithm 49 line 1. q·QINV ≡ 1 (mod 2³²).
pub const QINV: i32 = 58_728_449;

/// R = 2³² mod q. (Appendix A)
pub const MONT: i32 = 4_193_792;

/// Zeta table — FIPS 204 Appendix B (p.51), verbatim.
/// Same for all ML-DSA parameter sets (depends only on N=256 and Q).
pub const ZETAS: [i32; 256] = [
    0, 4808194, 3765607, 3761513, 5178923, 5496691, 5234739, 5178987, 7778734, 3542485, 2682288,
    2129892, 3764867, 7375178, 557458, 7159240, 5010068, 4317364, 2663378, 6705802, 4855975,
    7946292, 676590, 7044481, 5152541, 1714295, 2453983, 1460718, 7737789, 4795319, 2815639,
    2283733, 3602218, 3182878, 2740543, 4793971, 5269599, 2101410, 3704823, 1159875, 394148,
    928749, 1095468, 4874037, 2071829, 4361428, 3241972, 2156050, 3415069, 1759347, 7562881,
    4805951, 3756790, 6444618, 6663429, 4430364, 5483103, 3192354, 556856, 3870317, 2917338,
    1853806, 3345963, 1858416, 3073009, 1277625, 5744944, 3852015, 4183372, 5157610, 5258977,
    8106357, 2508980, 2028118, 1937570, 4564692, 2811291, 5396636, 7270901, 4158088, 1528066,
    482649, 1148858, 5418153, 7814814, 169688, 2462444, 5046034, 4213992, 4892034, 1987814,
    5183169, 1736313, 235407, 5130263, 3258457, 5801164, 1787943, 5989328, 6125690, 3482206,
    4197502, 7080401, 6018354, 7062739, 2461387, 3035980, 621164, 3901472, 7153756, 2925816,
    3374250, 1356448, 5604662, 2683270, 5601629, 4912752, 2312838, 7727142, 7921254, 348812,
    8052569, 1011223, 6026202, 4561790, 6458164, 6143691, 1744507, 1753, 6444997, 5720892, 6924527,
    2660408, 6600190, 8321269, 2772600, 1182243, 87208, 636927, 4415111, 4423672, 6084020, 5095502,
    4663471, 8352605, 822541, 1009365, 5926272, 6400920, 1596822, 4423473, 4620952, 6695264,
    4969849, 2678278, 4611469, 4829411, 635956, 8129971, 5925040, 4234153, 6607829, 2192938,
    6653329, 2387513, 4768667, 8111961, 5199961, 3747250, 2296099, 1239911, 4541938, 3195676,
    2642980, 1254190, 8368000, 2998219, 141835, 8291116, 2513018, 7025525, 613238, 7070156,
    6161950, 7921677, 6458423, 4040196, 4908348, 2039144, 6500539, 7561656, 6201452, 6757063,
    2105286, 6006015, 6346610, 586241, 7200804, 527981, 5637006, 6903432, 1994046, 2491325,
    6987258, 507927, 7192532, 7655613, 6545891, 5346675, 8041997, 2647994, 3009748, 5767564,
    4148469, 749577, 4357667, 3980599, 2569011, 6764887, 1723229, 1665318, 2028038, 1163598,
    5011144, 3994671, 8368538, 7009900, 3020393, 3363542, 214880, 545376, 7609976, 3105558,
    7277073, 508145, 7826699, 860144, 3430436, 140244, 6866265, 6195333, 3123762, 2358373, 6187330,
    5365997, 6663603, 2926054, 7987710, 8077412, 3531229, 4405932, 4606686, 1900052, 7598542,
    1054478, 7648983,
];

/// Size of t1 vector in bytes: K × POLYT1_PACKEDBYTES = 4 × 320 = 1280
pub const T1_BYTES: usize = K * POLYT1_PACKEDBYTES;

/// Size of t0 vector in bytes: K × POLYT0_PACKEDBYTES = 4 × 416 = 1664
pub const T0_BYTES: usize = K * POLYT0_PACKEDBYTES;

/// Size of s1 vector in bytes: L × POLYETA_PACKEDBYTES = 4 × 96 = 384
pub const S1_BYTES: usize = L * POLYETA_PACKEDBYTES;

/// Size of s2 vector in bytes: K × POLYETA_PACKEDBYTES = 4 × 96 = 384
pub const S2_BYTES: usize = K * POLYETA_PACKEDBYTES;

/// Size of z vector in bytes: L × POLYZ_PACKEDBYTES = 4 × 576 = 2304
pub const Z_BYTES: usize = L * POLYZ_PACKEDBYTES;

/// Size of packed hint vector: OMEGA + K = 80 + 4 = 84
pub const H_BYTES: usize = OMEGA + K;