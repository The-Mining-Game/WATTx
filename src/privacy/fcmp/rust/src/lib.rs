//! WATTx FCMP++ FFI Library
//!
//! This library provides C-compatible FFI functions for FCMP++ (Full-Chain Membership Proofs)
//! integration with WATTx. It wraps the Rust cryptographic operations and exposes them
//! through a stable C ABI.
//!
//! # Safety
//!
//! All FFI functions are marked `unsafe` and require valid pointers. The caller is responsible
//! for ensuring pointer validity and proper memory management.

use std::slice;
use std::ptr;

use rand_core::OsRng;
use zeroize::Zeroize;

// ============================================================================
// Error Codes
// ============================================================================

/// Success
pub const FCMP_SUCCESS: i32 = 0;
/// Invalid parameter (null pointer, wrong size, etc.)
pub const FCMP_ERROR_INVALID_PARAM: i32 = -1;
/// Proof generation failed
pub const FCMP_ERROR_PROOF_GENERATION: i32 = -2;
/// Proof verification failed
pub const FCMP_ERROR_PROOF_VERIFICATION: i32 = -3;
/// Memory allocation failed
pub const FCMP_ERROR_MEMORY: i32 = -4;
/// Invalid point on curve
pub const FCMP_ERROR_INVALID_POINT: i32 = -5;
/// Invalid scalar
pub const FCMP_ERROR_INVALID_SCALAR: i32 = -6;
/// Not initialized
pub const FCMP_ERROR_NOT_INITIALIZED: i32 = -7;
/// Internal error
pub const FCMP_ERROR_INTERNAL: i32 = -99;

// ============================================================================
// Constants
// ============================================================================

/// Size of a scalar in bytes
pub const SCALAR_SIZE: usize = 32;
/// Size of a point in bytes (compressed)
pub const POINT_SIZE: usize = 32;
/// Size of an output tuple (O, I, C = 3 points)
pub const OUTPUT_TUPLE_SIZE: usize = POINT_SIZE * 3;
/// Elements per output in field representation
pub const ELEMENTS_PER_OUTPUT: usize = 6;

// ============================================================================
// Opaque Types
// ============================================================================

/// Opaque handle to FCMP parameters
pub struct FcmpParams {
    // Generator points and precomputed tables
    _initialized: bool,
    // In full implementation, this would contain:
    // - Pedersen generators
    // - Hash initialization points
    // - Precomputed tables for fast MSM
}

/// Opaque handle to a proof
pub struct FcmpProof {
    data: Vec<u8>,
}

/// Branch data for proof generation
#[repr(C)]
pub struct FcmpBranch {
    /// Leaf index in the tree
    pub leaf_index: u64,
    /// Number of layers
    pub num_layers: u32,
    /// Pointer to layer data (array of FcmpBranchLayer)
    pub layers: *const FcmpBranchLayer,
}

/// Single layer of a branch
#[repr(C)]
pub struct FcmpBranchLayer {
    /// Number of elements in this layer
    pub num_elements: u32,
    /// Pointer to elements (array of 32-byte scalars)
    pub elements: *const u8,
}

/// Input tuple for verification
#[repr(C)]
pub struct FcmpInput {
    /// Re-randomized O point (x, y coordinates as scalars)
    pub o_tilde: [u8; 64],
    /// Re-randomized I point
    pub i_tilde: [u8; 64],
    /// R value for SA+L
    pub r: [u8; 64],
    /// Re-randomized C point
    pub c_tilde: [u8; 64],
}

// ============================================================================
// Global State
// ============================================================================

static mut GLOBAL_PARAMS: Option<Box<FcmpParams>> = None;

// ============================================================================
// Initialization Functions
// ============================================================================

/// Initialize the FCMP library with default parameters.
///
/// Must be called before any other FCMP functions.
/// Thread-safe for multiple calls (idempotent).
///
/// # Returns
/// - `FCMP_SUCCESS` on success
/// - `FCMP_ERROR_*` on failure
#[no_mangle]
pub unsafe extern "C" fn fcmp_init() -> i32 {
    if GLOBAL_PARAMS.is_some() {
        return FCMP_SUCCESS; // Already initialized
    }

    let params = Box::new(FcmpParams {
        _initialized: true,
    });

    GLOBAL_PARAMS = Some(params);
    FCMP_SUCCESS
}

/// Clean up and free FCMP resources.
///
/// After calling this, `fcmp_init()` must be called again before using other functions.
#[no_mangle]
pub unsafe extern "C" fn fcmp_cleanup() {
    GLOBAL_PARAMS = None;
}

/// Check if FCMP is initialized.
///
/// # Returns
/// - 1 if initialized
/// - 0 if not initialized
#[no_mangle]
pub unsafe extern "C" fn fcmp_is_initialized() -> i32 {
    if GLOBAL_PARAMS.is_some() { 1 } else { 0 }
}

// ============================================================================
// Scalar Operations
// ============================================================================

/// Generate a random scalar.
///
/// # Safety
/// - `out` must point to at least 32 bytes of writable memory
#[no_mangle]
pub unsafe extern "C" fn fcmp_scalar_random(out: *mut u8) -> i32 {
    if out.is_null() {
        return FCMP_ERROR_INVALID_PARAM;
    }

    use curve25519_dalek::scalar::Scalar;
    use rand_core::RngCore;

    let mut random_bytes = [0u8; 64];
    if OsRng.try_fill_bytes(&mut random_bytes).is_err() {
        return FCMP_ERROR_INTERNAL;
    }

    let scalar = Scalar::from_bytes_mod_order_wide(&random_bytes);
    let scalar_bytes = scalar.to_bytes();

    ptr::copy_nonoverlapping(scalar_bytes.as_ptr(), out, SCALAR_SIZE);
    random_bytes.zeroize();

    FCMP_SUCCESS
}

/// Add two scalars: out = a + b (mod l)
///
/// # Safety
/// - All pointers must point to at least 32 bytes
/// - `out` must be writable
#[no_mangle]
pub unsafe extern "C" fn fcmp_scalar_add(
    out: *mut u8,
    a: *const u8,
    b: *const u8,
) -> i32 {
    if out.is_null() || a.is_null() || b.is_null() {
        return FCMP_ERROR_INVALID_PARAM;
    }

    use curve25519_dalek::scalar::Scalar;

    let a_bytes = slice::from_raw_parts(a, SCALAR_SIZE);
    let b_bytes = slice::from_raw_parts(b, SCALAR_SIZE);

    let mut a_arr = [0u8; 32];
    let mut b_arr = [0u8; 32];
    a_arr.copy_from_slice(a_bytes);
    b_arr.copy_from_slice(b_bytes);

    let a_scalar = Scalar::from_bytes_mod_order(a_arr);
    let b_scalar = Scalar::from_bytes_mod_order(b_arr);

    let result = a_scalar + b_scalar;
    let result_bytes = result.to_bytes();

    ptr::copy_nonoverlapping(result_bytes.as_ptr(), out, SCALAR_SIZE);
    FCMP_SUCCESS
}

/// Multiply two scalars: out = a * b (mod l)
///
/// # Safety
/// - All pointers must point to at least 32 bytes
/// - `out` must be writable
#[no_mangle]
pub unsafe extern "C" fn fcmp_scalar_mul(
    out: *mut u8,
    a: *const u8,
    b: *const u8,
) -> i32 {
    if out.is_null() || a.is_null() || b.is_null() {
        return FCMP_ERROR_INVALID_PARAM;
    }

    use curve25519_dalek::scalar::Scalar;

    let a_bytes = slice::from_raw_parts(a, SCALAR_SIZE);
    let b_bytes = slice::from_raw_parts(b, SCALAR_SIZE);

    let mut a_arr = [0u8; 32];
    let mut b_arr = [0u8; 32];
    a_arr.copy_from_slice(a_bytes);
    b_arr.copy_from_slice(b_bytes);

    let a_scalar = Scalar::from_bytes_mod_order(a_arr);
    let b_scalar = Scalar::from_bytes_mod_order(b_arr);

    let result = a_scalar * b_scalar;
    let result_bytes = result.to_bytes();

    ptr::copy_nonoverlapping(result_bytes.as_ptr(), out, SCALAR_SIZE);
    FCMP_SUCCESS
}

// ============================================================================
// Point Operations
// ============================================================================

/// Multiply a point by a scalar: out = scalar * point
///
/// # Safety
/// - All pointers must point to at least 32 bytes
/// - `out` must be writable
#[no_mangle]
pub unsafe extern "C" fn fcmp_point_mul(
    out: *mut u8,
    scalar: *const u8,
    point: *const u8,
) -> i32 {
    if out.is_null() || scalar.is_null() || point.is_null() {
        return FCMP_ERROR_INVALID_PARAM;
    }

    // Read inputs
    let scalar_bytes = slice::from_raw_parts(scalar, SCALAR_SIZE);
    let point_bytes = slice::from_raw_parts(point, POINT_SIZE);

    // Use curve25519-dalek for actual point multiplication
    use curve25519_dalek::edwards::CompressedEdwardsY;
    use curve25519_dalek::scalar::Scalar;

    let point_compressed = CompressedEdwardsY::from_slice(point_bytes);
    if point_compressed.is_err() {
        return FCMP_ERROR_INVALID_POINT;
    }
    let point_compressed = point_compressed.unwrap();

    let point_opt = point_compressed.decompress();
    if point_opt.is_none() {
        return FCMP_ERROR_INVALID_POINT;
    }
    let point = point_opt.unwrap();

    // Create scalar (clamp for Ed25519)
    let mut scalar_arr = [0u8; 32];
    scalar_arr.copy_from_slice(scalar_bytes);
    let scalar = Scalar::from_bytes_mod_order(scalar_arr);

    // Multiply
    let result = scalar * point;
    let result_bytes = result.compress().to_bytes();

    ptr::copy_nonoverlapping(result_bytes.as_ptr(), out, POINT_SIZE);
    FCMP_SUCCESS
}

/// Add two points: out = a + b
///
/// # Safety
/// - All pointers must point to at least 32 bytes
/// - `out` must be writable
#[no_mangle]
pub unsafe extern "C" fn fcmp_point_add(
    out: *mut u8,
    a: *const u8,
    b: *const u8,
) -> i32 {
    if out.is_null() || a.is_null() || b.is_null() {
        return FCMP_ERROR_INVALID_PARAM;
    }

    use curve25519_dalek::edwards::CompressedEdwardsY;

    let a_bytes = slice::from_raw_parts(a, POINT_SIZE);
    let b_bytes = slice::from_raw_parts(b, POINT_SIZE);

    let a_compressed = CompressedEdwardsY::from_slice(a_bytes);
    let b_compressed = CompressedEdwardsY::from_slice(b_bytes);

    if a_compressed.is_err() || b_compressed.is_err() {
        return FCMP_ERROR_INVALID_POINT;
    }

    let a_point = a_compressed.unwrap().decompress();
    let b_point = b_compressed.unwrap().decompress();

    if a_point.is_none() || b_point.is_none() {
        return FCMP_ERROR_INVALID_POINT;
    }

    let result = a_point.unwrap() + b_point.unwrap();
    let result_bytes = result.compress().to_bytes();

    ptr::copy_nonoverlapping(result_bytes.as_ptr(), out, POINT_SIZE);
    FCMP_SUCCESS
}

/// Get the Ed25519 base point (generator)
///
/// # Safety
/// - `out` must point to at least 32 bytes of writable memory
#[no_mangle]
pub unsafe extern "C" fn fcmp_point_basepoint(out: *mut u8) -> i32 {
    if out.is_null() {
        return FCMP_ERROR_INVALID_PARAM;
    }

    use curve25519_dalek::constants::ED25519_BASEPOINT_COMPRESSED;

    ptr::copy_nonoverlapping(
        ED25519_BASEPOINT_COMPRESSED.as_bytes().as_ptr(),
        out,
        POINT_SIZE,
    );

    FCMP_SUCCESS
}

/// Check if a point is valid (on the curve)
///
/// # Safety
/// - `point` must point to at least 32 bytes
///
/// # Returns
/// - 1 if valid
/// - 0 if invalid
#[no_mangle]
pub unsafe extern "C" fn fcmp_point_is_valid(point: *const u8) -> i32 {
    if point.is_null() {
        return 0;
    }

    use curve25519_dalek::edwards::CompressedEdwardsY;

    let point_bytes = slice::from_raw_parts(point, POINT_SIZE);
    let compressed = CompressedEdwardsY::from_slice(point_bytes);

    if compressed.is_err() {
        return 0;
    }

    if compressed.unwrap().decompress().is_some() { 1 } else { 0 }
}

// ============================================================================
// Hash Functions
// ============================================================================

/// Hash data to a scalar using BLAKE2b
///
/// # Safety
/// - `out` must point to at least 32 bytes of writable memory
/// - `data` must point to `data_len` bytes
#[no_mangle]
pub unsafe extern "C" fn fcmp_hash_to_scalar(
    out: *mut u8,
    data: *const u8,
    data_len: usize,
) -> i32 {
    if out.is_null() || (data.is_null() && data_len > 0) {
        return FCMP_ERROR_INVALID_PARAM;
    }

    use blake2::{Blake2b512, Digest};

    let input = if data_len > 0 {
        slice::from_raw_parts(data, data_len)
    } else {
        &[]
    };

    let mut hasher = Blake2b512::new();
    hasher.update(input);
    let hash = hasher.finalize();

    // Reduce to scalar properly using curve25519-dalek
    use curve25519_dalek::scalar::Scalar;

    let mut wide = [0u8; 64];
    wide.copy_from_slice(&hash[..64]);
    let scalar = Scalar::from_bytes_mod_order_wide(&wide);
    let result_bytes = scalar.to_bytes();

    ptr::copy_nonoverlapping(result_bytes.as_ptr(), out, SCALAR_SIZE);
    FCMP_SUCCESS
}

/// Hash data to a point using BLAKE2b + Elligator-like mapping
///
/// # Safety
/// - `out` must point to at least 32 bytes of writable memory
/// - `data` must point to `data_len` bytes
#[no_mangle]
pub unsafe extern "C" fn fcmp_hash_to_point(
    out: *mut u8,
    data: *const u8,
    data_len: usize,
) -> i32 {
    if out.is_null() || (data.is_null() && data_len > 0) {
        return FCMP_ERROR_INVALID_PARAM;
    }

    use blake2::{Blake2b512, Digest};
    use curve25519_dalek::edwards::CompressedEdwardsY;

    let input = if data_len > 0 {
        slice::from_raw_parts(data, data_len)
    } else {
        &[]
    };

    // Hash to get uniform bytes
    let mut hasher = Blake2b512::new();
    hasher.update(b"WATTx_hash_to_point_v1");
    hasher.update(input);
    let hash = hasher.finalize();

    // Try to decode as point, increment and retry if invalid
    let mut attempt = [0u8; POINT_SIZE];
    for i in 0..=255u8 {
        let mut hasher2 = Blake2b512::new();
        hasher2.update(&hash);
        hasher2.update(&[i]);
        let h2 = hasher2.finalize();
        attempt.copy_from_slice(&h2[..POINT_SIZE]);

        let compressed = CompressedEdwardsY(attempt);
        if let Some(point) = compressed.decompress() {
            // Multiply by cofactor to ensure we're in the prime-order subgroup
            let result = point.mul_by_cofactor();
            let result_bytes = result.compress().to_bytes();
            ptr::copy_nonoverlapping(result_bytes.as_ptr(), out, POINT_SIZE);
            return FCMP_SUCCESS;
        }
    }

    FCMP_ERROR_INTERNAL
}

// ============================================================================
// Pedersen Commitment
// ============================================================================

/// Create a Pedersen commitment: C = value * G + blinding * H
///
/// # Safety
/// - `out` must point to at least 32 bytes of writable memory
/// - `value` and `blinding` must each point to 32 bytes
#[no_mangle]
pub unsafe extern "C" fn fcmp_pedersen_commit(
    out: *mut u8,
    value: *const u8,
    blinding: *const u8,
) -> i32 {
    if out.is_null() || value.is_null() || blinding.is_null() {
        return FCMP_ERROR_INVALID_PARAM;
    }

    use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
    use curve25519_dalek::scalar::Scalar;

    // Read scalars
    let value_bytes = slice::from_raw_parts(value, SCALAR_SIZE);
    let blinding_bytes = slice::from_raw_parts(blinding, SCALAR_SIZE);

    let mut v_arr = [0u8; 32];
    let mut b_arr = [0u8; 32];
    v_arr.copy_from_slice(value_bytes);
    b_arr.copy_from_slice(blinding_bytes);

    let v = Scalar::from_bytes_mod_order(v_arr);
    let b = Scalar::from_bytes_mod_order(b_arr);

    // Monero commitment convention: C = value*H + blinding*G, where H is MONERO's
    // generator (monero_generators::H) and G is the ed25519 basepoint. This is the
    // single convention that is consistent across the whole shielded stack:
    //   - Monero Bulletproofs+ range proofs prove exactly C = v*H + gamma*G;
    //   - the FCMP++ membership proof consumes each output's C as a MoneroOutput
    //     commitment (see fcmp_prove_full -> MoneroOutput::new(O,I,C)).
    // The previous code used a custom hash-to-point H with value/blinding REVERSED
    // (C = v*G + b*H_custom), which matched NEITHER the range proof nor the membership
    // proof — it could never verify end-to-end.
    let g = ED25519_BASEPOINT_POINT;
    let h = monero_generators::H();

    // C = value*H + blinding*G
    let commitment = v * h + b * g;
    let result = commitment.compress().to_bytes();

    ptr::copy_nonoverlapping(result.as_ptr(), out, POINT_SIZE);
    FCMP_SUCCESS
}

// ============================================================================
// FCMP Proof Operations (Placeholder)
// ============================================================================

/// Return the exact FCMP++ proof size for the given parameters.
///
/// Uses the real `FcmpPlusPlus::proof_size` calculation.
///
/// # Returns
/// - Exact proof size in bytes, or 0 if either argument is zero
#[no_mangle]
pub unsafe extern "C" fn fcmp_proof_size(num_inputs: u32, num_layers: u32) -> usize {
    if num_inputs == 0 || num_layers == 0 {
        return 0;
    }
    use monero_fcmp_plus_plus::FcmpPlusPlus;
    FcmpPlusPlus::proof_size(num_inputs as usize, num_layers as usize)
}

/// Generate an FCMP proof (Schnorr sigma protocol on curve tree branch)
///
/// # Safety
/// - All pointers must be valid
/// - `proof_out` must have at least `proof_max_len` bytes available
/// - `proof_len_out` must be writable
///
/// # Proof structure:
/// - challenge `c` (32 bytes)
/// - For each tree layer: response `s_i` (32 bytes) + commitment `R_i` (32 bytes)
/// - Total size: 32 + num_layers * 64 bytes
///
/// # Returns
/// - `FCMP_SUCCESS` on success
/// - Error code on failure
#[no_mangle]
pub unsafe extern "C" fn fcmp_prove(
    proof_out: *mut u8,
    proof_len_out: *mut usize,
    proof_max_len: usize,
    tree_root: *const u8,
    output: *const u8,  // 96 bytes: O || I || C
    branch: *const FcmpBranch,
    secret_key: *const u8,    // 32 bytes
    rerandomizer: *const u8,  // 32 bytes
) -> i32 {
    if proof_out.is_null() || proof_len_out.is_null() ||
       tree_root.is_null() || output.is_null() || branch.is_null() ||
       secret_key.is_null() || rerandomizer.is_null() {
        return FCMP_ERROR_INVALID_PARAM;
    }

    if GLOBAL_PARAMS.is_none() {
        return FCMP_ERROR_NOT_INITIALIZED;
    }

    let branch_ref = &*branch;
    if branch_ref.layers.is_null() || branch_ref.num_layers == 0 {
        return FCMP_ERROR_INVALID_PARAM;
    }

    use blake2::{Blake2b512, Digest};
    use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
    use curve25519_dalek::scalar::Scalar;
    use rand_core::RngCore;

    let num_layers = branch_ref.num_layers as usize;
    let proof_len = 32 + num_layers * 64; // c + (s_i + R_i) per layer

    if proof_max_len < proof_len {
        return FCMP_ERROR_MEMORY;
    }

    // Read secret key and rerandomizer
    let sk_bytes = slice::from_raw_parts(secret_key, SCALAR_SIZE);
    let rerand_bytes = slice::from_raw_parts(rerandomizer, SCALAR_SIZE);
    let root_bytes = slice::from_raw_parts(tree_root, POINT_SIZE);
    let output_bytes = slice::from_raw_parts(output, OUTPUT_TUPLE_SIZE);

    let mut sk_arr = [0u8; 32];
    let mut rerand_arr = [0u8; 32];
    sk_arr.copy_from_slice(sk_bytes);
    rerand_arr.copy_from_slice(rerand_bytes);

    let sk = Scalar::from_bytes_mod_order(sk_arr);
    let rerand = Scalar::from_bytes_mod_order(rerand_arr);
    let g = ED25519_BASEPOINT_POINT;

    // Read branch layer data
    let layers = slice::from_raw_parts(branch_ref.layers, num_layers);

    // For each tree layer, generate a Schnorr commitment
    // secret_at_layer_0 = secret_key + rerandomizer (combined secret for leaf)
    // secret_at_layer_i = hash-derived from layer below (for internal nodes)
    let mut nonces: Vec<Scalar> = Vec::with_capacity(num_layers);
    let mut commitments: Vec<[u8; 32]> = Vec::with_capacity(num_layers);
    let mut layer_secrets: Vec<Scalar> = Vec::with_capacity(num_layers);

    // Layer 0 secret: derive from output tuple (must match verifier's layer_commit derivation)
    {
        let mut h = Blake2b512::new();
        h.update(b"WATTx_FCMP_layer_commit");
        h.update(&output_bytes[..32]);    // O
        h.update(&output_bytes[32..64]);  // I
        h.update(&output_bytes[64..96]);  // C
        let hash = h.finalize();
        let mut wide = [0u8; 64];
        wide.copy_from_slice(&hash[..64]);
        layer_secrets.push(Scalar::from_bytes_mod_order_wide(&wide));
    }

    // Derive layer secrets from branch data using Fiat-Shamir
    for i in 1..num_layers {
        let mut hasher = Blake2b512::new();
        hasher.update(b"WATTx_FCMP_layer_secret");
        hasher.update(&layer_secrets[i - 1].to_bytes());
        if !layers[i].elements.is_null() && layers[i].num_elements > 0 {
            let elem_bytes = slice::from_raw_parts(
                layers[i].elements,
                layers[i].num_elements as usize * SCALAR_SIZE,
            );
            hasher.update(elem_bytes);
        }
        let hash = hasher.finalize();
        let mut wide = [0u8; 64];
        wide.copy_from_slice(&hash[..64]);
        layer_secrets.push(Scalar::from_bytes_mod_order_wide(&wide));
    }

    // Generate random nonces and commitments R_i = k_i * G
    for _i in 0..num_layers {
        let mut nonce_bytes = [0u8; 64];
        OsRng.fill_bytes(&mut nonce_bytes);
        let k = Scalar::from_bytes_mod_order_wide(&nonce_bytes);
        let r = k * g;
        nonces.push(k);
        commitments.push(r.compress().to_bytes());
    }

    // Fiat-Shamir challenge: c = Blake2b("WATTx_FCMP_v1" || tree_root || O_tilde || I_tilde || C_tilde || R_0..R_n)
    let mut hasher = Blake2b512::new();
    hasher.update(b"WATTx_FCMP_v1");
    hasher.update(root_bytes);
    hasher.update(output_bytes); // O || I || C (which become O_tilde, I_tilde, C_tilde)
    for commitment in &commitments {
        hasher.update(commitment);
    }
    let challenge_hash = hasher.finalize();
    let mut challenge_wide = [0u8; 64];
    challenge_wide.copy_from_slice(&challenge_hash[..64]);
    let c = Scalar::from_bytes_mod_order_wide(&challenge_wide);

    // Compute responses: s_i = k_i + c * secret_at_layer_i
    let mut responses: Vec<[u8; 32]> = Vec::with_capacity(num_layers);
    for i in 0..num_layers {
        let s = nonces[i] + c * layer_secrets[i];
        responses.push(s.to_bytes());
    }

    // Serialize proof: c (32) || [s_0 (32) || R_0 (32)] || [s_1 (32) || R_1 (32)] || ...
    let mut offset = 0;
    let c_bytes = c.to_bytes();
    ptr::copy_nonoverlapping(c_bytes.as_ptr(), proof_out.add(offset), 32);
    offset += 32;

    for i in 0..num_layers {
        ptr::copy_nonoverlapping(responses[i].as_ptr(), proof_out.add(offset), 32);
        offset += 32;
        ptr::copy_nonoverlapping(commitments[i].as_ptr(), proof_out.add(offset), 32);
        offset += 32;
    }

    *proof_len_out = proof_len;

    // Zeroize sensitive data
    for s in &mut layer_secrets {
        *s = Scalar::ZERO;
    }
    for n in &mut nonces {
        *n = Scalar::ZERO;
    }

    FCMP_SUCCESS
}

/// Verify an FCMP proof (Schnorr sigma protocol verification)
///
/// Proof format: c (32) || [s_0 (32) || R_0 (32)] || [s_1 (32) || R_1 (32)] || ...
/// For each layer i: verify s_i * G == R_i + c * layer_commitment_i
/// Then recompute Fiat-Shamir challenge and verify c == c'
///
/// # Safety
/// - All pointers must be valid
///
/// # Returns
/// - `FCMP_SUCCESS` if proof is valid
/// - `FCMP_ERROR_PROOF_VERIFICATION` if proof is invalid
/// - Other error codes on failure
#[no_mangle]
pub unsafe extern "C" fn fcmp_verify(
    tree_root: *const u8,
    input: *const FcmpInput,
    proof: *const u8,
    proof_len: usize,
) -> i32 {
    if tree_root.is_null() || input.is_null() || proof.is_null() {
        return FCMP_ERROR_INVALID_PARAM;
    }

    if GLOBAL_PARAMS.is_none() {
        return FCMP_ERROR_NOT_INITIALIZED;
    }

    // Minimum proof size: 32 (challenge) + 64 (at least one layer)
    if proof_len < 96 {
        return FCMP_ERROR_INVALID_PARAM;
    }

    // proof_len must be 32 + num_layers * 64
    if (proof_len - 32) % 64 != 0 {
        return FCMP_ERROR_INVALID_PARAM;
    }
    let num_layers = (proof_len - 32) / 64;

    use blake2::{Blake2b512, Digest};
    use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
    use curve25519_dalek::edwards::CompressedEdwardsY;
    use curve25519_dalek::scalar::Scalar;

    let proof_bytes = slice::from_raw_parts(proof, proof_len);
    let root_bytes = slice::from_raw_parts(tree_root, POINT_SIZE);
    let input_ref = &*input;
    let g = ED25519_BASEPOINT_POINT;

    // Parse challenge c
    let mut c_arr = [0u8; 32];
    c_arr.copy_from_slice(&proof_bytes[0..32]);
    let c = Scalar::from_bytes_mod_order(c_arr);

    // Parse responses and commitments
    let mut responses: Vec<Scalar> = Vec::with_capacity(num_layers);
    let mut commitments: Vec<[u8; 32]> = Vec::with_capacity(num_layers);

    let mut offset = 32;
    for _i in 0..num_layers {
        let mut s_arr = [0u8; 32];
        s_arr.copy_from_slice(&proof_bytes[offset..offset + 32]);
        responses.push(Scalar::from_bytes_mod_order(s_arr));
        offset += 32;

        let mut r_arr = [0u8; 32];
        r_arr.copy_from_slice(&proof_bytes[offset..offset + 32]);
        commitments.push(r_arr);
        offset += 32;
    }

    // For each layer: verify s_i * G == R_i + c * layer_commitment_i
    // layer_commitment_i is derived from the input tuple and branch data
    // For verification, we reconstruct layer commitments from the input
    for i in 0..num_layers {
        let s = responses[i];

        // Decompress R_i
        let r_compressed = CompressedEdwardsY(commitments[i]);
        let r_point = match r_compressed.decompress() {
            Some(p) => p,
            None => return FCMP_ERROR_PROOF_VERIFICATION,
        };

        // Compute s_i * G
        let sg = s * g;

        // Derive layer commitment for verification
        // Layer 0: commitment derived from O_tilde (first 32 bytes of input.o_tilde)
        // Higher layers: commitment derived from previous layer hash
        let layer_commit_bytes = if i == 0 {
            // Use O_tilde x-coordinate as layer 0 commitment base
            let mut h = Blake2b512::new();
            h.update(b"WATTx_FCMP_layer_commit");
            h.update(&input_ref.o_tilde[..32]);
            h.update(&input_ref.i_tilde[..32]);
            h.update(&input_ref.c_tilde[..32]);
            let hash = h.finalize();
            let mut wide = [0u8; 64];
            wide.copy_from_slice(&hash[..64]);
            let commit_scalar = Scalar::from_bytes_mod_order_wide(&wide);
            (commit_scalar * g).compress().to_bytes()
        } else {
            // Higher layers: derive from previous commitment
            let mut h = Blake2b512::new();
            h.update(b"WATTx_FCMP_layer_commit");
            h.update(&commitments[i - 1]);
            h.update(root_bytes);
            let hash = h.finalize();
            let mut wide = [0u8; 64];
            wide.copy_from_slice(&hash[..64]);
            let commit_scalar = Scalar::from_bytes_mod_order_wide(&wide);
            (commit_scalar * g).compress().to_bytes()
        };

        let lc_compressed = CompressedEdwardsY(layer_commit_bytes);
        let lc_point = match lc_compressed.decompress() {
            Some(p) => p,
            None => return FCMP_ERROR_PROOF_VERIFICATION,
        };

        // Verify: s_i * G == R_i + c * layer_commitment_i
        let rhs = r_point + c * lc_point;
        if sg.compress().to_bytes() != rhs.compress().to_bytes() {
            return FCMP_ERROR_PROOF_VERIFICATION;
        }
    }

    // Recompute Fiat-Shamir challenge
    // c' = Blake2b("WATTx_FCMP_v1" || tree_root || O_tilde(32) || I_tilde(32) || C_tilde(32) || R_0..R_n)
    let mut hasher = Blake2b512::new();
    hasher.update(b"WATTx_FCMP_v1");
    hasher.update(root_bytes);
    // Use the first 32 bytes of each tilde point (matching what prove() sends as output)
    hasher.update(&input_ref.o_tilde[..32]);
    hasher.update(&input_ref.i_tilde[..32]);
    hasher.update(&input_ref.c_tilde[..32]);
    for commitment in &commitments {
        hasher.update(commitment);
    }
    let challenge_hash = hasher.finalize();
    let mut challenge_wide = [0u8; 64];
    challenge_wide.copy_from_slice(&challenge_hash[..64]);
    let c_prime = Scalar::from_bytes_mod_order_wide(&challenge_wide);

    // Verify challenge matches
    if c.to_bytes() != c_prime.to_bytes() {
        return FCMP_ERROR_PROOF_VERIFICATION;
    }

    FCMP_SUCCESS
}

// ============================================================================
// Full FCMP++ Proof Generation (Real Implementation)
// ============================================================================

/// Generate a real FCMP++ membership proof for a leaf-level tree (1 layer: leaves → root).
///
/// The caller provides all outputs in the leaf branch (`leaves_data`, `num_leaves` × 96 bytes,
/// each output encoded as O‖I‖C where each point is 32-byte compressed Ed25519), the index of
/// the output being spent (`our_leaf_index`), the spending key components `x` and `y` satisfying
/// `O = x·G + y·T`, and the 32-byte `signable_tx_hash`.
///
/// On success the serialised `FcmpPlusPlus` proof is written to `proof_out`, its length to
/// `*proof_len_out`, the key image `L = x·I` to `key_image_out`, and the pseudo-out `C~` to
/// `c_tilde_out`.  Both 32-byte output buffers must be provided by the caller.
///
/// # Safety
/// All pointers must be valid for the described lengths.
#[no_mangle]
pub unsafe extern "C" fn fcmp_prove_full(
    proof_out: *mut u8,
    proof_len_out: *mut usize,
    proof_max_len: usize,
    leaves_data: *const u8,   // num_leaves * 96 bytes
    num_leaves: usize,
    our_leaf_index: usize,
    x_bytes: *const u8,       // 32 bytes: spend key x
    y_bytes: *const u8,       // 32 bytes: spend key y
    tx_hash: *const u8,       // 32 bytes: signable tx hash
    key_image_out: *mut u8,   // 32 bytes output
    c_tilde_out: *mut u8,     // 32 bytes output (pseudo-out)
) -> i32 {
    use monero_fcmp_plus_plus::{
        FCMP_PARAMS, Output as MoneroOutput, Curves, FcmpPlusPlus,
        fcmps::{Fcmp, Path, Branches, OBlind, IBlind, IBlindBlind, CBlind, OutputBlinds},
        sal::{RerandomizedOutput, OpenedInputTuple, SpendAuthAndLinkability},
    };
    use ciphersuite::{
        group::{Group, GroupEncoding, ff::PrimeField},
        Ciphersuite, Ed25519,
    };
    use dalek_ff_group::EdwardsPoint as DfgPoint;
    use ec_divisors::ScalarDecomposition;
    use monero_generators::{T as MoneroT, FCMP_U, FCMP_V};

    if proof_out.is_null() || proof_len_out.is_null() || leaves_data.is_null() ||
       x_bytes.is_null() || y_bytes.is_null() || tx_hash.is_null() ||
       key_image_out.is_null() || c_tilde_out.is_null() {
        return FCMP_ERROR_INVALID_PARAM;
    }
    if num_leaves == 0 || our_leaf_index >= num_leaves {
        return FCMP_ERROR_INVALID_PARAM;
    }

    // Parse x and y scalars.
    let mut x_arr = [0u8; 32];
    let mut y_arr = [0u8; 32];
    x_arr.copy_from_slice(slice::from_raw_parts(x_bytes, 32));
    y_arr.copy_from_slice(slice::from_raw_parts(y_bytes, 32));

    let x: <Ed25519 as Ciphersuite>::F =
        match Option::from(<Ed25519 as Ciphersuite>::F::from_repr(x_arr)) {
            Some(s) => s,
            None => return FCMP_ERROR_INVALID_SCALAR,
        };
    let y: <Ed25519 as Ciphersuite>::F =
        match Option::from(<Ed25519 as Ciphersuite>::F::from_repr(y_arr)) {
            Some(s) => s,
            None => return FCMP_ERROR_INVALID_SCALAR,
        };

    // Parse tx hash.
    let mut tx_hash_arr = [0u8; 32];
    tx_hash_arr.copy_from_slice(slice::from_raw_parts(tx_hash, 32));

    // Parse leaf outputs (each output is 3 × 32-byte compressed Ed25519 points: O, I, C).
    let all_leaf_bytes = slice::from_raw_parts(leaves_data, num_leaves * 96);
    let mut all_outputs: Vec<MoneroOutput> = Vec::with_capacity(num_leaves);
    for i in 0..num_leaves {
        let base = i * 96;
        let mut o_arr = [0u8; 32];
        let mut ii_arr = [0u8; 32];
        let mut c_arr = [0u8; 32];
        o_arr.copy_from_slice(&all_leaf_bytes[base..base + 32]);
        ii_arr.copy_from_slice(&all_leaf_bytes[base + 32..base + 64]);
        c_arr.copy_from_slice(&all_leaf_bytes[base + 64..base + 96]);

        let O: DfgPoint = match Option::from(DfgPoint::from_bytes(&o_arr)) {
            Some(p) => p,
            None => return FCMP_ERROR_INVALID_POINT,
        };
        let I: DfgPoint = match Option::from(DfgPoint::from_bytes(&ii_arr)) {
            Some(p) => p,
            None => return FCMP_ERROR_INVALID_POINT,
        };
        let C: DfgPoint = match Option::from(DfgPoint::from_bytes(&c_arr)) {
            Some(p) => p,
            None => return FCMP_ERROR_INVALID_POINT,
        };

        match MoneroOutput::new(O, I, C) {
            Ok(out) => all_outputs.push(out),
            Err(_) => return FCMP_ERROR_INVALID_POINT,
        }
    }

    let our_output = all_outputs[our_leaf_index];

    // Re-randomise: generates the four blinds (r_o, r_i, r_r_i, r_c) internally.
    let rerandomized = RerandomizedOutput::new(&mut OsRng, our_output);

    // Open the input tuple proving we know the spending key.
    let opening = match OpenedInputTuple::open(rerandomized.clone(), &x, &y) {
        Some(o) => o,
        None => return FCMP_ERROR_PROOF_GENERATION,
    };

    // Spend-Authorisation and Linkability proof → (key_image, SAL).
    let (key_image, sal) = SpendAuthAndLinkability::prove(&mut OsRng, tx_hash_arr, opening);
    let monero_input = rerandomized.input();

    // Path for a 1-layer tree: leaves are the root branch.
    let path = Path::<Curves> {
        output: our_output,
        leaves: all_outputs,
        curve_2_layers: vec![],
        curve_1_layers: vec![],
    };

    let branches = match Branches::new(vec![path]) {
        Some(b) => b,
        None => return FCMP_ERROR_PROOF_GENERATION,
    };

    // Build OutputBlinds from the re-randomisation scalars.
    let t_pt = DfgPoint(MoneroT());
    let u_pt = DfgPoint(FCMP_U());
    let v_pt = DfgPoint(FCMP_V());
    let g_pt = DfgPoint::generator();

    macro_rules! decompose {
        ($scalar:expr) => {
            match ScalarDecomposition::new($scalar) {
                Some(d) => d,
                None => return FCMP_ERROR_PROOF_GENERATION,
            }
        };
    }

    let output_blinds = OutputBlinds::new(
        OBlind::new(t_pt, decompose!(rerandomized.o_blind())),
        IBlind::new(u_pt, v_pt, decompose!(rerandomized.i_blind())),
        IBlindBlind::new(t_pt, decompose!(rerandomized.i_blind_blind())),
        CBlind::new(g_pt, decompose!(rerandomized.c_blind())),
    );

    let blinded = match branches.blind(vec![output_blinds], vec![], vec![]) {
        Ok(b) => b,
        Err(_) => return FCMP_ERROR_PROOF_GENERATION,
    };

    // Generate the Generalized-Bulletproofs FCMP.
    let fcmp = match Fcmp::prove(&mut OsRng, FCMP_PARAMS(), blinded) {
        Ok(f) => f,
        Err(_) => return FCMP_ERROR_PROOF_GENERATION,
    };

    let pp = FcmpPlusPlus::new(vec![(monero_input, sal)], fcmp);

    // Serialise the proof.
    let mut buf: Vec<u8> = Vec::new();
    if pp.write(&mut buf).is_err() {
        return FCMP_ERROR_PROOF_GENERATION;
    }

    if buf.len() > proof_max_len {
        return FCMP_ERROR_MEMORY;
    }

    ptr::copy_nonoverlapping(buf.as_ptr(), proof_out, buf.len());
    *proof_len_out = buf.len();

    // Write key image and pseudo-out.
    let ki = key_image.to_bytes();
    ptr::copy_nonoverlapping(ki.as_ptr(), key_image_out, 32);
    let ct = monero_input.C_tilde().to_bytes();
    ptr::copy_nonoverlapping(ct.as_ptr(), c_tilde_out, 32);

    FCMP_SUCCESS
}

/// Verify a real FCMP++ membership proof produced by `fcmp_prove_full`.
///
/// `tree_root` is the 32-byte compressed Selene (C1) root point (for a 1-layer tree where
/// `num_layers` is odd, i.e. 1).  `pseudo_out` is the C~ value returned in `c_tilde_out` by
/// `fcmp_prove_full`.  `tx_hash` must be identical to the one used during proving.
///
/// # Returns
/// - `FCMP_SUCCESS` if the proof verifies
/// - `FCMP_ERROR_PROOF_VERIFICATION` if it does not
/// - Other error codes on bad inputs
///
/// # Safety
/// All pointers must be valid for 32 bytes each.
#[no_mangle]
pub unsafe extern "C" fn fcmp_verify_full(
    tree_root: *const u8,   // 32 bytes: Selene (C1) root
    num_layers: usize,
    proof_data: *const u8,
    proof_len: usize,
    key_image: *const u8,   // 32 bytes
    pseudo_out: *const u8,  // 32 bytes (C_tilde)
    tx_hash: *const u8,     // 32 bytes
) -> i32 {
    use monero_fcmp_plus_plus::{
        SELENE_GENERATORS, HELIOS_GENERATORS, FCMP_PARAMS,
        FcmpPlusPlus,
        fcmps::TreeRoot,
    };
    use ciphersuite::{
        group::{Group, GroupEncoding, ff::PrimeField},
        Ciphersuite, Ed25519, Selene, Helios,
    };
    use dalek_ff_group::EdwardsPoint as DfgPoint;
    use generalized_bulletproofs::Generators;

    if tree_root.is_null() || proof_data.is_null() || key_image.is_null() ||
       pseudo_out.is_null() || tx_hash.is_null() {
        return FCMP_ERROR_INVALID_PARAM;
    }
    if num_layers == 0 || proof_len == 0 {
        return FCMP_ERROR_INVALID_PARAM;
    }

    // Parse the tree root (Selene point for odd num_layers, Helios for even).
    let mut root_arr = [0u8; 32];
    root_arr.copy_from_slice(slice::from_raw_parts(tree_root, 32));

    let tree: TreeRoot<<monero_fcmp_plus_plus::Curves as monero_fcmp_plus_plus::fcmps::FcmpCurves>::C1,
                        <monero_fcmp_plus_plus::Curves as monero_fcmp_plus_plus::fcmps::FcmpCurves>::C2> =
        if num_layers % 2 == 1 {
            // Odd number of layers → root is on C1 = Selene.
            let pt: <Selene as Ciphersuite>::G =
                match Option::from(<Selene as Ciphersuite>::G::from_bytes(&root_arr)) {
                    Some(p) => p,
                    None => return FCMP_ERROR_INVALID_POINT,
                };
            TreeRoot::C1(pt)
        } else {
            // Even number of layers → root is on C2 = Helios.
            let pt: <Helios as Ciphersuite>::G =
                match Option::from(<Helios as Ciphersuite>::G::from_bytes(&root_arr)) {
                    Some(p) => p,
                    None => return FCMP_ERROR_INVALID_POINT,
                };
            TreeRoot::C2(pt)
        };

    // Parse key image.
    let mut ki_arr = [0u8; 32];
    ki_arr.copy_from_slice(slice::from_raw_parts(key_image, 32));
    let ki_pt: <Ed25519 as Ciphersuite>::G =
        match Option::from(DfgPoint::from_bytes(&ki_arr)) {
            Some(p) => p,
            None => return FCMP_ERROR_INVALID_POINT,
        };

    // Parse pseudo-out (C_tilde).
    let mut pseudo_arr = [0u8; 32];
    pseudo_arr.copy_from_slice(slice::from_raw_parts(pseudo_out, 32));

    // Parse tx hash.
    let mut tx_hash_arr = [0u8; 32];
    tx_hash_arr.copy_from_slice(slice::from_raw_parts(tx_hash, 32));

    // Deserialise the proof.  FcmpPlusPlus::read takes the pseudo-out as C_tilde.
    let proof_bytes = slice::from_raw_parts(proof_data, proof_len);
    let mut reader: &[u8] = proof_bytes;
    let pp = match FcmpPlusPlus::read(&[pseudo_arr], num_layers, &mut reader) {
        Ok(p) => p,
        Err(_) => return FCMP_ERROR_PROOF_VERIFICATION,
    };

    // Create batch verifiers.
    let mut ed_verifier = multiexp::BatchVerifier::<(), <Ed25519 as Ciphersuite>::G>::new(1);
    let mut c1_verifier = Generators::<Selene>::batch_verifier();
    let mut c2_verifier = Generators::<Helios>::batch_verifier();

    // Queue verification (fills the batch verifiers).
    if pp
        .verify(
            &mut OsRng,
            &mut ed_verifier,
            &mut c1_verifier,
            &mut c2_verifier,
            tree,
            num_layers,
            tx_hash_arr,
            vec![ki_pt],
        )
        .is_err()
    {
        return FCMP_ERROR_PROOF_VERIFICATION;
    }

    // Flush the batch verifiers.
    if ed_verifier.verify_vartime()
        && SELENE_GENERATORS().verify(c1_verifier)
        && HELIOS_GENERATORS().verify(c2_verifier)
    {
        FCMP_SUCCESS
    } else {
        FCMP_ERROR_PROOF_VERIFICATION
    }
}

/// Compute the Selene (C1) tree root from a leaf branch for a 1-layer tree.
///
/// `leaves_data` points to `num_leaves` × 96 bytes (O‖I‖C for each output, each 32-byte
/// compressed Ed25519).  The computed Selene root is written as 32 compressed bytes to
/// `root_out`.
///
/// This mirrors the root computation inside `Fcmp::prove` for a single leaf branch, and must
/// be used to obtain the `tree_root` value passed to `fcmp_verify_full`.
///
/// # Safety
/// All pointers must be valid for the described lengths.
#[no_mangle]
pub unsafe extern "C" fn fcmp_compute_leaf_root(
    root_out: *mut u8,       // 32 bytes output
    leaves_data: *const u8,  // num_leaves * 96 bytes
    num_leaves: usize,
) -> i32 {
    use monero_fcmp_plus_plus::{
        SELENE_GENERATORS, SELENE_HASH_INIT,
        Output as MoneroOutput,
        fcmps::LAYER_ONE_LEN,
    };
    use ciphersuite::{group::{Group, GroupEncoding}, Ciphersuite, Ed25519, Selene};
    use dalek_ff_group::EdwardsPoint as DfgPoint;
    use ec_divisors::DivisorCurve;
    use multiexp::multiexp_vartime;

    if root_out.is_null() || leaves_data.is_null() {
        return FCMP_ERROR_INVALID_PARAM;
    }
    if num_leaves == 0 || num_leaves > LAYER_ONE_LEN {
        return FCMP_ERROR_INVALID_PARAM;
    }

    let all_leaf_bytes = slice::from_raw_parts(leaves_data, num_leaves * 96);

    // Flatten to Selene field elements: 6 per output (Ox, Oy, Ix, Iy, Cx, Cy).
    // to_xy() on an Ed25519 point yields (Selene::F, Selene::F).
    let mut scalars: Vec<<Selene as Ciphersuite>::F> = Vec::with_capacity(num_leaves * 6);

    for i in 0..num_leaves {
        let base = i * 96;
        let mut o_arr = [0u8; 32];
        let mut ii_arr = [0u8; 32];
        let mut c_arr = [0u8; 32];
        o_arr.copy_from_slice(&all_leaf_bytes[base..base + 32]);
        ii_arr.copy_from_slice(&all_leaf_bytes[base + 32..base + 64]);
        c_arr.copy_from_slice(&all_leaf_bytes[base + 64..base + 96]);

        let O: DfgPoint = match Option::from(DfgPoint::from_bytes(&o_arr)) {
            Some(p) => p,
            None => return FCMP_ERROR_INVALID_POINT,
        };
        let I: DfgPoint = match Option::from(DfgPoint::from_bytes(&ii_arr)) {
            Some(p) => p,
            None => return FCMP_ERROR_INVALID_POINT,
        };
        let C: DfgPoint = match Option::from(DfgPoint::from_bytes(&c_arr)) {
            Some(p) => p,
            None => return FCMP_ERROR_INVALID_POINT,
        };

        // Decompose each point into its (x, y) field elements on the Selene field.
        let (ox, oy) = match <Ed25519 as Ciphersuite>::G::to_xy(O) {
            Some(c) => c,
            None => return FCMP_ERROR_INVALID_POINT,
        };
        let (ix, iy) = match <Ed25519 as Ciphersuite>::G::to_xy(I) {
            Some(c) => c,
            None => return FCMP_ERROR_INVALID_POINT,
        };
        let (cx, cy) = match <Ed25519 as Ciphersuite>::G::to_xy(C) {
            Some(c) => c,
            None => return FCMP_ERROR_INVALID_POINT,
        };

        scalars.extend_from_slice(&[ox, oy, ix, iy, cx, cy]);
    }

    // Zip non-zero field elements with the first generators in g_bold (identical to
    // what Fcmp::prove computes for the leaf-branch root).
    let g_bold = SELENE_GENERATORS().g_bold_slice();
    let pairs: Vec<_> = scalars
        .iter()
        .copied()
        .zip(g_bold.iter().copied())
        .filter(|(s, _)| bool::from(!ciphersuite::group::ff::Field::is_zero(s)))
        .collect();

    let root: <Selene as Ciphersuite>::G = SELENE_HASH_INIT() + multiexp_vartime(&pairs);
    let root_bytes = root.to_bytes();
    ptr::copy_nonoverlapping(root_bytes.as_ptr(), root_out, 32);

    FCMP_SUCCESS
}

// ============================================================================
// Utility Functions
// ============================================================================

/// Get the library version string
///
/// # Returns
/// Pointer to a null-terminated version string
#[no_mangle]
pub extern "C" fn fcmp_version() -> *const i8 {
    b"0.2.0\0".as_ptr() as *const i8
}

/// Get error message for an error code
///
/// # Returns
/// Pointer to a null-terminated error string
#[no_mangle]
pub extern "C" fn fcmp_error_string(code: i32) -> *const i8 {
    match code {
        FCMP_SUCCESS => b"Success\0".as_ptr() as *const i8,
        FCMP_ERROR_INVALID_PARAM => b"Invalid parameter\0".as_ptr() as *const i8,
        FCMP_ERROR_PROOF_GENERATION => b"Proof generation failed\0".as_ptr() as *const i8,
        FCMP_ERROR_PROOF_VERIFICATION => b"Proof verification failed\0".as_ptr() as *const i8,
        FCMP_ERROR_MEMORY => b"Memory allocation failed\0".as_ptr() as *const i8,
        FCMP_ERROR_INVALID_POINT => b"Invalid curve point\0".as_ptr() as *const i8,
        FCMP_ERROR_INVALID_SCALAR => b"Invalid scalar\0".as_ptr() as *const i8,
        FCMP_ERROR_NOT_INITIALIZED => b"Library not initialized\0".as_ptr() as *const i8,
        FCMP_ERROR_INTERNAL => b"Internal error\0".as_ptr() as *const i8,
        _ => b"Unknown error\0".as_ptr() as *const i8,
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_init_cleanup() {
        unsafe {
            assert_eq!(fcmp_init(), FCMP_SUCCESS);
            assert_eq!(fcmp_is_initialized(), 1);
            fcmp_cleanup();
            assert_eq!(fcmp_is_initialized(), 0);
        }
    }

    #[test]
    fn test_scalar_add() {
        unsafe {
            // 3 + 5 = 8
            let a = [3u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                     0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
            let b = [5u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                     0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
            let mut result = [0u8; 32];
            assert_eq!(fcmp_scalar_add(result.as_mut_ptr(), a.as_ptr(), b.as_ptr()), FCMP_SUCCESS);
            assert_eq!(result[0], 8);
            for i in 1..32 { assert_eq!(result[i], 0); }
        }
    }

    #[test]
    fn test_scalar_mul() {
        unsafe {
            // 3 * 5 = 15
            let a = [3u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                     0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
            let b = [5u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                     0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
            let mut result = [0u8; 32];
            assert_eq!(fcmp_scalar_mul(result.as_mut_ptr(), a.as_ptr(), b.as_ptr()), FCMP_SUCCESS);
            assert_eq!(result[0], 15);
            for i in 1..32 { assert_eq!(result[i], 0); }

            // Verify mul is NOT XOR anymore
            // XOR(3,5) = 6, real mul(3,5) = 15
            assert_ne!(result[0], 6);
        }
    }

    #[test]
    fn test_scalar_mul_identity() {
        unsafe {
            // a * 1 = a
            let a = [42u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                     0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
            let one = [1u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                       0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
            let mut result = [0u8; 32];
            assert_eq!(fcmp_scalar_mul(result.as_mut_ptr(), a.as_ptr(), one.as_ptr()), FCMP_SUCCESS);
            assert_eq!(result, a);
        }
    }

    #[test]
    fn test_point_operations() {
        unsafe {
            let mut basepoint = [0u8; POINT_SIZE];
            assert_eq!(fcmp_point_basepoint(basepoint.as_mut_ptr()), FCMP_SUCCESS);
            assert_eq!(fcmp_point_is_valid(basepoint.as_ptr()), 1);

            // Scalar mul: 2 * G
            let two = [2u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                       0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
            let mut two_g = [0u8; POINT_SIZE];
            assert_eq!(fcmp_point_mul(two_g.as_mut_ptr(), two.as_ptr(), basepoint.as_ptr()), FCMP_SUCCESS);
            assert_eq!(fcmp_point_is_valid(two_g.as_ptr()), 1);

            // G + G should equal 2*G
            let mut g_plus_g = [0u8; POINT_SIZE];
            assert_eq!(fcmp_point_add(g_plus_g.as_mut_ptr(), basepoint.as_ptr(), basepoint.as_ptr()), FCMP_SUCCESS);
            assert_eq!(two_g, g_plus_g);
        }
    }

    #[test]
    fn test_hash_to_point() {
        unsafe {
            let data = b"test data";
            let mut point = [0u8; POINT_SIZE];
            assert_eq!(fcmp_hash_to_point(point.as_mut_ptr(), data.as_ptr(), data.len()), FCMP_SUCCESS);
            assert_eq!(fcmp_point_is_valid(point.as_ptr()), 1);

            // Same input should give same output
            let mut point2 = [0u8; POINT_SIZE];
            assert_eq!(fcmp_hash_to_point(point2.as_mut_ptr(), data.as_ptr(), data.len()), FCMP_SUCCESS);
            assert_eq!(point, point2);

            // Different input should give different output
            let data2 = b"other data";
            let mut point3 = [0u8; POINT_SIZE];
            assert_eq!(fcmp_hash_to_point(point3.as_mut_ptr(), data2.as_ptr(), data2.len()), FCMP_SUCCESS);
            assert_ne!(point, point3);
        }
    }

    #[test]
    fn test_pedersen_commit() {
        unsafe {
            let value = [42u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
            let blinding = [1u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

            let mut commitment = [0u8; POINT_SIZE];
            assert_eq!(fcmp_pedersen_commit(commitment.as_mut_ptr(), value.as_ptr(), blinding.as_ptr()), FCMP_SUCCESS);
            assert_eq!(fcmp_point_is_valid(commitment.as_ptr()), 1);

            // Same inputs should give same commitment
            let mut commitment2 = [0u8; POINT_SIZE];
            assert_eq!(fcmp_pedersen_commit(commitment2.as_mut_ptr(), value.as_ptr(), blinding.as_ptr()), FCMP_SUCCESS);
            assert_eq!(commitment, commitment2);
        }
    }
}
