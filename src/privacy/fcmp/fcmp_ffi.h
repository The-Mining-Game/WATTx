// Copyright (c) 2024-2026 The WATTx Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef WATTX_PRIVACY_FCMP_FFI_H
#define WATTX_PRIVACY_FCMP_FFI_H

#include <cstddef>
#include <cstdint>

#ifdef __cplusplus
extern "C" {
#endif

// ============================================================================
// Error Codes
// ============================================================================

#define FCMP_SUCCESS                    0
#define FCMP_ERROR_INVALID_PARAM       -1
#define FCMP_ERROR_PROOF_GENERATION    -2
#define FCMP_ERROR_PROOF_VERIFICATION  -3
#define FCMP_ERROR_MEMORY              -4
#define FCMP_ERROR_INVALID_POINT       -5
#define FCMP_ERROR_INVALID_SCALAR      -6
#define FCMP_ERROR_NOT_INITIALIZED     -7
#define FCMP_ERROR_INTERNAL           -99

// ============================================================================
// Constants
// ============================================================================

#define FCMP_SCALAR_SIZE      32
#define FCMP_POINT_SIZE       32
#define FCMP_OUTPUT_TUPLE_SIZE 96  // 3 * 32 bytes (O, I, C)

// ============================================================================
// Types
// ============================================================================

/**
 * Branch layer data for proof generation
 */
typedef struct {
    uint32_t num_elements;    // Number of elements in this layer
    const uint8_t* elements;  // Pointer to elements (32 bytes each)
} FcmpBranchLayer;

/**
 * Branch (Merkle path) for proof generation
 */
typedef struct {
    uint64_t leaf_index;              // Index of the leaf output
    uint32_t num_layers;              // Number of layers in branch
    const FcmpBranchLayer* layers;    // Array of layer data
} FcmpBranch;

/**
 * Input tuple for proof verification
 */
typedef struct {
    uint8_t o_tilde[64];   // Re-randomized O point (x, y as scalars)
    uint8_t i_tilde[64];   // Re-randomized I point
    uint8_t r[64];         // R value for SA+L
    uint8_t c_tilde[64];   // Re-randomized C point
} FcmpInput;

// ============================================================================
// Initialization
// ============================================================================

/**
 * Initialize the FCMP library.
 * Must be called before any other FCMP functions.
 *
 * @return FCMP_SUCCESS on success, error code on failure
 */
int32_t fcmp_init(void);

/**
 * Clean up FCMP resources.
 */
void fcmp_cleanup(void);

/**
 * Check if FCMP is initialized.
 *
 * @return 1 if initialized, 0 if not
 */
int32_t fcmp_is_initialized(void);

// ============================================================================
// Scalar Operations
// ============================================================================

/**
 * Generate a random scalar.
 *
 * @param out Output buffer (32 bytes)
 * @return FCMP_SUCCESS on success
 */
int32_t fcmp_scalar_random(uint8_t* out);

/**
 * Add two scalars: out = a + b (mod l)
 *
 * @param out Output buffer (32 bytes)
 * @param a First scalar (32 bytes)
 * @param b Second scalar (32 bytes)
 * @return FCMP_SUCCESS on success
 */
int32_t fcmp_scalar_add(uint8_t* out, const uint8_t* a, const uint8_t* b);

/**
 * Multiply two scalars: out = a * b (mod l)
 *
 * @param out Output buffer (32 bytes)
 * @param a First scalar (32 bytes)
 * @param b Second scalar (32 bytes)
 * @return FCMP_SUCCESS on success
 */
int32_t fcmp_scalar_mul(uint8_t* out, const uint8_t* a, const uint8_t* b);

// ============================================================================
// Point Operations
// ============================================================================

/**
 * Scalar multiplication: out = scalar * point
 *
 * @param out Output point (32 bytes)
 * @param scalar Scalar (32 bytes)
 * @param point Input point (32 bytes)
 * @return FCMP_SUCCESS on success
 */
int32_t fcmp_point_mul(uint8_t* out, const uint8_t* scalar, const uint8_t* point);

/**
 * Point addition: out = a + b
 *
 * @param out Output point (32 bytes)
 * @param a First point (32 bytes)
 * @param b Second point (32 bytes)
 * @return FCMP_SUCCESS on success
 */
int32_t fcmp_point_add(uint8_t* out, const uint8_t* a, const uint8_t* b);

/**
 * Get the Ed25519 base point (generator G).
 *
 * @param out Output point (32 bytes)
 * @return FCMP_SUCCESS on success
 */
int32_t fcmp_point_basepoint(uint8_t* out);

/**
 * Check if a point is valid (on the curve).
 *
 * @param point Point to check (32 bytes)
 * @return 1 if valid, 0 if invalid
 */
int32_t fcmp_point_is_valid(const uint8_t* point);

// ============================================================================
// Hash Functions
// ============================================================================

/**
 * Hash data to a scalar using BLAKE2b.
 *
 * @param out Output scalar (32 bytes)
 * @param data Input data
 * @param data_len Length of input data
 * @return FCMP_SUCCESS on success
 */
int32_t fcmp_hash_to_scalar(uint8_t* out, const uint8_t* data, size_t data_len);

/**
 * Hash data to a point on the curve.
 *
 * @param out Output point (32 bytes)
 * @param data Input data
 * @param data_len Length of input data
 * @return FCMP_SUCCESS on success
 */
int32_t fcmp_hash_to_point(uint8_t* out, const uint8_t* data, size_t data_len);

// ============================================================================
// Pedersen Commitment
// ============================================================================

/**
 * Create a Pedersen commitment: C = value * G + blinding * H
 *
 * @param out Output commitment (32 bytes)
 * @param value Value scalar (32 bytes)
 * @param blinding Blinding scalar (32 bytes)
 * @return FCMP_SUCCESS on success
 */
int32_t fcmp_pedersen_commit(uint8_t* out, const uint8_t* value, const uint8_t* blinding);

// ============================================================================
// FCMP Proof Operations
// ============================================================================

/**
 * Estimate proof size for given parameters.
 *
 * @param num_inputs Number of inputs being proven
 * @param num_layers Number of tree layers
 * @return Estimated proof size in bytes, or 0 on error
 */
size_t fcmp_proof_size(uint32_t num_inputs, uint32_t num_layers);

/**
 * Generate an FCMP proof.
 *
 * @param proof_out Output buffer for proof
 * @param proof_len_out Output: actual proof length
 * @param proof_max_len Maximum size of proof buffer
 * @param tree_root Tree root point (32 bytes)
 * @param output Output tuple (96 bytes: O || I || C)
 * @param branch Branch/path data
 * @param secret_key Secret key for Schnorr proof (32 bytes)
 * @param rerandomizer Rerandomization scalar (32 bytes)
 * @return FCMP_SUCCESS on success
 */
int32_t fcmp_prove(
    uint8_t* proof_out,
    size_t* proof_len_out,
    size_t proof_max_len,
    const uint8_t* tree_root,
    const uint8_t* output,
    const FcmpBranch* branch,
    const uint8_t* secret_key,
    const uint8_t* rerandomizer
);

/**
 * Verify an FCMP proof.
 *
 * @param tree_root Tree root point (32 bytes)
 * @param input Input tuple for verification
 * @param proof Proof data
 * @param proof_len Length of proof
 * @return FCMP_SUCCESS if valid, FCMP_ERROR_PROOF_VERIFICATION if invalid
 */
int32_t fcmp_verify(
    const uint8_t* tree_root,
    const FcmpInput* input,
    const uint8_t* proof,
    size_t proof_len
);

// ============================================================================
// Full FCMP++ Proof Operations (Real Implementation)
// ============================================================================

/**
 * Generate a real FCMP++ membership proof for a 1-layer (leaf-only) tree.
 *
 * leaves_data   - num_leaves * 96 bytes (O || I || C per output, each 32-byte compressed Ed25519)
 * num_leaves    - number of outputs in the leaf branch (1 .. LAYER_ONE_LEN=38)
 * our_leaf_index - index of the output being spent within leaves_data (0-based)
 * x_bytes       - 32-byte spend key x  (O = x*G + y*T)
 * y_bytes       - 32-byte spend key y
 * tx_hash       - 32-byte signable transaction hash
 * key_image_out - 32-byte output: key image L = x*I
 * c_tilde_out   - 32-byte output: pseudo-out C~ (pass to fcmp_verify_full)
 * c_blind_out   - 32-byte output: r_c, the commitment re-randomiser. SECRET.
 *
 * The re-randomisation is C~ = C + r_c*G, so the pseudo-out's blinding is
 * b~ = b + r_c. A spender needs r_c to balance the transaction's output blindings
 * against its inputs; without it the balance equation is unsatisfiable even for an
 * honest sender. Never publish it: r_c + C~ re-links the input to its tree leaf.
 *
 * @return FCMP_SUCCESS on success
 */
int32_t fcmp_prove_full(
    uint8_t*       proof_out,
    size_t*        proof_len_out,
    size_t         proof_max_len,
    const uint8_t* leaves_data,
    size_t         num_leaves,
    size_t         our_leaf_index,
    const uint8_t* x_bytes,
    const uint8_t* y_bytes,
    const uint8_t* tx_hash,
    uint8_t*       key_image_out,
    uint8_t*       c_tilde_out,
    uint8_t*       c_blind_out
);

/**
 * Verify a real FCMP++ membership proof produced by fcmp_prove_full.
 *
 * tree_root  - 32-byte Selene (C1) root (num_layers odd) or Helios (even)
 * num_layers - number of tree layers (1 for a leaf-only tree)
 * proof_data - proof bytes from fcmp_prove_full
 * proof_len  - length of proof_data
 * key_image  - 32-byte key image from fcmp_prove_full
 * pseudo_out - 32-byte C~ from fcmp_prove_full
 * tx_hash    - 32-byte hash, identical to the one used in fcmp_prove_full
 *
 * @return FCMP_SUCCESS if valid, FCMP_ERROR_PROOF_VERIFICATION if invalid
 */
int32_t fcmp_verify_full(
    const uint8_t* tree_root,
    size_t         num_layers,
    const uint8_t* proof_data,
    size_t         proof_len,
    const uint8_t* key_image,
    const uint8_t* pseudo_out,
    const uint8_t* tx_hash
);

/**
 * Compute the Selene (C1) tree root from a leaf branch for a 1-layer tree.
 *
 * root_out    - 32-byte output: Selene root (pass as tree_root to fcmp_verify_full)
 * leaves_data - num_leaves * 96 bytes (same layout as fcmp_prove_full)
 * num_leaves  - number of outputs (1 .. 38)
 *
 * @return FCMP_SUCCESS on success
 */
int32_t fcmp_compute_leaf_root(
    uint8_t*       root_out,
    const uint8_t* leaves_data,
    size_t         num_leaves
);

// ============================================================================
// Utility Functions
// ============================================================================

/**
 * Get library version string.
 *
 * @return Null-terminated version string
 */
const char* fcmp_version(void);

/**
 * Get error message for an error code.
 *
 * @param code Error code
 * @return Null-terminated error message
 */
const char* fcmp_error_string(int32_t code);

#ifdef __cplusplus
}
#endif

#endif // WATTX_PRIVACY_FCMP_FFI_H
