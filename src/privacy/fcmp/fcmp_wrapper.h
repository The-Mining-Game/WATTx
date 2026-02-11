// Copyright (c) 2024-2026 The WATTx Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef WATTX_PRIVACY_FCMP_WRAPPER_H
#define WATTX_PRIVACY_FCMP_WRAPPER_H

#include <privacy/fcmp/fcmp_ffi.h>
#include <privacy/ed25519/ed25519_types.h>
#include <privacy/curvetree/curve_tree.h>

#include <memory>
#include <vector>
#include <string>
#include <optional>

namespace privacy {
namespace fcmp {

/**
 * Exception class for FCMP errors
 */
class FcmpError : public std::runtime_error {
public:
    int32_t code;

    FcmpError(int32_t error_code, const char* msg = nullptr)
        : std::runtime_error(msg ? msg : fcmp_error_string(error_code))
        , code(error_code) {}
};

/**
 * RAII wrapper for FCMP library initialization
 *
 * Ensures fcmp_init() is called on construction and fcmp_cleanup() on destruction.
 * Multiple instances are safe - initialization is idempotent.
 */
class FcmpContext {
public:
    FcmpContext() {
        int32_t result = fcmp_init();
        if (result != FCMP_SUCCESS) {
            throw FcmpError(result);
        }
    }

    ~FcmpContext() {
        fcmp_cleanup();
    }

    // Non-copyable
    FcmpContext(const FcmpContext&) = delete;
    FcmpContext& operator=(const FcmpContext&) = delete;

    // Movable
    FcmpContext(FcmpContext&&) = default;
    FcmpContext& operator=(FcmpContext&&) = default;

    bool IsInitialized() const {
        return fcmp_is_initialized() != 0;
    }

    static std::string GetVersion() {
        return std::string(fcmp_version());
    }
};

/**
 * High-level wrapper for FCMP proof generation and verification
 *
 * Uses the Rust FFI library for cryptographic operations.
 */
class FcmpProver {
public:
    /**
     * Create a prover with the given tree
     */
    explicit FcmpProver(std::shared_ptr<curvetree::CurveTree> tree)
        : m_tree(std::move(tree)) {}

    /**
     * Generate a proof that an output is in the tree
     *
     * @param output The output tuple (O, I, C)
     * @param leaf_index Index of the output in the tree
     * @param secret_key Secret key for Schnorr proof construction
     * @param rerandomizer Rerandomization scalar
     * @return Serialized proof bytes
     * @throws FcmpError on failure
     */
    std::vector<uint8_t> GenerateProof(
        const curvetree::OutputTuple& output,
        uint64_t leaf_index,
        const ed25519::Scalar& secret_key,
        const ed25519::Scalar& rerandomizer
    );

    /**
     * Estimate the proof size for verification buffer allocation
     */
    size_t EstimateProofSize(uint32_t num_inputs = 1) const {
        uint32_t depth = m_tree->GetDepth();
        return fcmp_proof_size(num_inputs, depth);
    }

private:
    std::shared_ptr<curvetree::CurveTree> m_tree;
};

/**
 * High-level wrapper for FCMP proof verification
 */
class FcmpVerifier {
public:
    /**
     * Create a verifier with the given tree root
     */
    explicit FcmpVerifier(const ed25519::Point& tree_root)
        : m_tree_root(tree_root) {}

    /**
     * Verify an FCMP proof
     *
     * @param input The input tuple for verification
     * @param proof The proof bytes
     * @return true if valid, false otherwise
     */
    bool Verify(const FcmpInput& input, const std::vector<uint8_t>& proof) const;

    /**
     * Update the tree root (e.g., after new blocks)
     */
    void SetTreeRoot(const ed25519::Point& root) {
        m_tree_root = root;
    }

private:
    ed25519::Point m_tree_root;
};

// ============================================================================
// Utility functions using Rust FFI
// ============================================================================

namespace util {

/**
 * Generate a random scalar using the Rust library
 */
inline ed25519::Scalar RandomScalar() {
    ed25519::Scalar s;
    int32_t result = fcmp_scalar_random(s.data.data());
    if (result != FCMP_SUCCESS) {
        throw FcmpError(result);
    }
    return s;
}

/**
 * Add two scalars using the Rust library
 */
inline ed25519::Scalar ScalarAdd(const ed25519::Scalar& a, const ed25519::Scalar& b) {
    ed25519::Scalar result;
    int32_t code = fcmp_scalar_add(result.data.data(), a.data.data(), b.data.data());
    if (code != FCMP_SUCCESS) {
        throw FcmpError(code);
    }
    return result;
}

/**
 * Multiply two scalars using the Rust library
 */
inline ed25519::Scalar ScalarMul(const ed25519::Scalar& a, const ed25519::Scalar& b) {
    ed25519::Scalar result;
    int32_t code = fcmp_scalar_mul(result.data.data(), a.data.data(), b.data.data());
    if (code != FCMP_SUCCESS) {
        throw FcmpError(code);
    }
    return result;
}

/**
 * Scalar-point multiplication using the Rust library
 */
inline ed25519::Point PointMul(const ed25519::Scalar& scalar, const ed25519::Point& point) {
    ed25519::Point result;
    int32_t code = fcmp_point_mul(result.data.data(), scalar.data.data(), point.data.data());
    if (code != FCMP_SUCCESS) {
        throw FcmpError(code);
    }
    return result;
}

/**
 * Point addition using the Rust library
 */
inline ed25519::Point PointAdd(const ed25519::Point& a, const ed25519::Point& b) {
    ed25519::Point result;
    int32_t code = fcmp_point_add(result.data.data(), a.data.data(), b.data.data());
    if (code != FCMP_SUCCESS) {
        throw FcmpError(code);
    }
    return result;
}

/**
 * Get Ed25519 base point using the Rust library
 */
inline ed25519::Point Basepoint() {
    ed25519::Point result;
    int32_t code = fcmp_point_basepoint(result.data.data());
    if (code != FCMP_SUCCESS) {
        throw FcmpError(code);
    }
    return result;
}

/**
 * Check if a point is valid using the Rust library
 */
inline bool PointIsValid(const ed25519::Point& point) {
    return fcmp_point_is_valid(point.data.data()) != 0;
}

/**
 * Hash data to scalar using the Rust library
 */
inline ed25519::Scalar HashToScalar(const std::vector<uint8_t>& data) {
    ed25519::Scalar result;
    int32_t code = fcmp_hash_to_scalar(
        result.data.data(),
        data.data(),
        data.size()
    );
    if (code != FCMP_SUCCESS) {
        throw FcmpError(code);
    }
    return result;
}

/**
 * Hash data to point using the Rust library
 */
inline ed25519::Point HashToPoint(const std::vector<uint8_t>& data) {
    ed25519::Point result;
    int32_t code = fcmp_hash_to_point(
        result.data.data(),
        data.data(),
        data.size()
    );
    if (code != FCMP_SUCCESS) {
        throw FcmpError(code);
    }
    return result;
}

/**
 * Create Pedersen commitment using the Rust library
 */
inline ed25519::Point PedersenCommit(const ed25519::Scalar& value, const ed25519::Scalar& blinding) {
    ed25519::Point result;
    int32_t code = fcmp_pedersen_commit(
        result.data.data(),
        value.data.data(),
        blinding.data.data()
    );
    if (code != FCMP_SUCCESS) {
        throw FcmpError(code);
    }
    return result;
}

} // namespace util

} // namespace fcmp
} // namespace privacy

#endif // WATTX_PRIVACY_FCMP_WRAPPER_H
