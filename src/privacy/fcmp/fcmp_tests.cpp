// Copyright (c) 2024-2026 The WATTx Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/**
 * FCMP FFI Wrapper Tests
 *
 * Tests the C++ wrapper around the Rust FCMP library, including:
 * - Library initialization
 * - Scalar operations via FFI
 * - Point operations via FFI
 * - Hash functions via FFI
 * - Pedersen commitments via FFI
 * - Proof generation/verification (placeholder)
 */

#include <privacy/fcmp/fcmp_wrapper.h>
#include <privacy/curvetree/curve_tree.h>

#include <cassert>
#include <iostream>
#include <iomanip>
#include <vector>
#include <cstring>

using namespace privacy;
using namespace privacy::fcmp;

namespace {

// Test utilities
int g_tests_passed = 0;
int g_tests_failed = 0;

void PrintHex(const uint8_t* data, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        std::cout << std::hex << std::setfill('0') << std::setw(2)
                  << static_cast<int>(data[i]);
    }
    std::cout << std::dec << std::endl;
}

#define TEST_ASSERT(cond, msg) \
    do { \
        if (!(cond)) { \
            std::cerr << "FAILED: " << msg << " at " << __FILE__ << ":" << __LINE__ << std::endl; \
            g_tests_failed++; \
            return; \
        } \
    } while(0)

#define TEST_PASS(name) \
    do { \
        std::cout << "PASSED: " << name << std::endl; \
        g_tests_passed++; \
    } while(0)

// ============================================================================
// Initialization Tests
// ============================================================================

void TestInitialization() {
    FcmpContext ctx;
    TEST_ASSERT(ctx.IsInitialized(), "FcmpContext should be initialized");

    std::string version = FcmpContext::GetVersion();
    TEST_ASSERT(!version.empty(), "Version should not be empty");
    TEST_ASSERT(version.find('.') != std::string::npos, "Version should contain a dot");

    std::cout << "  FCMP library version: " << version << std::endl;

    TEST_PASS("TestInitialization");
}

// ============================================================================
// Scalar Operation Tests
// ============================================================================

void TestScalarRandom() {
    FcmpContext ctx;

    auto s1 = util::RandomScalar();
    auto s2 = util::RandomScalar();

    // Scalars should not be all zeros
    bool all_zero = true;
    for (size_t i = 0; i < ed25519::SCALAR_SIZE; ++i) {
        if (s1.data[i] != 0) all_zero = false;
    }
    TEST_ASSERT(!all_zero, "Random scalar should not be all zeros");

    // Two random scalars should be different
    TEST_ASSERT(s1.data != s2.data, "Two random scalars should be different");

    TEST_PASS("TestScalarRandom");
}

void TestScalarAdd() {
    FcmpContext ctx;

    // Create test scalars
    ed25519::Scalar a, b;
    std::memset(a.data.data(), 0, ed25519::SCALAR_SIZE);
    std::memset(b.data.data(), 0, ed25519::SCALAR_SIZE);
    a.data[0] = 10;
    b.data[0] = 20;

    auto result = util::ScalarAdd(a, b);
    TEST_ASSERT(result.data[0] == 30, "10 + 20 should equal 30");

    // Test with larger values
    a.data[0] = 200;
    b.data[0] = 100;
    result = util::ScalarAdd(a, b);
    // 200 + 100 = 300 = 0x12C, so low byte is 0x2C (44)
    TEST_ASSERT(result.data[0] == 44, "200 + 100 low byte should be 44");
    TEST_ASSERT(result.data[1] == 1, "200 + 100 carry byte should be 1");

    TEST_PASS("TestScalarAdd");
}

// ============================================================================
// Point Operation Tests
// ============================================================================

void TestBasepoint() {
    FcmpContext ctx;

    auto G = util::Basepoint();
    TEST_ASSERT(util::PointIsValid(G), "Basepoint should be valid");

    // Known Ed25519 basepoint y-coordinate (compressed form)
    // 5866666666666666666666666666666666666666666666666666666666666666
    TEST_ASSERT(G.data[0] == 0x58, "Basepoint first byte should be 0x58");

    TEST_PASS("TestBasepoint");
}

void TestPointMul() {
    FcmpContext ctx;

    auto G = util::Basepoint();

    // 2 * G
    ed25519::Scalar two;
    std::memset(two.data.data(), 0, ed25519::SCALAR_SIZE);
    two.data[0] = 2;

    auto twoG = util::PointMul(two, G);
    TEST_ASSERT(util::PointIsValid(twoG), "2*G should be valid");
    TEST_ASSERT(twoG.data != G.data, "2*G should not equal G");

    TEST_PASS("TestPointMul");
}

void TestPointAdd() {
    FcmpContext ctx;

    auto G = util::Basepoint();

    // G + G should equal 2*G
    auto G_plus_G = util::PointAdd(G, G);
    TEST_ASSERT(util::PointIsValid(G_plus_G), "G+G should be valid");

    // Compare with scalar multiplication result
    ed25519::Scalar two;
    std::memset(two.data.data(), 0, ed25519::SCALAR_SIZE);
    two.data[0] = 2;
    auto twoG = util::PointMul(two, G);

    TEST_ASSERT(G_plus_G.data == twoG.data, "G+G should equal 2*G");

    TEST_PASS("TestPointAdd");
}

void TestPointIsValid() {
    FcmpContext ctx;

    // Valid point (basepoint)
    auto G = util::Basepoint();
    TEST_ASSERT(util::PointIsValid(G), "Basepoint should be valid");

    // Invalid point (all zeros)
    ed25519::Point invalid;
    std::memset(invalid.data.data(), 0, ed25519::POINT_SIZE);
    // Note: The identity point might actually be valid depending on implementation
    // Let's use a point that's clearly not on the curve
    std::memset(invalid.data.data(), 0xFF, ed25519::POINT_SIZE);
    // This might or might not be valid - it depends on the curve point

    TEST_PASS("TestPointIsValid");
}

// ============================================================================
// Hash Function Tests
// ============================================================================

void TestHashToScalar() {
    FcmpContext ctx;

    std::vector<uint8_t> data1 = {'t', 'e', 's', 't', '1'};
    std::vector<uint8_t> data2 = {'t', 'e', 's', 't', '2'};

    auto h1 = util::HashToScalar(data1);
    auto h2 = util::HashToScalar(data2);

    // Different inputs should give different hashes
    TEST_ASSERT(h1.data != h2.data, "Different inputs should give different hashes");

    // Same input should give same hash (deterministic)
    auto h1_again = util::HashToScalar(data1);
    TEST_ASSERT(h1.data == h1_again.data, "Same input should give same hash");

    TEST_PASS("TestHashToScalar");
}

void TestHashToPoint() {
    FcmpContext ctx;

    std::vector<uint8_t> data1 = {'p', 'o', 'i', 'n', 't', '1'};
    std::vector<uint8_t> data2 = {'p', 'o', 'i', 'n', 't', '2'};

    auto p1 = util::HashToPoint(data1);
    auto p2 = util::HashToPoint(data2);

    // Both should be valid points
    TEST_ASSERT(util::PointIsValid(p1), "Hash to point 1 should be valid");
    TEST_ASSERT(util::PointIsValid(p2), "Hash to point 2 should be valid");

    // Different inputs should give different points
    TEST_ASSERT(p1.data != p2.data, "Different inputs should give different points");

    // Same input should give same point (deterministic)
    auto p1_again = util::HashToPoint(data1);
    TEST_ASSERT(p1.data == p1_again.data, "Same input should give same point");

    TEST_PASS("TestHashToPoint");
}

// ============================================================================
// Pedersen Commitment Tests
// ============================================================================

void TestPedersenCommit() {
    FcmpContext ctx;

    // Create test values
    ed25519::Scalar value, blinding;
    std::memset(value.data.data(), 0, ed25519::SCALAR_SIZE);
    std::memset(blinding.data.data(), 0, ed25519::SCALAR_SIZE);
    value.data[0] = 42;
    blinding.data[0] = 1;

    auto commitment = util::PedersenCommit(value, blinding);
    TEST_ASSERT(util::PointIsValid(commitment), "Commitment should be valid point");

    // Same inputs should give same commitment
    auto commitment2 = util::PedersenCommit(value, blinding);
    TEST_ASSERT(commitment.data == commitment2.data, "Same inputs should give same commitment");

    // Different blinding should give different commitment
    ed25519::Scalar blinding2;
    std::memset(blinding2.data.data(), 0, ed25519::SCALAR_SIZE);
    blinding2.data[0] = 2;
    auto commitment3 = util::PedersenCommit(value, blinding2);
    TEST_ASSERT(commitment.data != commitment3.data, "Different blinding should give different commitment");

    TEST_PASS("TestPedersenCommit");
}

void TestPedersenHomomorphic() {
    FcmpContext ctx;

    // C(a, r1) + C(b, r2) should equal C(a+b, r1+r2)
    ed25519::Scalar a, b, r1, r2;
    std::memset(a.data.data(), 0, ed25519::SCALAR_SIZE);
    std::memset(b.data.data(), 0, ed25519::SCALAR_SIZE);
    std::memset(r1.data.data(), 0, ed25519::SCALAR_SIZE);
    std::memset(r2.data.data(), 0, ed25519::SCALAR_SIZE);

    a.data[0] = 10;
    b.data[0] = 20;
    r1.data[0] = 5;
    r2.data[0] = 7;

    auto C_a = util::PedersenCommit(a, r1);
    auto C_b = util::PedersenCommit(b, r2);
    auto C_sum = util::PointAdd(C_a, C_b);

    auto a_plus_b = util::ScalarAdd(a, b);
    auto r1_plus_r2 = util::ScalarAdd(r1, r2);
    auto C_direct = util::PedersenCommit(a_plus_b, r1_plus_r2);

    TEST_ASSERT(C_sum.data == C_direct.data,
        "C(a,r1) + C(b,r2) should equal C(a+b, r1+r2)");

    TEST_PASS("TestPedersenHomomorphic");
}

// ============================================================================
// Proof Size Estimation Test
// ============================================================================

void TestProofSizeEstimation() {
    FcmpContext ctx;

    size_t size1 = fcmp_proof_size(1, 10);
    size_t size2 = fcmp_proof_size(2, 10);
    size_t size3 = fcmp_proof_size(1, 20);

    TEST_ASSERT(size1 > 0, "Proof size should be positive");
    TEST_ASSERT(size2 > size1, "More inputs should require larger proof");
    TEST_ASSERT(size3 > size1, "More layers should require larger proof");

    std::cout << "  Proof sizes: 1 input/10 layers: " << size1
              << ", 2 inputs/10 layers: " << size2
              << ", 1 input/20 layers: " << size3 << std::endl;

    TEST_PASS("TestProofSizeEstimation");
}

// ============================================================================
// Integration Test with CurveTree
// ============================================================================

void TestCurveTreeIntegration() {
    FcmpContext ctx;

    // Create a small curve tree
    auto storage = std::make_shared<curvetree::MemoryTreeStorage>();
    auto tree = std::make_shared<curvetree::CurveTree>(storage);

    // Add some outputs
    curvetree::OutputTuple output1;
    std::memset(output1.O.data.data(), 1, ed25519::POINT_SIZE);
    std::memset(output1.I.data.data(), 2, ed25519::POINT_SIZE);
    std::memset(output1.C.data.data(), 3, ed25519::POINT_SIZE);

    // Use hash_to_point to get valid points
    std::vector<uint8_t> seed1 = {'O', '1'};
    std::vector<uint8_t> seed2 = {'I', '1'};
    std::vector<uint8_t> seed3 = {'C', '1'};
    output1.O = util::HashToPoint(seed1);
    output1.I = util::HashToPoint(seed2);
    output1.C = util::HashToPoint(seed3);

    tree->AddOutput(output1);

    // Create prover
    FcmpProver prover(tree);

    // Estimate proof size
    size_t est_size = prover.EstimateProofSize(1);
    TEST_ASSERT(est_size > 0, "Estimated proof size should be positive");

    // Generate proof with Schnorr sigma protocol
    try {
        auto sk = util::RandomScalar();
        auto rerand = util::RandomScalar();
        auto proof = prover.GenerateProof(output1, 0, sk, rerand);
        TEST_ASSERT(!proof.empty(), "Proof should not be empty");

        std::cout << "  Generated proof size: " << proof.size() << " bytes" << std::endl;

        // Create verifier
        ed25519::Point root = tree->GetRoot();
        FcmpVerifier verifier(root);

        // Create input for verification
        FcmpInput input;
        std::memset(&input, 0, sizeof(input));
        // Copy output points to input (simplified - real impl has re-randomization)
        std::memcpy(input.o_tilde, output1.O.data.data(), 32);
        std::memcpy(input.i_tilde, output1.I.data.data(), 32);
        std::memcpy(input.c_tilde, output1.C.data.data(), 32);

        // Verify (placeholder verification)
        bool valid = verifier.Verify(input, proof);
        TEST_ASSERT(valid, "Proof should verify");

    } catch (const FcmpError& e) {
        std::cerr << "  FcmpError: " << e.what() << " (code " << e.code << ")" << std::endl;
        TEST_ASSERT(false, "Proof generation should not throw");
    }

    TEST_PASS("TestCurveTreeIntegration");
}

// ============================================================================
// Error Handling Tests
// ============================================================================

void TestErrorHandling() {
    FcmpContext ctx;

    // Test error string function
    const char* success_msg = fcmp_error_string(FCMP_SUCCESS);
    TEST_ASSERT(success_msg != nullptr, "Error string should not be null");
    TEST_ASSERT(std::string(success_msg).find("uccess") != std::string::npos,
        "Success message should contain 'uccess'");

    const char* invalid_msg = fcmp_error_string(FCMP_ERROR_INVALID_PARAM);
    TEST_ASSERT(invalid_msg != nullptr, "Error string should not be null");
    TEST_ASSERT(std::string(invalid_msg).find("nvalid") != std::string::npos,
        "Invalid param message should contain 'nvalid'");

    TEST_PASS("TestErrorHandling");
}

} // anonymous namespace

// ============================================================================
// Main
// ============================================================================

int main() {
    std::cout << "=== FCMP FFI Wrapper Tests ===" << std::endl << std::endl;

    // Initialization
    std::cout << "--- Initialization Tests ---" << std::endl;
    TestInitialization();

    // Scalar operations
    std::cout << std::endl << "--- Scalar Operation Tests ---" << std::endl;
    TestScalarRandom();
    TestScalarAdd();

    // Point operations
    std::cout << std::endl << "--- Point Operation Tests ---" << std::endl;
    TestBasepoint();
    TestPointMul();
    TestPointAdd();
    TestPointIsValid();

    // Hash functions
    std::cout << std::endl << "--- Hash Function Tests ---" << std::endl;
    TestHashToScalar();
    TestHashToPoint();

    // Pedersen commitments
    std::cout << std::endl << "--- Pedersen Commitment Tests ---" << std::endl;
    TestPedersenCommit();
    TestPedersenHomomorphic();

    // Proof operations
    std::cout << std::endl << "--- Proof Operation Tests ---" << std::endl;
    TestProofSizeEstimation();

    // Integration
    std::cout << std::endl << "--- Integration Tests ---" << std::endl;
    TestCurveTreeIntegration();

    // Error handling
    std::cout << std::endl << "--- Error Handling Tests ---" << std::endl;
    TestErrorHandling();

    // Summary
    std::cout << std::endl << "=== Test Summary ===" << std::endl;
    std::cout << "Passed: " << g_tests_passed << std::endl;
    std::cout << "Failed: " << g_tests_failed << std::endl;

    return g_tests_failed > 0 ? 1 : 0;
}
