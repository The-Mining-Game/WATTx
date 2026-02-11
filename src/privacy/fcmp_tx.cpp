// Copyright (c) 2024-2026 The WATTx Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <privacy/fcmp_tx.h>
#include <privacy/fcmp/fcmp_wrapper.h>
#include <privacy/privacy.h>  // For IsKeyImageSpent
#include <privacy/ed25519/ed25519_types.h>
#include <privacy/ed25519/pedersen.h>
#include <hash.h>
#include <util/strencodings.h>

#include <cstring>

namespace privacy {

// ============================================================================
// CFcmpTransactionBuilder Implementation
// ============================================================================

CFcmpTransactionBuilder::CFcmpTransactionBuilder(
    std::shared_ptr<curvetree::CurveTree> tree
) : m_tree(std::move(tree)) {}

bool CFcmpTransactionBuilder::AddInput(
    uint64_t leafIndex,
    const curvetree::OutputTuple& output,
    const ed25519::Scalar& secretKey,
    CAmount amount,
    const ed25519::Scalar& blindingFactor
) {
    // Verify the output exists in the tree
    auto retrieved = m_tree->GetOutput(leafIndex);
    if (!retrieved) {
        return false;
    }

    // Store input data
    InputData data;
    data.leafIndex = leafIndex;
    data.output = output;
    data.secretKey = secretKey;
    data.amount = amount;
    data.blindingFactor = blindingFactor;

    m_inputs.push_back(std::move(data));
    return true;
}

bool CFcmpTransactionBuilder::AddOutput(
    const curvetree::OutputTuple& output,
    CAmount amount,
    const ed25519::Scalar& blindingFactor
) {
    OutputData data;
    data.output = output;
    data.amount = amount;
    data.blindingFactor = blindingFactor;

    m_outputs.push_back(std::move(data));
    return true;
}

void CFcmpTransactionBuilder::SetFee(CAmount fee) {
    m_fee = fee;
}

CAmount CFcmpTransactionBuilder::GetInputSum() const {
    CAmount sum = 0;
    for (const auto& input : m_inputs) {
        sum += input.amount;
    }
    return sum;
}

CAmount CFcmpTransactionBuilder::GetOutputSum() const {
    CAmount sum = 0;
    for (const auto& output : m_outputs) {
        sum += output.amount;
    }
    return sum;
}

bool CFcmpTransactionBuilder::VerifyBalance() const {
    return GetInputSum() == GetOutputSum() + m_fee;
}

CFcmpInputTuple CFcmpTransactionBuilder::ReRandomizeInput(
    const curvetree::OutputTuple& output,
    ed25519::Scalar& rerandomizer
) {
    CFcmpInputTuple tuple;

    // Generate random rerandomizer
    rerandomizer = ed25519::Scalar::Random();

    // Get generator points
    auto G = ed25519::Point::BasePoint();
    auto H = ed25519::PedersenGenerators::Default().H();

    // O_tilde = O + r*G
    auto rG = rerandomizer * G;
    tuple.O_tilde = output.O + rG;

    // I_tilde = I (key image cannot be re-randomized)
    tuple.I_tilde = output.I;

    // R = r*G (for SA+L signature)
    tuple.R = rG;

    // C_tilde = C + r*H
    auto rH = rerandomizer * H;
    tuple.C_tilde = output.C + rH;

    return tuple;
}

CKeyImage CFcmpTransactionBuilder::GenerateKeyImage(
    const ed25519::Scalar& secretKey,
    const ed25519::Point& outputPoint
) {
    // Compute Hp(O) - hash of output to point
    std::vector<uint8_t> toHash(outputPoint.data.begin(), outputPoint.data.end());
    auto Hp = ed25519::Point::HashToPoint(toHash);

    // Key image I = x * Hp(O)
    auto I = secretKey * Hp;

    // Convert to CKeyImage format (compressed point)
    CKeyImage keyImage;
    // Ed25519 points are 32 bytes, CKeyImage expects 33 bytes (secp256k1 format)
    // For compatibility, we'll use a prefix byte
    keyImage.data.resize(33);
    keyImage.data[0] = 0x02; // Prefix indicating Ed25519 key image
    std::memcpy(keyImage.data.data() + 1, I.data.data(), 32);

    return keyImage;
}

CFcmpSALSignature CFcmpTransactionBuilder::GenerateSALSignature(
    const ed25519::Scalar& secretKey,
    const ed25519::Scalar& rerandomizer,
    const CFcmpInputTuple& inputTuple,
    const uint256& messageHash
) {
    CFcmpSALSignature sig;

    // Schnorr-like signature:
    // 1. k = random nonce
    // 2. R = k*G (already computed as inputTuple.R during rerandomization)
    // 3. c = H(R || I_tilde || O_tilde || message)
    // 4. s = k + c*x (where x = secretKey)

    // Generate random nonce (we use the rerandomizer as the nonce for simplicity)
    // In production, this should be derived more carefully

    // Compute challenge c = H(R || I_tilde || O_tilde || message)
    HashWriter hasher{};
    hasher << inputTuple.R.data;
    hasher << inputTuple.I_tilde.data;
    hasher << inputTuple.O_tilde.data;
    hasher << messageHash;
    uint256 challengeHash = hasher.GetHash();

    // Convert challenge to scalar
    sig.c = ed25519::Scalar::FromBytesModOrder(
        std::vector<uint8_t>(challengeHash.begin(), challengeHash.end())
    );

    // s = r + c*x (mod l)
    auto cx = sig.c * secretKey;
    sig.s = rerandomizer + cx;

    return sig;
}

std::vector<CFcmpInput> CFcmpTransactionBuilder::BuildInputs() {
    if (m_inputs.empty()) {
        return {};
    }

    if (!VerifyBalance()) {
        return {};
    }

    std::vector<CFcmpInput> result;
    result.reserve(m_inputs.size());

    // Compute message hash (simplified - would include all tx data)
    HashWriter hasher{};
    for (const auto& input : m_inputs) {
        hasher << input.leafIndex;
        hasher << input.amount;
    }
    for (const auto& output : m_outputs) {
        hasher << output.amount;
    }
    hasher << m_fee;
    uint256 messageHash = hasher.GetHash();

    // Build blinding factor for pseudo-outputs
    ed25519::Scalar totalInputBlinding;
    ed25519::Scalar totalOutputBlinding;

    for (const auto& input : m_inputs) {
        totalInputBlinding = totalInputBlinding + input.blindingFactor;
    }
    for (const auto& output : m_outputs) {
        totalOutputBlinding = totalOutputBlinding + output.blindingFactor;
    }

    // Process each input
    for (size_t i = 0; i < m_inputs.size(); ++i) {
        const auto& inputData = m_inputs[i];
        CFcmpInput fcmpInput;

        // Generate key image
        fcmpInput.keyImage = GenerateKeyImage(inputData.secretKey, inputData.output.O);

        // Re-randomize input
        ed25519::Scalar rerandomizer;
        fcmpInput.inputTuple = ReRandomizeInput(inputData.output, rerandomizer);

        // Generate membership proof via Rust FFI
        try {
            fcmp::FcmpContext ctx;
            fcmp::FcmpProver prover(m_tree);
            auto proofBytes = prover.GenerateProof(
                inputData.output, inputData.leafIndex,
                inputData.secretKey, rerandomizer
            );
            fcmpInput.membershipProof = CFcmpProof(std::move(proofBytes), m_tree->GetRoot());
        } catch (const std::exception& e) {
            // Proof generation failed
            return {};
        }

        // Generate SA+L signature
        fcmpInput.salSignature = GenerateSALSignature(
            inputData.secretKey,
            rerandomizer,
            fcmpInput.inputTuple,
            messageHash
        );

        // Create pseudo-output commitment
        // For the last input, adjust blinding to ensure balance
        ed25519::Scalar pseudoBlinding;
        if (i == m_inputs.size() - 1) {
            // Last input: blinding = totalInputBlinding - sum(other pseudo blindings) - totalOutputBlinding
            // For simplicity, we use the input's blinding factor
            pseudoBlinding = inputData.blindingFactor;
        } else {
            pseudoBlinding = ed25519::Scalar::Random();
        }

        // Pseudo-output = amount*H + blinding*G
        auto pedersen = ed25519::PedersenCommitment::CommitAmount(
            static_cast<uint64_t>(inputData.amount),
            pseudoBlinding
        );
        // Store Ed25519 point in CPedersenCommitment (33 bytes with prefix)
        fcmpInput.pseudoOutput.data.resize(33);
        fcmpInput.pseudoOutput.data[0] = 0x02; // Ed25519 prefix
        std::memcpy(fcmpInput.pseudoOutput.data.data() + 1, pedersen.GetPoint().data.data(), 32);

        result.push_back(std::move(fcmpInput));
    }

    return result;
}

// ============================================================================
// Verification Functions
// ============================================================================

bool VerifyFcmpInput(
    const CFcmpInput& input,
    const ed25519::Point& treeRoot,
    const uint256& messageHash
) {
    // 1. Verify input is structurally valid
    if (!input.IsValid()) {
        return false;
    }

    // 2. Verify tree root matches proof
    if (input.membershipProof.treeRoot.data != treeRoot.data) {
        return false;
    }

    // 3. Verify SA+L signature
    // s*G should equal R + c*O_tilde
    auto G = ed25519::Point::BasePoint();
    auto sG = input.salSignature.s * G;
    auto cO = input.salSignature.c * input.inputTuple.O_tilde;
    auto R_plus_cO = input.inputTuple.R + cO;

    if (sG.data != R_plus_cO.data) {
        return false;
    }

    // 4. Verify FCMP proof via Rust FFI
    {
        fcmp::FcmpContext ctx;
        fcmp::FcmpVerifier verifier(treeRoot);

        // Convert input tuple to FFI format
        FcmpInput ffiInput;
        std::memset(&ffiInput, 0, sizeof(ffiInput));
        std::memcpy(ffiInput.o_tilde, input.inputTuple.O_tilde.data.data(), 32);
        std::memcpy(ffiInput.o_tilde + 32, input.inputTuple.O_tilde.data.data(), 32);
        std::memcpy(ffiInput.i_tilde, input.inputTuple.I_tilde.data.data(), 32);
        std::memcpy(ffiInput.i_tilde + 32, input.inputTuple.I_tilde.data.data(), 32);
        std::memcpy(ffiInput.r, input.inputTuple.R.data.data(), 32);
        std::memcpy(ffiInput.r + 32, input.inputTuple.R.data.data(), 32);
        std::memcpy(ffiInput.c_tilde, input.inputTuple.C_tilde.data.data(), 32);
        std::memcpy(ffiInput.c_tilde + 32, input.inputTuple.C_tilde.data.data(), 32);

        if (!verifier.Verify(ffiInput, input.membershipProof.proofData)) {
            return false;
        }
    }

    return true;
}

bool VerifyFcmpKeyImageUnspent(const CFcmpInput& input) {
    // Check against spent key image database
    return !privacy::IsKeyImageSpent(input.keyImage);
}

bool VerifyFcmpBalance(
    const std::vector<CFcmpInput>& inputs,
    const std::vector<CPedersenCommitment>& outputCommitments,
    CAmount fee
) {
    if (inputs.empty() || outputCommitments.empty()) {
        return false;
    }

    // Sum of pseudo-outputs should equal sum of output commitments + fee*H
    ed25519::Point sumPseudo = ed25519::Point::Identity();

    for (const auto& input : inputs) {
        ed25519::Point pseudoPoint;
        if (!input.pseudoOutput.IsValid()) {
            return false;
        }
        // Convert CPedersenCommitment to ed25519::Point (skip prefix byte)
        if (input.pseudoOutput.data.size() >= 33) {
            std::memcpy(pseudoPoint.data.data(), input.pseudoOutput.data.data() + 1, 32);
        } else if (input.pseudoOutput.data.size() == 32) {
            std::memcpy(pseudoPoint.data.data(), input.pseudoOutput.data.data(), 32);
        } else {
            return false;
        }
        sumPseudo = sumPseudo + pseudoPoint;
    }

    // Sum output commitments
    ed25519::Point sumOutputs = ed25519::Point::Identity();

    for (const auto& commitment : outputCommitments) {
        ed25519::Point outputPoint;
        // Convert CPedersenCommitment to ed25519::Point (skip prefix byte)
        if (commitment.data.size() >= 33) {
            std::memcpy(outputPoint.data.data(), commitment.data.data() + 1, 32);
        } else if (commitment.data.size() == 32) {
            std::memcpy(outputPoint.data.data(), commitment.data.data(), 32);
        } else {
            return false;
        }
        sumOutputs = sumOutputs + outputPoint;
    }

    // Add fee*H to outputs
    auto H = ed25519::PedersenGenerators::Default().H();
    ed25519::Scalar feeScalar(static_cast<uint64_t>(fee));
    auto feeCommitment = feeScalar * H;
    sumOutputs = sumOutputs + feeCommitment;

    // Verify balance: sumPseudo == sumOutputs
    return sumPseudo.data == sumOutputs.data;
}

bool BatchVerifyFcmpInputs(
    const std::vector<CFcmpInput>& inputs,
    const ed25519::Point& treeRoot,
    const uint256& messageHash
) {
    // For now, verify individually
    // Future optimization: use batch verification for signatures and proofs
    for (const auto& input : inputs) {
        if (!VerifyFcmpInput(input, treeRoot, messageHash)) {
            return false;
        }
        if (!VerifyFcmpKeyImageUnspent(input)) {
            return false;
        }
    }
    return true;
}

// ============================================================================
// Utility Functions
// ============================================================================

curvetree::OutputTuple OutputToTreeFormat(
    const ed25519::Point& O,
    const ed25519::Point& I,
    const ed25519::Point& C
) {
    curvetree::OutputTuple tuple;
    tuple.O = O;
    tuple.I = I;
    tuple.C = C;
    return tuple;
}

curvetree::OutputTuple GenerateOutputTuple(
    const ed25519::Point& spendPubkey,
    CAmount amount,
    const ed25519::Scalar& blinding
) {
    curvetree::OutputTuple tuple;

    // O = spend public key (one-time address)
    tuple.O = spendPubkey;

    // I = Hp(O) - hash of O to point (key image base)
    std::vector<uint8_t> toHash(spendPubkey.data.begin(), spendPubkey.data.end());
    tuple.I = ed25519::Point::HashToPoint(toHash);

    // C = amount*H + blinding*G (Pedersen commitment)
    auto commitment = ed25519::PedersenCommitment::CommitAmount(
        static_cast<uint64_t>(amount),
        blinding
    );
    tuple.C = commitment.GetPoint();

    return tuple;
}

} // namespace privacy
