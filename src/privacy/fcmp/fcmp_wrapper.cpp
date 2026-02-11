// Copyright (c) 2024-2026 The WATTx Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <privacy/fcmp/fcmp_wrapper.h>

#include <cstring>

namespace privacy {
namespace fcmp {

std::vector<uint8_t> FcmpProver::GenerateProof(
    const curvetree::OutputTuple& output,
    uint64_t leaf_index,
    const ed25519::Scalar& secret_key,
    const ed25519::Scalar& rerandomizer
) {
    // Get the branch (Merkle path) for this output
    auto branch_opt = m_tree->GetBranch(leaf_index);
    if (!branch_opt) {
        throw FcmpError(FCMP_ERROR_INVALID_PARAM, "Failed to get branch for leaf index");
    }
    const curvetree::TreeBranch& branch = *branch_opt;

    // Get tree root
    ed25519::Point root = m_tree->GetRoot();

    // Prepare output tuple (O || I || C = 96 bytes)
    std::vector<uint8_t> output_bytes(FCMP_OUTPUT_TUPLE_SIZE);
    std::memcpy(output_bytes.data(), output.O.data.data(), FCMP_POINT_SIZE);
    std::memcpy(output_bytes.data() + FCMP_POINT_SIZE, output.I.data.data(), FCMP_POINT_SIZE);
    std::memcpy(output_bytes.data() + 2 * FCMP_POINT_SIZE, output.C.data.data(), FCMP_POINT_SIZE);

    // Convert branch to FFI format
    std::vector<FcmpBranchLayer> layers;
    std::vector<std::vector<uint8_t>> layer_elements;

    for (const auto& level : branch.layers) {
        // Serialize all siblings at this level (each is a Scalar)
        std::vector<uint8_t> elements;
        for (const auto& sibling : level) {
            elements.insert(elements.end(), sibling.data.begin(), sibling.data.end());
        }
        layer_elements.push_back(std::move(elements));
    }

    // Build FcmpBranchLayer array (after layer_elements is stable)
    layers.reserve(branch.layers.size());
    for (size_t i = 0; i < branch.layers.size(); ++i) {
        FcmpBranchLayer layer;
        layer.num_elements = static_cast<uint32_t>(branch.layers[i].size());
        layer.elements = layer_elements[i].data();
        layers.push_back(layer);
    }

    // Build FcmpBranch
    FcmpBranch fcmp_branch;
    fcmp_branch.leaf_index = leaf_index;
    fcmp_branch.num_layers = static_cast<uint32_t>(layers.size());
    fcmp_branch.layers = layers.data();

    // Allocate proof buffer
    size_t max_proof_size = EstimateProofSize(1);
    std::vector<uint8_t> proof(max_proof_size);
    size_t actual_size = 0;

    // Generate proof with secret key and rerandomizer
    int32_t result = fcmp_prove(
        proof.data(),
        &actual_size,
        max_proof_size,
        root.data.data(),
        output_bytes.data(),
        &fcmp_branch,
        secret_key.data.data(),
        rerandomizer.data.data()
    );

    if (result != FCMP_SUCCESS) {
        throw FcmpError(result);
    }

    proof.resize(actual_size);
    return proof;
}

bool FcmpVerifier::Verify(const FcmpInput& input, const std::vector<uint8_t>& proof) const {
    int32_t result = fcmp_verify(
        m_tree_root.data.data(),
        &input,
        proof.data(),
        proof.size()
    );

    return result == FCMP_SUCCESS;
}

} // namespace fcmp
} // namespace privacy
