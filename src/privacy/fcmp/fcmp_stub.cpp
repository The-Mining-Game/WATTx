// Copyright (c) 2026 The WATTx Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Linked only when the FCMP Rust static library is not built (cargo missing,
// or the external fcmp-plus-plus tree is not checked out). Consensus key-image
// tracking does not need the prover. Proof generation and verification fail
// closed so a node built this way cannot accept a forged membership proof.

#include <privacy/fcmp/fcmp_wrapper.h>

extern "C" {

int32_t fcmp_init(void) { return 0; }

void fcmp_cleanup(void) {}

const char* fcmp_error_string(int32_t) { return "FCMP Rust library is not linked"; }

} // extern "C"

namespace privacy {
namespace fcmp {

std::vector<uint8_t> FcmpProver::GenerateProof(
    const curvetree::OutputTuple&,
    uint64_t,
    const ed25519::Scalar&,
    const ed25519::Scalar&)
{
    throw FcmpError(-1, "FCMP Rust library is not linked");
}

bool FcmpVerifier::Verify(const FcmpInput&, const std::vector<uint8_t>&) const
{
    return false;
}

} // namespace fcmp
} // namespace privacy
