// Copyright (c) 2024-2026 The WATTx Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef WATTX_PRIVACY_CONFIDENTIAL_H
#define WATTX_PRIVACY_CONFIDENTIAL_H

#include <key.h>
#include <pubkey.h>
#include <uint256.h>
#include <serialize.h>
#include <consensus/amount.h>

#include <vector>
#include <optional>

namespace privacy {

/**
 * Confidential Transactions Implementation
 *
 * Hides transaction amounts using Pedersen commitments:
 *   C = v*H + r*G
 * Where:
 *   v = amount (scalar)
 *   r = blinding factor (random scalar)
 *   H = secondary generator (nothing-up-my-sleeve point)
 *   G = secp256k1 generator
 *
 * Properties:
 * - Commitments are homomorphic: C1 + C2 = (v1+v2)*H + (r1+r2)*G
 * - Balance can be verified: sum(inputs) == sum(outputs) + fee
 * - Individual amounts remain hidden
 * - Range proofs ensure amounts are positive (no negative amounts)
 */

/**
 * @brief Pedersen commitment to an amount
 */
class CPedersenCommitment
{
public:
    std::vector<unsigned char> data; // 33 bytes compressed point

    CPedersenCommitment() : data(33, 0) {}
    CPedersenCommitment(const std::vector<unsigned char>& d) : data(d) {}

    bool IsValid() const { return data.size() == 33 && data[0] != 0; }
    bool IsNull() const { return data.size() != 33 || data[0] == 0; }

    bool operator==(const CPedersenCommitment& other) const { return data == other.data; }
    bool operator!=(const CPedersenCommitment& other) const { return !(*this == other); }

    SERIALIZE_METHODS(CPedersenCommitment, obj) {
        READWRITE(obj.data);
    }
};

/**
 * @brief Blinding factor for Pedersen commitment
 */
class CBlindingFactor
{
public:
    uint256 data;

    CBlindingFactor() : data() {}
    CBlindingFactor(const uint256& d) : data(d) {}

    bool IsValid() const { return !data.IsNull(); }
    bool IsNull() const { return data.IsNull(); }

    const unsigned char* begin() const { return data.begin(); }
    const unsigned char* end() const { return data.end(); }

    static CBlindingFactor Random();

    SERIALIZE_METHODS(CBlindingFactor, obj) {
        READWRITE(obj.data);
    }
};

/**
 * @brief Inner product proof for Bulletproofs
 *
 * Proves that for vectors a, b and generators G, H:
 *   P = <a, G> + <b, H> + <a, b> * U
 *
 * The proof is logarithmic in the vector size (log2(n) rounds).
 * Each round produces L and R points.
 */
struct CInnerProductProof
{
    // L and R commitments for each round (log2(n) pairs)
    std::vector<CPubKey> L;
    std::vector<CPubKey> R;

    // Final scalars after recursion
    uint256 a;
    uint256 b;

    bool IsValid() const {
        return !L.empty() && L.size() == R.size();
    }

    size_t Rounds() const { return L.size(); }

    SERIALIZE_METHODS(CInnerProductProof, obj) {
        READWRITE(obj.L, obj.R, obj.a, obj.b);
    }
};

/**
 * @brief Range proof proving amount is in [0, 2^64)
 *
 * Uses Bulletproofs for efficient range proofs.
 * Single proof: ~700 bytes (vs ~5KB for Borromean proofs)
 * Aggregated: Sublinear growth for multiple outputs
 */
class CRangeProof
{
public:
    std::vector<unsigned char> data;

    CRangeProof() = default;
    CRangeProof(const std::vector<unsigned char>& d) : data(d) {}

    bool IsValid() const { return !data.empty(); }
    size_t Size() const { return data.size(); }

    SERIALIZE_METHODS(CRangeProof, obj) {
        READWRITE(obj.data);
    }
};

/**
 * @brief Confidential output with hidden amount
 */
struct CConfidentialOutput
{
    // Pedersen commitment: C = v*H + r*G
    CPedersenCommitment commitment;

    // Range proof that v is in valid range
    CRangeProof rangeProof;

    // Encrypted amount for recipient (optional)
    std::vector<unsigned char> encryptedAmount; // 8 bytes encrypted

    // Encrypted blinding factor for recipient (optional)
    std::vector<unsigned char> encryptedBlinding; // 32 bytes encrypted

    bool IsValid() const {
        return commitment.IsValid() && rangeProof.IsValid();
    }

    SERIALIZE_METHODS(CConfidentialOutput, obj) {
        READWRITE(obj.commitment, obj.rangeProof, obj.encryptedAmount, obj.encryptedBlinding);
    }
};

/**
 * @brief Create a Pedersen commitment
 *
 * @param amount The amount to commit to
 * @param blindingFactor The blinding factor
 * @param commitment [out] The resulting commitment
 * @return true if creation succeeded
 */
bool CreateCommitment(
    CAmount amount,
    const CBlindingFactor& blindingFactor,
    CPedersenCommitment& commitment);

/**
 * @brief Make output blinding factors balance the inputs
 *
 * Sets the LAST output blinding to  sum(inputs) - sum(other outputs)  so that
 * the blinding terms cancel in  sum(in) == sum(out) + fee. The fee commitment
 * carries zero blinding (see CreatePublicValueCommitment), so once the values
 * balance this makes the whole equation hold on the curve.
 *
 * Without this the sender picks every blinding at random, the G-components
 * never cancel, and a correctly-valued transaction is still rejected as
 * imbalanced. The caller must recompute the last output's commitment after
 * calling this.
 *
 * @param inputBlinds   Blinding factors of the input pseudo-outputs
 * @param outputBlinds  [in,out] Output blinding factors; last entry is overwritten
 * @return true if the adjustment succeeded
 */
bool BalanceBlindingFactors(
    const std::vector<CBlindingFactor>& inputBlinds,
    std::vector<CBlindingFactor>& outputBlinds);

/**
 * @brief Commit to a PUBLIC value with zero blinding: C = v*H
 *
 * Used for the transaction fee, which is public. Because the blinding is zero
 * the commitment is fully determined by v, so any verifier can recompute it and
 * check  sum(inputs) == sum(outputs) + fee  without being told a secret.
 * This is what lets a shielded transaction pay a transparent fee while still
 * being balance-checkable.
 *
 * @param amount The public amount (>= 0)
 * @param commitment [out] The resulting commitment
 * @return true if creation succeeded
 */
bool CreatePublicValueCommitment(
    CAmount amount,
    CPedersenCommitment& commitment);

/**
 * @brief Verify that commitments balance (sum inputs == sum outputs)
 *
 * @param inputCommitments Input commitments
 * @param outputCommitments Output commitments
 * @param feeCommitment Commitment to the fee (or null for explicit fee)
 * @return true if commitments balance
 */
bool VerifyCommitmentBalance(
    const std::vector<CPedersenCommitment>& inputCommitments,
    const std::vector<CPedersenCommitment>& outputCommitments,
    const CPedersenCommitment* feeCommitment = nullptr);

/**
 * @brief Create a range proof for an amount
 *
 * @param amount The amount
 * @param blindingFactor The blinding factor used in commitment
 * @param commitment The commitment (for verification)
 * @param rangeProof [out] The generated range proof
 * @return true if creation succeeded
 */
bool CreateRangeProof(
    CAmount amount,
    const CBlindingFactor& blindingFactor,
    const CPedersenCommitment& commitment,
    CRangeProof& rangeProof);

/**
 * @brief Verify a range proof
 *
 * @param commitment The commitment
 * @param rangeProof The range proof
 * @return true if proof is valid
 */
bool VerifyRangeProof(
    const CPedersenCommitment& commitment,
    const CRangeProof& rangeProof);

/**
 * @brief Create aggregated range proof for multiple outputs
 *
 * @param amounts Vector of amounts
 * @param blindingFactors Vector of blinding factors
 * @param commitments Vector of commitments
 * @param rangeProof [out] Single aggregated range proof
 * @return true if creation succeeded
 */
bool CreateAggregatedRangeProof(
    const std::vector<CAmount>& amounts,
    const std::vector<CBlindingFactor>& blindingFactors,
    const std::vector<CPedersenCommitment>& commitments,
    CRangeProof& rangeProof);

/**
 * @brief Verify aggregated range proof
 *
 * @param commitments Vector of commitments
 * @param rangeProof The aggregated range proof
 * @return true if proof is valid for all commitments
 */
bool VerifyAggregatedRangeProof(
    const std::vector<CPedersenCommitment>& commitments,
    const CRangeProof& rangeProof);

/**
 * @brief Compute blinding factor that balances transaction
 *
 * Given input blinding factors and output amounts/blinding factors,
 * compute the final output's blinding factor so commitments balance.
 *
 * @param inputBlinds Input blinding factors
 * @param outputBlinds Output blinding factors (last one computed)
 * @param balancingBlind [out] The computed blinding factor
 * @return true if computation succeeded
 */
bool ComputeBalancingBlindingFactor(
    const std::vector<CBlindingFactor>& inputBlinds,
    const std::vector<CBlindingFactor>& outputBlinds,
    CBlindingFactor& balancingBlind);

/**
 * @brief Encrypt amount for recipient using ECDH
 *
 * @param amount The amount to encrypt
 * @param sharedSecret ECDH shared secret with recipient
 * @param encrypted [out] Encrypted amount (8 bytes)
 * @return true if encryption succeeded
 */
bool EncryptAmount(
    CAmount amount,
    const uint256& sharedSecret,
    std::vector<unsigned char>& encrypted);

/**
 * @brief Decrypt amount using shared secret
 *
 * @param encrypted Encrypted amount
 * @param sharedSecret ECDH shared secret
 * @param amount [out] Decrypted amount
 * @return true if decryption succeeded
 */
bool DecryptAmount(
    const std::vector<unsigned char>& encrypted,
    const uint256& sharedSecret,
    CAmount& amount);

/**
 * @brief Get the secondary generator H for Pedersen commitments
 *
 * H is a nothing-up-my-sleeve point derived from G via hashing.
 * H = hash_to_curve("WATTx_Pedersen_H")
 *
 * @return The H generator as a public key
 */
CPubKey GetGeneratorH();

/**
 * @brief Get the U generator for inner product proofs
 *
 * U is used in the inner product argument: P = <a,G> + <b,H> + <a,b>*U
 *
 * @return The U generator as a public key
 */
CPubKey GetGeneratorU();

/**
 * @brief Create an inner product proof
 *
 * Proves knowledge of vectors a, b such that:
 *   P = <a, G> + <b, H> + <a, b> * U
 *
 * @param transcript Fiat-Shamir transcript data
 * @param G Generator vector
 * @param H Generator vector
 * @param a Witness vector
 * @param b Witness vector
 * @param proof [out] The generated proof
 * @return true if proof creation succeeded
 */
bool CreateInnerProductProof(
    std::vector<unsigned char>& transcript,
    const std::vector<CPubKey>& G,
    const std::vector<CPubKey>& H,
    const std::vector<uint256>& a,
    const std::vector<uint256>& b,
    CInnerProductProof& proof);

/**
 * @brief Verify an inner product proof
 *
 * Verifies that the prover knows a, b such that:
 *   P = <a, G> + <b, H> + c * U
 * where c is the claimed inner product.
 *
 * @param transcript Fiat-Shamir transcript data
 * @param G Generator vector
 * @param H Generator vector
 * @param P Commitment point
 * @param c Claimed inner product
 * @param proof The proof to verify
 * @return true if proof is valid
 */
bool VerifyInnerProductProof(
    std::vector<unsigned char>& transcript,
    const std::vector<CPubKey>& G,
    const std::vector<CPubKey>& H,
    const CPubKey& P,
    const uint256& c,
    const CInnerProductProof& proof);

} // namespace privacy

#endif // WATTX_PRIVACY_CONFIDENTIAL_H
