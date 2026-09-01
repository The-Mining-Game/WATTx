// Copyright (c) 2026 The WATTx Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Confidential amount layer, on ed25519.
//
// WHY THIS FILE EXISTS
// --------------------
// The original implementations (now legacy_secp256k1_* in confidential.cpp)
// built output commitments with secp256k1, while FCMP input pseudo-outputs are
// ed25519 Pedersen commitments (fcmp_tx.cpp). Value conservation cannot be
// verified across two different groups: adding a secp256k1 point to an ed25519
// point is not a defined operation, so "inputs == outputs" was unprovable and a
// shielded output could carry unbacked value. That is a DASH/Particl/Ghost-class
// inflation bug, and it is why fcmp_consensus.cpp fails closed on any
// transaction that creates confidential outputs.
//
// The range proofs had the same problem from the other side: bpplus/ is Monero's
// AUDITED Bulletproofs+ over ed25519, so it could not be pointed at secp256k1
// commitments. The old code fell back to a hand-rolled 229-byte "v1 proof", and
// at one point accepted a 33-byte 0xFF placeholder outright.
//
// This file puts the whole amount layer in ONE group (ed25519, Monero's
// convention C = v*H + r*G) so that:
//   * balance is a real single-group check -- sum(in) == sum(out) + fee;
//   * range proofs come from the audited prover, via bpplus_api.h;
//   * the proof is BOUND to its commitment (wattx_bpplus::verify checks
//     C == 8*V), so a valid proof cannot be replayed onto another output.
//
// ENCODING
// --------
// CPedersenCommitment.data stays 33 bytes so every existing size check,
// serializer and call site keeps working unchanged:
//     data[0]    = COMMITMENT_TAG_ED25519 (0x0E), non-zero so IsValid() holds
//     data[1..33]= compressed ed25519 point
// The tag also makes a legacy secp256k1 commitment (prefix 0x02/0x03/0x08/0x09)
// structurally distinguishable, so the two can never be silently mixed.
//
// Range proof blobs are tagged RANGEPROOF_VERSION_BPPLUS (0x02) to separate them
// from the legacy 0x01 format, which is no longer produced or accepted here.

#include <privacy/confidential.h>
#include <privacy/ed25519/ed25519_types.h>
#include <privacy/ed25519/pedersen.h>

#include <bpplus_api.h>

#include <cstring>
#include <vector>

namespace privacy {

namespace {

constexpr uint8_t COMMITMENT_TAG_ED25519 = 0x0E;
constexpr uint8_t RANGEPROOF_VERSION_BPPLUS = 0x02;
constexpr size_t ED25519_POINT_SIZE = 32;
constexpr size_t COMMITMENT_SIZE = 33;

// Generous upper bound: a BP+ aggregate proof grows logarithmically in the
// number of aggregated values, so this covers well past any sane output count.
constexpr size_t MAX_PROOF_BYTES = 64 * 1024;

//! Encode an ed25519 point into the 33-byte tagged commitment container.
void EncodeCommitment(const ed25519::Point& p, CPedersenCommitment& out)
{
    const std::vector<uint8_t> bytes = p.GetBytes();
    out.data.assign(COMMITMENT_SIZE, 0);
    out.data[0] = COMMITMENT_TAG_ED25519;
    // GetBytes() is always 32 bytes for a compressed ed25519 point; guard anyway
    // so a future change cannot silently write a short commitment.
    if (bytes.size() != ED25519_POINT_SIZE) {
        out.data.assign(COMMITMENT_SIZE, 0); // leaves it !IsValid()
        return;
    }
    std::memcpy(out.data.data() + 1, bytes.data(), ED25519_POINT_SIZE);
}

//! Decode a tagged commitment back to an ed25519 point.
//! Fails closed on wrong size, wrong tag (e.g. a legacy secp256k1 commitment),
//! or a byte string that is not a valid curve point.
bool DecodeCommitment(const CPedersenCommitment& c, ed25519::Point& out)
{
    if (c.data.size() != COMMITMENT_SIZE) return false;
    if (c.data[0] != COMMITMENT_TAG_ED25519) return false;
    out = ed25519::Point(c.data.data() + 1);
    return out.IsValid();
}

//! Reduce a raw 32-byte blinding factor into a canonical ed25519 scalar. The
//! SAME reduction must be used for the commitment and for the range proof, or
//! the proof will not bind to the commitment.
ed25519::Scalar BlindingToScalar(const CBlindingFactor& bf)
{
    return ed25519::Scalar::FromBytesModOrder(bf.begin(), 32);
}

//! Collect n commitments into the flat 32-byte-per-entry buffer bpplus wants.
bool FlattenCommitments(const std::vector<CPedersenCommitment>& commitments,
                        std::vector<uint8_t>& flat)
{
    flat.clear();
    flat.reserve(commitments.size() * ED25519_POINT_SIZE);
    for (const auto& c : commitments) {
        ed25519::Point p;
        if (!DecodeCommitment(c, p)) return false;
        const std::vector<uint8_t> b = p.GetBytes();
        if (b.size() != ED25519_POINT_SIZE) return false;
        flat.insert(flat.end(), b.begin(), b.end());
    }
    return true;
}

} // namespace

bool CreateCommitment(
    CAmount amount,
    const CBlindingFactor& blindingFactor,
    CPedersenCommitment& commitment)
{
    // A negative amount has no representation here and must never be committed:
    // the range proof covers [0, 2^64), so accepting a negative would let a
    // caller construct a commitment no honest proof could cover.
    if (amount < 0) return false;
    if (!blindingFactor.IsValid()) return false;

    const ed25519::Scalar r = BlindingToScalar(blindingFactor);
    const ed25519::PedersenCommitment C =
        ed25519::PedersenCommitment::CommitAmount(static_cast<uint64_t>(amount), r);

    EncodeCommitment(C.commitment, commitment);
    return commitment.IsValid();
}

bool BalanceBlindingFactors(
    const std::vector<CBlindingFactor>& inputBlinds,
    std::vector<CBlindingFactor>& outputBlinds)
{
    if (inputBlinds.empty() || outputBlinds.empty()) return false;

    ed25519::Scalar sumIn = ed25519::Scalar::Zero();
    for (const auto& b : inputBlinds) {
        if (!b.IsValid()) return false;
        sumIn = sumIn + BlindingToScalar(b);
    }

    // Sum every output blinding EXCEPT the last, which we are about to define.
    ed25519::Scalar sumOut = ed25519::Scalar::Zero();
    for (size_t i = 0; i + 1 < outputBlinds.size(); ++i) {
        if (!outputBlinds[i].IsValid()) return false;
        sumOut = sumOut + BlindingToScalar(outputBlinds[i]);
    }

    const ed25519::Scalar last = sumIn - sumOut;
    const std::vector<uint8_t> lb = last.GetBytes();
    if (lb.size() != 32) return false;

    uint256 u;
    std::memcpy(u.begin(), lb.data(), 32);
    outputBlinds.back() = CBlindingFactor(u);

    // A zero final blinding would leak that output's value (C would be v*H with
    // no mask). Astronomically unlikely, but fail rather than silently publish.
    return outputBlinds.back().IsValid();
}

bool ComputeBalancingBlindingFactor(
    const std::vector<CBlindingFactor>& inputBlinds,
    const std::vector<CBlindingFactor>& outputBlinds,
    CBlindingFactor& balancingBlind)
{
    // sum(inputs) - sum(known outputs), on ed25519.
    //
    // The previous implementation summed these modulo the SECP256K1 group order
    // and was left behind when the amount layer moved to ed25519 -- it kept the
    // unprefixed name while its siblings became legacy_secp256k1_*. Reducing mod
    // the wrong order yields a scalar that does not cancel, so commitments built
    // from it never balanced, with nothing to indicate why.
    if (inputBlinds.empty()) return false;

    ed25519::Scalar sum = ed25519::Scalar::Zero();
    for (const auto& b : inputBlinds) {
        if (!b.IsValid()) return false;
        sum = sum + BlindingToScalar(b);
    }
    for (const auto& b : outputBlinds) {
        if (!b.IsValid()) return false;
        sum = sum - BlindingToScalar(b);
    }

    const std::vector<uint8_t> bytes = sum.GetBytes();
    if (bytes.size() != 32) return false;

    uint256 u;
    std::memcpy(u.begin(), bytes.data(), 32);
    balancingBlind = CBlindingFactor(u);

    // A zero result would leave the final commitment unblinded.
    return balancingBlind.IsValid();
}

bool CreatePublicValueCommitment(
    CAmount amount,
    CPedersenCommitment& commitment)
{
    if (amount < 0) return false;

    // Zero blinding on purpose: the fee is public, so C = v*H must be
    // recomputable by every verifier from the value alone. Do NOT route this
    // through CreateCommitment(), which rejects a null blinding factor.
    const ed25519::PedersenCommitment C =
        ed25519::PedersenCommitment::CommitAmount(static_cast<uint64_t>(amount),
                                                  ed25519::Scalar::Zero());
    EncodeCommitment(C.commitment, commitment);
    return commitment.IsValid();
}

bool VerifyCommitmentBalance(
    const std::vector<CPedersenCommitment>& inputCommitments,
    const std::vector<CPedersenCommitment>& outputCommitments,
    const CPedersenCommitment* feeCommitment)
{
    // Everything is in one group now, so this is a genuine conservation check:
    //   sum(inputs) == sum(outputs) + fee
    // Under C = v*H + r*G this holds exactly when the values balance AND the
    // blindings balance, which is what the sender arranges when building the tx.
    if (inputCommitments.empty() || outputCommitments.empty()) return false;

    ed25519::Point lhs = ed25519::Point::Identity();
    for (const auto& c : inputCommitments) {
        ed25519::Point p;
        if (!DecodeCommitment(c, p)) return false;
        lhs = lhs + p;
    }

    ed25519::Point rhs = ed25519::Point::Identity();
    for (const auto& c : outputCommitments) {
        ed25519::Point p;
        if (!DecodeCommitment(c, p)) return false;
        rhs = rhs + p;
    }

    if (feeCommitment != nullptr) {
        ed25519::Point f;
        if (!DecodeCommitment(*feeCommitment, f)) return false;
        rhs = rhs + f;
    }

    return lhs.GetBytes() == rhs.GetBytes();
}

bool VerifyPoolBalance(
    const std::vector<CPedersenCommitment>& inputCommitments,
    const std::vector<CPedersenCommitment>& outputCommitments,
    CAmount delta)
{
    // Unlike VerifyCommitmentBalance, EITHER side may legitimately be empty: a pure
    // shield has no shielded inputs (delta > 0 funds the outputs), and a full
    // unshield has no shielded outputs (delta < 0 pays the value out). Requiring
    // both would make those two shapes inexpressible.
    if (inputCommitments.empty() && outputCommitments.empty()) return false;

    ed25519::Point lhs = ed25519::Point::Identity();
    for (const auto& c : inputCommitments) {
        ed25519::Point p;
        if (!DecodeCommitment(c, p)) return false;
        lhs = lhs + p;
    }

    ed25519::Point rhs = ed25519::Point::Identity();
    for (const auto& c : outputCommitments) {
        ed25519::Point p;
        if (!DecodeCommitment(c, p)) return false;
        rhs = rhs + p;
    }

    // delta*H, with zero blinding because delta is public.
    //
    // The sign is handled by choosing WHICH SIDE the term lands on, never by
    // negating into a scalar: scalars here are residues mod the group order, so a
    // negative CAmount cast into one would silently become an enormous positive
    // value and the equation would balance against a number nobody intended.
    // CreatePublicValueCommitment likewise rejects a negative amount outright.
    if (delta != 0) {
        const CAmount magnitude = (delta > 0) ? delta : -delta;

        // Guard the negation itself: -CAmount_MIN is undefined behaviour, and a
        // delta of that magnitude is not a real transaction in any case.
        if (magnitude < 0) return false;

        CPedersenCommitment deltaCommitment;
        if (!CreatePublicValueCommitment(magnitude, deltaCommitment)) return false;

        ed25519::Point d;
        if (!DecodeCommitment(deltaCommitment, d)) return false;

        if (delta > 0) {
            lhs = lhs + d;   // value entered the pool: it funds the outputs
        } else {
            rhs = rhs + d;   // value left the pool: the inputs paid for it
        }
    }

    return lhs.GetBytes() == rhs.GetBytes();
}

bool CreateRangeProof(
    CAmount amount,
    const CBlindingFactor& blindingFactor,
    const CPedersenCommitment& commitment,
    CRangeProof& rangeProof)
{
    std::vector<CPedersenCommitment> one{commitment};
    std::vector<CAmount> amounts{amount};
    std::vector<CBlindingFactor> blinds{blindingFactor};
    return CreateAggregatedRangeProof(amounts, blinds, one, rangeProof);
}

bool VerifyRangeProof(
    const CPedersenCommitment& commitment,
    const CRangeProof& rangeProof)
{
    std::vector<CPedersenCommitment> one{commitment};
    return VerifyAggregatedRangeProof(one, rangeProof);
}

bool CreateAggregatedRangeProof(
    const std::vector<CAmount>& amounts,
    const std::vector<CBlindingFactor>& blindingFactors,
    const std::vector<CPedersenCommitment>& commitments,
    CRangeProof& rangeProof)
{
    const size_t n = amounts.size();
    if (n == 0) return false;
    if (blindingFactors.size() != n || commitments.size() != n) return false;

    std::vector<uint64_t> vals(n);
    std::vector<std::array<uint8_t, 32>> blinds(n);
    for (size_t i = 0; i < n; ++i) {
        if (amounts[i] < 0) return false;
        if (!blindingFactors[i].IsValid()) return false;
        vals[i] = static_cast<uint64_t>(amounts[i]);

        // Must match CreateCommitment's reduction exactly, or the produced proof
        // will not verify against the commitment it is supposed to cover.
        const std::vector<uint8_t> rb = BlindingToScalar(blindingFactors[i]).GetBytes();
        if (rb.size() != 32) return false;
        std::memcpy(blinds[i].data(), rb.data(), 32);
    }

    std::vector<uint8_t> buf(MAX_PROOF_BYTES);
    size_t proof_len = 0;
    const int rc = wattx_bpplus::prove(
        vals.data(),
        reinterpret_cast<const uint8_t (*)[32]>(blinds.data()),
        n,
        buf.data(), buf.size(), &proof_len);
    if (rc != 0 || proof_len == 0 || proof_len > buf.size()) return false;

    rangeProof.data.clear();
    rangeProof.data.reserve(proof_len + 1);
    rangeProof.data.push_back(RANGEPROOF_VERSION_BPPLUS);
    rangeProof.data.insert(rangeProof.data.end(), buf.begin(), buf.begin() + proof_len);

    // Never hand back a proof we cannot ourselves verify against the very
    // commitments it was asked to cover.
    return VerifyAggregatedRangeProof(commitments, rangeProof);
}

bool VerifyAggregatedRangeProof(
    const std::vector<CPedersenCommitment>& commitments,
    const CRangeProof& rangeProof)
{
    if (commitments.empty()) return false;

    // Fail closed on anything that is not an explicitly tagged BP+ proof. This
    // is what rejects the historical 33-byte 0xFF placeholder and any leftover
    // legacy 0x01 blob -- neither can be treated as evidence of range.
    if (rangeProof.data.size() < 2) return false;
    if (rangeProof.data[0] != RANGEPROOF_VERSION_BPPLUS) return false;

    std::vector<uint8_t> flat;
    if (!FlattenCommitments(commitments, flat)) return false;

    return wattx_bpplus::verify(
        flat.data(), commitments.size(),
        rangeProof.data.data() + 1, rangeProof.data.size() - 1);
}

} // namespace privacy
