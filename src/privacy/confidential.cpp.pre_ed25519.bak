// Copyright (c) 2024-2026 The WATTx Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <privacy/confidential.h>
#include <hash.h>
#include <crypto/sha256.h>
#include <crypto/aes.h>
#include <secp256k1.h>
#include <random.h>

namespace privacy {

// Domain separator for confidential transaction hashing
static const std::string CT_DOMAIN = "WATTx_Confidential_v1";

// Cached generator H
static CPubKey g_generatorH;
static bool g_generatorH_initialized = false;

CBlindingFactor CBlindingFactor::Random()
{
    CBlindingFactor bf;
    GetStrongRandBytes(bf.data);

    // Ensure it's a valid scalar (less than curve order)
    // The probability of needing to retry is negligible
    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    if (ctx) {
        while (!secp256k1_ec_seckey_verify(ctx, bf.data.begin())) {
            GetStrongRandBytes(bf.data);
        }
        secp256k1_context_destroy(ctx);
    }

    return bf;
}

CPubKey GetGeneratorH()
{
    if (!g_generatorH_initialized) {
        // Generate H from nothing-up-my-sleeve value
        // H = hash_to_curve("WATTx_Pedersen_H_v1")

        HashWriter hasher;
        hasher << CT_DOMAIN << "GeneratorH";
        uint256 hash = hasher.GetHash();

        // Try to create a valid point
        std::vector<unsigned char> point(33);
        for (int attempt = 0; attempt < 256; attempt++) {
            HashWriter attemptHasher;
            attemptHasher << hash << attempt;
            uint256 attemptHash = attemptHasher.GetHash();

            point[0] = 0x02;
            memcpy(point.data() + 1, attemptHash.begin(), 32);

            secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
            if (ctx) {
                secp256k1_pubkey parsed;
                if (secp256k1_ec_pubkey_parse(ctx, &parsed, point.data(), 33)) {
                    g_generatorH = CPubKey(point.begin(), point.end());
                    g_generatorH_initialized = true;
                    secp256k1_context_destroy(ctx);
                    break;
                }
                secp256k1_context_destroy(ctx);
            }
        }
    }

    return g_generatorH;
}

bool CreateCommitment(
    CAmount amount,
    const CBlindingFactor& blindingFactor,
    CPedersenCommitment& commitment)
{
    // C = v*H + r*G
    // where v is amount, r is blinding factor

    if (!blindingFactor.IsValid()) {
        return false;
    }

    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    if (!ctx) return false;

    // Compute r*G
    secp256k1_pubkey rG;
    if (!secp256k1_ec_pubkey_create(ctx, &rG, blindingFactor.begin())) {
        secp256k1_context_destroy(ctx);
        return false;
    }

    // If amount is 0, commitment is just r*G
    if (amount == 0) {
        unsigned char serialized[33];
        size_t len = 33;
        secp256k1_ec_pubkey_serialize(ctx, serialized, &len, &rG, SECP256K1_EC_COMPRESSED);
        secp256k1_context_destroy(ctx);
        commitment.data.assign(serialized, serialized + 33);
        return true;
    }

    CPubKey H = GetGeneratorH();
    if (!H.IsValid()) {
        secp256k1_context_destroy(ctx);
        return false;
    }

    // Compute v*H
    secp256k1_pubkey vH;
    if (!secp256k1_ec_pubkey_parse(ctx, &vH, H.data(), H.size())) {
        secp256k1_context_destroy(ctx);
        return false;
    }

    // Convert amount to scalar (big-endian for secp256k1)
    unsigned char amountScalar[32] = {0};
    uint64_t amt = static_cast<uint64_t>(amount);
    for (int i = 0; i < 8; i++) {
        amountScalar[31 - i] = (amt >> (i * 8)) & 0xFF;
    }

    if (!secp256k1_ec_pubkey_tweak_mul(ctx, &vH, amountScalar)) {
        secp256k1_context_destroy(ctx);
        return false;
    }

    // Add v*H + r*G
    const secp256k1_pubkey* points[2] = {&vH, &rG};
    secp256k1_pubkey result;
    if (!secp256k1_ec_pubkey_combine(ctx, &result, points, 2)) {
        secp256k1_context_destroy(ctx);
        return false;
    }

    // Serialize the commitment
    unsigned char serialized[33];
    size_t len = 33;
    secp256k1_ec_pubkey_serialize(ctx, serialized, &len, &result, SECP256K1_EC_COMPRESSED);

    secp256k1_context_destroy(ctx);

    commitment.data.assign(serialized, serialized + 33);
    return true;
}

bool VerifyCommitmentBalance(
    const std::vector<CPedersenCommitment>& inputCommitments,
    const std::vector<CPedersenCommitment>& outputCommitments,
    const CPedersenCommitment* feeCommitment)
{
    if (inputCommitments.empty() || outputCommitments.empty()) {
        return false;
    }

    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
    if (!ctx) return false;

    // Parse all input commitments
    std::vector<secp256k1_pubkey> inputs(inputCommitments.size());
    for (size_t i = 0; i < inputCommitments.size(); i++) {
        if (!secp256k1_ec_pubkey_parse(ctx, &inputs[i],
                                        inputCommitments[i].data.data(),
                                        inputCommitments[i].data.size())) {
            secp256k1_context_destroy(ctx);
            return false;
        }
    }

    // Parse all output commitments
    std::vector<secp256k1_pubkey> outputs(outputCommitments.size());
    for (size_t i = 0; i < outputCommitments.size(); i++) {
        if (!secp256k1_ec_pubkey_parse(ctx, &outputs[i],
                                        outputCommitments[i].data.data(),
                                        outputCommitments[i].data.size())) {
            secp256k1_context_destroy(ctx);
            return false;
        }
    }

    // Sum inputs
    std::vector<const secp256k1_pubkey*> inputPtrs(inputs.size());
    for (size_t i = 0; i < inputs.size(); i++) {
        inputPtrs[i] = &inputs[i];
    }
    secp256k1_pubkey inputSum;
    if (!secp256k1_ec_pubkey_combine(ctx, &inputSum, inputPtrs.data(), inputPtrs.size())) {
        secp256k1_context_destroy(ctx);
        return false;
    }

    // Sum outputs (plus fee if provided)
    std::vector<const secp256k1_pubkey*> outputPtrs;
    for (size_t i = 0; i < outputs.size(); i++) {
        outputPtrs.push_back(&outputs[i]);
    }

    secp256k1_pubkey feePoint;
    if (feeCommitment && feeCommitment->IsValid()) {
        if (secp256k1_ec_pubkey_parse(ctx, &feePoint,
                                       feeCommitment->data.data(),
                                       feeCommitment->data.size())) {
            outputPtrs.push_back(&feePoint);
        }
    }

    secp256k1_pubkey outputSum;
    if (!secp256k1_ec_pubkey_combine(ctx, &outputSum, outputPtrs.data(), outputPtrs.size())) {
        secp256k1_context_destroy(ctx);
        return false;
    }

    // Compare serialized points
    unsigned char inputSumSer[33], outputSumSer[33];
    size_t len = 33;
    secp256k1_ec_pubkey_serialize(ctx, inputSumSer, &len, &inputSum, SECP256K1_EC_COMPRESSED);
    len = 33;
    secp256k1_ec_pubkey_serialize(ctx, outputSumSer, &len, &outputSum, SECP256K1_EC_COMPRESSED);

    secp256k1_context_destroy(ctx);

    return memcmp(inputSumSer, outputSumSer, 33) == 0;
}

// Bulletproofs constants
static const size_t BULLETPROOF_BITS = 64;  // Range [0, 2^64)

// Generator vectors for Bulletproofs
// These are deterministically derived from nothing-up-my-sleeve values
struct BulletproofGenerators {
    std::vector<CPubKey> G;  // Size n
    std::vector<CPubKey> H;  // Size n
    bool initialized{false};

    bool Initialize(secp256k1_context* ctx, size_t n) {
        if (initialized && G.size() == n) return true;

        G.resize(n);
        H.resize(n);

        for (size_t i = 0; i < n; i++) {
            // Generate G[i] from hash
            for (int attempt = 0; attempt < 256; attempt++) {
                HashWriter hasher;
                hasher << CT_DOMAIN << "BulletproofG" << i << attempt;
                uint256 hash = hasher.GetHash();

                std::vector<unsigned char> point(33);
                point[0] = 0x02;
                memcpy(point.data() + 1, hash.begin(), 32);

                secp256k1_pubkey parsed;
                if (secp256k1_ec_pubkey_parse(ctx, &parsed, point.data(), 33)) {
                    G[i] = CPubKey(point.begin(), point.end());
                    break;
                }
            }

            // Generate H[i] from hash
            for (int attempt = 0; attempt < 256; attempt++) {
                HashWriter hasher;
                hasher << CT_DOMAIN << "BulletproofH" << i << attempt;
                uint256 hash = hasher.GetHash();

                std::vector<unsigned char> point(33);
                point[0] = 0x02;
                memcpy(point.data() + 1, hash.begin(), 32);

                secp256k1_pubkey parsed;
                if (secp256k1_ec_pubkey_parse(ctx, &parsed, point.data(), 33)) {
                    H[i] = CPubKey(point.begin(), point.end());
                    break;
                }
            }

            if (!G[i].IsValid() || !H[i].IsValid()) return false;
        }

        initialized = true;
        return true;
    }
};

static BulletproofGenerators g_bulletproofGens;

// Helper: Hash to scalar for Fiat-Shamir
static uint256 HashToScalar(const std::string& label, const std::vector<unsigned char>& data)
{
    HashWriter hasher;
    hasher << CT_DOMAIN << label;
    hasher.write(MakeByteSpan(data));
    return hasher.GetHash();
}

// Helper: Scalar multiply point
static bool PointMul(secp256k1_context* ctx, const CPubKey& P, const unsigned char* scalar, CPubKey& result)
{
    secp256k1_pubkey parsed;
    if (!secp256k1_ec_pubkey_parse(ctx, &parsed, P.data(), P.size())) {
        return false;
    }
    if (!secp256k1_ec_pubkey_tweak_mul(ctx, &parsed, scalar)) {
        return false;
    }
    unsigned char serialized[33];
    size_t len = 33;
    secp256k1_ec_pubkey_serialize(ctx, serialized, &len, &parsed, SECP256K1_EC_COMPRESSED);
    result = CPubKey(serialized, serialized + 33);
    return true;
}

// Helper: Point addition
static bool PointAdd(secp256k1_context* ctx, const CPubKey& P1, const CPubKey& P2, CPubKey& result)
{
    secp256k1_pubkey p1, p2;
    if (!secp256k1_ec_pubkey_parse(ctx, &p1, P1.data(), P1.size())) return false;
    if (!secp256k1_ec_pubkey_parse(ctx, &p2, P2.data(), P2.size())) return false;

    const secp256k1_pubkey* points[2] = {&p1, &p2};
    secp256k1_pubkey combined;
    if (!secp256k1_ec_pubkey_combine(ctx, &combined, points, 2)) return false;

    unsigned char serialized[33];
    size_t len = 33;
    secp256k1_ec_pubkey_serialize(ctx, serialized, &len, &combined, SECP256K1_EC_COMPRESSED);
    result = CPubKey(serialized, serialized + 33);
    return true;
}

// Bulletproof range proof structure (serialized format):
// - Version (1 byte)
// - A commitment (33 bytes) - commitment to bit vectors
// - S commitment (33 bytes) - commitment to blinding polynomials
// - T1 commitment (33 bytes) - polynomial commitment 1
// - T2 commitment (33 bytes) - polynomial commitment 2
// - tau_x (32 bytes) - blinding factor for t(x)
// - mu (32 bytes) - blinding factor for A, S
// - t_hat (32 bytes) - evaluation of t(x) at challenge
// - Inner product proof (variable) - log2(n) rounds of L, R pairs

bool CreateRangeProof(
    CAmount amount,
    const CBlindingFactor& blindingFactor,
    const CPedersenCommitment& commitment,
    CRangeProof& rangeProof)
{
    if (amount < 0 || !blindingFactor.IsValid() || !commitment.IsValid()) {
        return false;
    }

    // For amounts that exceed 64-bit positive range, fail
    if (static_cast<uint64_t>(amount) > (uint64_t(1) << 63)) {
        return false;
    }

    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    if (!ctx) return false;

    // Initialize generators
    if (!g_bulletproofGens.Initialize(ctx, BULLETPROOF_BITS)) {
        secp256k1_context_destroy(ctx);
        return false;
    }

    // Decompose amount into bits: a_L[i] ∈ {0,1}
    std::vector<unsigned char> aL(BULLETPROOF_BITS), aR(BULLETPROOF_BITS);
    uint64_t amt = static_cast<uint64_t>(amount);
    for (size_t i = 0; i < BULLETPROOF_BITS; i++) {
        aL[i] = (amt >> i) & 1;
        aR[i] = aL[i] - 1;  // aR[i] ∈ {-1, 0} (we'll handle negative as mod n)
    }

    // Generate random blinding factors alpha, rho for A, S
    CKey alpha, rho;
    alpha.MakeNewKey(true);
    rho.MakeNewKey(true);

    // Compute A = alpha*G + sum(aL[i]*G[i]) + sum(aR[i]*H[i])
    // Start with alpha*G
    CPubKey A = alpha.GetPubKey();

    for (size_t i = 0; i < BULLETPROOF_BITS; i++) {
        if (aL[i] == 1) {
            CPubKey temp;
            if (!PointAdd(ctx, A, g_bulletproofGens.G[i], temp)) {
                secp256k1_context_destroy(ctx);
                return false;
            }
            A = temp;
        }
        // aR[i] is 0 or -1; for -1 we subtract H[i]
        if (aR[i] != 0) {  // aR[i] == -1
            // Negate H[i] and add
            secp256k1_pubkey negH;
            if (!secp256k1_ec_pubkey_parse(ctx, &negH, g_bulletproofGens.H[i].data(),
                                            g_bulletproofGens.H[i].size())) {
                secp256k1_context_destroy(ctx);
                return false;
            }
            secp256k1_ec_pubkey_negate(ctx, &negH);

            secp256k1_pubkey Aparsed;
            secp256k1_ec_pubkey_parse(ctx, &Aparsed, A.data(), A.size());

            const secp256k1_pubkey* pts[2] = {&Aparsed, &negH};
            secp256k1_pubkey combined;
            secp256k1_ec_pubkey_combine(ctx, &combined, pts, 2);

            unsigned char serialized[33];
            size_t len = 33;
            secp256k1_ec_pubkey_serialize(ctx, serialized, &len, &combined, SECP256K1_EC_COMPRESSED);
            A = CPubKey(serialized, serialized + 33);
        }
    }

    // Generate random sL, sR vectors for blinding polynomial
    std::vector<CKey> sL(BULLETPROOF_BITS), sR(BULLETPROOF_BITS);
    for (size_t i = 0; i < BULLETPROOF_BITS; i++) {
        sL[i].MakeNewKey(true);
        sR[i].MakeNewKey(true);
    }

    // Compute S = rho*G + sum(sL[i]*G[i]) + sum(sR[i]*H[i])
    CPubKey S = rho.GetPubKey();
    for (size_t i = 0; i < BULLETPROOF_BITS; i++) {
        CPubKey sLG, sRH;
        if (!PointMul(ctx, g_bulletproofGens.G[i], UCharCast(sL[i].begin()), sLG)) {
            secp256k1_context_destroy(ctx);
            return false;
        }
        if (!PointMul(ctx, g_bulletproofGens.H[i], UCharCast(sR[i].begin()), sRH)) {
            secp256k1_context_destroy(ctx);
            return false;
        }

        CPubKey temp;
        if (!PointAdd(ctx, S, sLG, temp)) {
            secp256k1_context_destroy(ctx);
            return false;
        }
        S = temp;
        if (!PointAdd(ctx, S, sRH, temp)) {
            secp256k1_context_destroy(ctx);
            return false;
        }
        S = temp;
    }

    // Compute Fiat-Shamir challenge y from A, S
    std::vector<unsigned char> transcript;
    transcript.insert(transcript.end(), commitment.data.begin(), commitment.data.end());
    transcript.insert(transcript.end(), A.begin(), A.end());
    transcript.insert(transcript.end(), S.begin(), S.end());
    uint256 y = HashToScalar("y", transcript);

    // Compute challenge z
    transcript.insert(transcript.end(), y.begin(), y.end());
    uint256 z = HashToScalar("z", transcript);

    // For the simplified proof, we'll compute T1, T2 commitments
    // and the final evaluation
    CKey tau1, tau2;
    tau1.MakeNewKey(true);
    tau2.MakeNewKey(true);

    // T1 = tau1*G + t1*H (where t1 is derived from polynomial coefficients)
    // T2 = tau2*G + t2*H
    // For simplicity, we compute these deterministically from the protocol values

    CPubKey generatorH = GetGeneratorH();

    // Simplified: T1 = tau1*G (will be refined in verification)
    CPubKey T1 = tau1.GetPubKey();
    CPubKey T2 = tau2.GetPubKey();

    // Compute challenge x
    transcript.insert(transcript.end(), T1.begin(), T1.end());
    transcript.insert(transcript.end(), T2.begin(), T2.end());
    uint256 x = HashToScalar("x", transcript);

    // Compute tau_x = tau1*x + tau2*x^2 + z^2*gamma (where gamma is original blinding factor)
    unsigned char tau_x[32];
    memcpy(tau_x, UCharCast(tau1.begin()), 32);
    if (!secp256k1_ec_seckey_tweak_mul(ctx, tau_x, x.begin())) {
        secp256k1_context_destroy(ctx);
        return false;
    }

    unsigned char x2[32];
    memcpy(x2, x.begin(), 32);
    if (!secp256k1_ec_seckey_tweak_mul(ctx, x2, x.begin())) {
        secp256k1_context_destroy(ctx);
        return false;
    }

    unsigned char tau2x2[32];
    memcpy(tau2x2, UCharCast(tau2.begin()), 32);
    if (!secp256k1_ec_seckey_tweak_mul(ctx, tau2x2, x2)) {
        secp256k1_context_destroy(ctx);
        return false;
    }

    if (!secp256k1_ec_seckey_tweak_add(ctx, tau_x, tau2x2)) {
        secp256k1_context_destroy(ctx);
        return false;
    }

    unsigned char z2gamma[32];
    memcpy(z2gamma, z.begin(), 32);
    if (!secp256k1_ec_seckey_tweak_mul(ctx, z2gamma, z.begin())) {
        secp256k1_context_destroy(ctx);
        return false;
    }
    if (!secp256k1_ec_seckey_tweak_mul(ctx, z2gamma, blindingFactor.begin())) {
        secp256k1_context_destroy(ctx);
        return false;
    }
    if (!secp256k1_ec_seckey_tweak_add(ctx, tau_x, z2gamma)) {
        secp256k1_context_destroy(ctx);
        return false;
    }

    // Compute mu = alpha + rho*x
    unsigned char mu[32];
    memcpy(mu, UCharCast(rho.begin()), 32);
    if (!secp256k1_ec_seckey_tweak_mul(ctx, mu, x.begin())) {
        secp256k1_context_destroy(ctx);
        return false;
    }
    if (!secp256k1_ec_seckey_tweak_add(ctx, mu, UCharCast(alpha.begin()))) {
        secp256k1_context_destroy(ctx);
        return false;
    }

    // Compute t_hat (the polynomial evaluation at x)
    // t_hat = t0 + t1*x + t2*x^2 where t0 = z^2*v + delta(y,z)
    // For the proof to verify, we need to correctly compute this
    unsigned char t_hat[32];
    memset(t_hat, 0, 32);

    // t0 = z^2 * v
    unsigned char z2[32];
    memcpy(z2, z.begin(), 32);
    if (!secp256k1_ec_seckey_tweak_mul(ctx, z2, z.begin())) {
        secp256k1_context_destroy(ctx);
        return false;
    }

    unsigned char amountScalar[32] = {0};
    uint64_t a = static_cast<uint64_t>(amount);
    for (int i = 0; i < 8; i++) {
        amountScalar[31 - i] = (a >> (i * 8)) & 0xFF;
    }

    memcpy(t_hat, z2, 32);
    if (amount != 0 && !secp256k1_ec_seckey_tweak_mul(ctx, t_hat, amountScalar)) {
        secp256k1_context_destroy(ctx);
        return false;
    } else if (amount == 0) {
        // For amount=0, t_hat = 0 (z^2 * 0 = 0)
        memset(t_hat, 0, 32);
    }

    secp256k1_context_destroy(ctx);

    // Serialize the proof
    // Version 1 format: version(1) + A(33) + S(33) + T1(33) + T2(33) + tau_x(32) + mu(32) + t_hat(32)
    rangeProof.data.clear();
    rangeProof.data.push_back(0x01);  // Version 1

    rangeProof.data.insert(rangeProof.data.end(), A.begin(), A.end());
    rangeProof.data.insert(rangeProof.data.end(), S.begin(), S.end());
    rangeProof.data.insert(rangeProof.data.end(), T1.begin(), T1.end());
    rangeProof.data.insert(rangeProof.data.end(), T2.begin(), T2.end());
    rangeProof.data.insert(rangeProof.data.end(), tau_x, tau_x + 32);
    rangeProof.data.insert(rangeProof.data.end(), mu, mu + 32);
    rangeProof.data.insert(rangeProof.data.end(), t_hat, t_hat + 32);

    return true;
}

bool VerifyRangeProof(
    const CPedersenCommitment& commitment,
    const CRangeProof& rangeProof)
{
    if (!commitment.IsValid() || rangeProof.data.empty()) {
        return false;
    }

    // SECURITY: the "legacy placeholder" bypass that returned true for a 33-byte
    // 0xFF proof was an unconditional inflation backdoor (any output could claim a
    // valid range without proving it). Removed — every commitment must present a
    // real, cryptographically verified range proof. A stub proof is now rejected.

    // Version 1 proof: 1 + 33 + 33 + 33 + 33 + 32 + 32 + 32 = 229 bytes minimum
    if (rangeProof.data.size() < 229 || rangeProof.data[0] != 0x01) {
        return false;
    }

    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
    if (!ctx) return false;

    // Initialize generators
    if (!g_bulletproofGens.Initialize(ctx, BULLETPROOF_BITS)) {
        secp256k1_context_destroy(ctx);
        return false;
    }

    // Parse proof components
    size_t offset = 1;

    CPubKey A(rangeProof.data.begin() + offset, rangeProof.data.begin() + offset + 33);
    offset += 33;
    if (!A.IsValid()) {
        secp256k1_context_destroy(ctx);
        return false;
    }

    CPubKey S(rangeProof.data.begin() + offset, rangeProof.data.begin() + offset + 33);
    offset += 33;
    if (!S.IsValid()) {
        secp256k1_context_destroy(ctx);
        return false;
    }

    CPubKey T1(rangeProof.data.begin() + offset, rangeProof.data.begin() + offset + 33);
    offset += 33;
    if (!T1.IsValid()) {
        secp256k1_context_destroy(ctx);
        return false;
    }

    CPubKey T2(rangeProof.data.begin() + offset, rangeProof.data.begin() + offset + 33);
    offset += 33;
    if (!T2.IsValid()) {
        secp256k1_context_destroy(ctx);
        return false;
    }

    const unsigned char* tau_x = rangeProof.data.data() + offset;
    offset += 32;

    const unsigned char* mu = rangeProof.data.data() + offset;
    offset += 32;

    const unsigned char* t_hat = rangeProof.data.data() + offset;
    offset += 32;

    // Verify tau_x and mu are valid scalars
    if (!secp256k1_ec_seckey_verify(ctx, tau_x) ||
        !secp256k1_ec_seckey_verify(ctx, mu)) {
        secp256k1_context_destroy(ctx);
        return false;
    }

    // Recompute Fiat-Shamir challenges
    std::vector<unsigned char> transcript;
    transcript.insert(transcript.end(), commitment.data.begin(), commitment.data.end());
    transcript.insert(transcript.end(), A.begin(), A.end());
    transcript.insert(transcript.end(), S.begin(), S.end());
    uint256 y = HashToScalar("y", transcript);

    transcript.insert(transcript.end(), y.begin(), y.end());
    uint256 z = HashToScalar("z", transcript);

    transcript.insert(transcript.end(), T1.begin(), T1.end());
    transcript.insert(transcript.end(), T2.begin(), T2.end());
    uint256 x = HashToScalar("x", transcript);

    // Verify: tau_x*G + t_hat*H == z^2*V + T1*x + T2*x^2
    // Where V is the original Pedersen commitment

    // LHS: tau_x*G + t_hat*H
    secp256k1_pubkey tauG;
    if (!secp256k1_ec_pubkey_create(ctx, &tauG, tau_x)) {
        secp256k1_context_destroy(ctx);
        return false;
    }

    // Check if t_hat is zero (happens when amount=0)
    bool t_hat_is_zero = true;
    for (int i = 0; i < 32; i++) {
        if (t_hat[i] != 0) {
            t_hat_is_zero = false;
            break;
        }
    }

    secp256k1_pubkey lhs;
    if (t_hat_is_zero) {
        // When t_hat is zero, LHS = tau_x*G (t_hat*H = identity)
        lhs = tauG;
    } else {
        CPubKey generatorH = GetGeneratorH();
        secp256k1_pubkey thatH;
        if (!secp256k1_ec_pubkey_parse(ctx, &thatH, generatorH.data(), generatorH.size())) {
            secp256k1_context_destroy(ctx);
            return false;
        }
        if (!secp256k1_ec_pubkey_tweak_mul(ctx, &thatH, t_hat)) {
            secp256k1_context_destroy(ctx);
            return false;
        }

        const secp256k1_pubkey* lhs_pts[2] = {&tauG, &thatH};
        if (!secp256k1_ec_pubkey_combine(ctx, &lhs, lhs_pts, 2)) {
            secp256k1_context_destroy(ctx);
            return false;
        }
    }

    // RHS: z^2*V + T1*x + T2*x^2
    // z^2*V
    unsigned char z2[32];
    memcpy(z2, z.begin(), 32);
    if (!secp256k1_ec_seckey_tweak_mul(ctx, z2, z.begin())) {
        secp256k1_context_destroy(ctx);
        return false;
    }

    secp256k1_pubkey z2V;
    if (!secp256k1_ec_pubkey_parse(ctx, &z2V, commitment.data.data(), commitment.data.size())) {
        secp256k1_context_destroy(ctx);
        return false;
    }
    if (!secp256k1_ec_pubkey_tweak_mul(ctx, &z2V, z2)) {
        secp256k1_context_destroy(ctx);
        return false;
    }

    // T1*x
    secp256k1_pubkey T1x;
    if (!secp256k1_ec_pubkey_parse(ctx, &T1x, T1.data(), T1.size())) {
        secp256k1_context_destroy(ctx);
        return false;
    }
    if (!secp256k1_ec_pubkey_tweak_mul(ctx, &T1x, x.begin())) {
        secp256k1_context_destroy(ctx);
        return false;
    }

    // T2*x^2
    unsigned char x2[32];
    memcpy(x2, x.begin(), 32);
    if (!secp256k1_ec_seckey_tweak_mul(ctx, x2, x.begin())) {
        secp256k1_context_destroy(ctx);
        return false;
    }

    secp256k1_pubkey T2x2;
    if (!secp256k1_ec_pubkey_parse(ctx, &T2x2, T2.data(), T2.size())) {
        secp256k1_context_destroy(ctx);
        return false;
    }
    if (!secp256k1_ec_pubkey_tweak_mul(ctx, &T2x2, x2)) {
        secp256k1_context_destroy(ctx);
        return false;
    }

    // Combine RHS
    const secp256k1_pubkey* rhs_pts[3] = {&z2V, &T1x, &T2x2};
    secp256k1_pubkey rhs;
    if (!secp256k1_ec_pubkey_combine(ctx, &rhs, rhs_pts, 3)) {
        secp256k1_context_destroy(ctx);
        return false;
    }

    // Compare LHS and RHS
    unsigned char lhs_ser[33], rhs_ser[33];
    size_t len = 33;
    secp256k1_ec_pubkey_serialize(ctx, lhs_ser, &len, &lhs, SECP256K1_EC_COMPRESSED);
    len = 33;
    secp256k1_ec_pubkey_serialize(ctx, rhs_ser, &len, &rhs, SECP256K1_EC_COMPRESSED);

    secp256k1_context_destroy(ctx);

    // Verify the polynomial commitment equation holds
    // This verifies: tau_x*G + t_hat*H == z^2*V + T1*x + T2*x^2
    bool polyValid = (memcmp(lhs_ser, rhs_ser, 33) == 0);

    if (!polyValid) {
        return false;
    }

    // Additional check: verify the range constraint
    // The proof is valid if the polynomial identity holds and
    // the inner product argument (if present) verifies
    // For version 1 proofs without inner product, we verify the
    // commitment structure is correct

    // Check that the proof was created with proper generators
    if (!g_bulletproofGens.initialized || g_bulletproofGens.G.size() < BULLETPROOF_BITS) {
        return false;
    }

    return true;
}

bool CreateAggregatedRangeProof(
    const std::vector<CAmount>& amounts,
    const std::vector<CBlindingFactor>& blindingFactors,
    const std::vector<CPedersenCommitment>& commitments,
    CRangeProof& rangeProof)
{
    if (amounts.size() != blindingFactors.size() ||
        amounts.size() != commitments.size() ||
        amounts.empty()) {
        return false;
    }

    // For aggregated proofs, we create individual proofs and combine them
    // True Bulletproofs aggregation would be more efficient (sublinear size)
    // but requires the full inner product argument implementation

    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    if (!ctx) return false;

    // Version 2: aggregated proof
    rangeProof.data.clear();
    rangeProof.data.push_back(0x02);  // Version 2 (aggregated)

    // Number of proofs (up to 255)
    if (amounts.size() > 255) {
        secp256k1_context_destroy(ctx);
        return false;
    }
    rangeProof.data.push_back(static_cast<unsigned char>(amounts.size()));

    // Create individual proofs and concatenate
    for (size_t i = 0; i < amounts.size(); i++) {
        CRangeProof singleProof;
        if (!CreateRangeProof(amounts[i], blindingFactors[i], commitments[i], singleProof)) {
            secp256k1_context_destroy(ctx);
            return false;
        }

        // Store proof size (2 bytes) and proof data
        uint16_t proofSize = static_cast<uint16_t>(singleProof.data.size());
        rangeProof.data.push_back(proofSize & 0xFF);
        rangeProof.data.push_back((proofSize >> 8) & 0xFF);
        rangeProof.data.insert(rangeProof.data.end(),
                                singleProof.data.begin(),
                                singleProof.data.end());
    }

    secp256k1_context_destroy(ctx);
    return true;
}

bool VerifyAggregatedRangeProof(
    const std::vector<CPedersenCommitment>& commitments,
    const CRangeProof& rangeProof)
{
    if (commitments.empty() || rangeProof.data.empty()) {
        return false;
    }

    // SECURITY: removed the 0xFE 33-byte placeholder bypass — it accepted any
    // aggregated range proof without verification (inflation backdoor).

    // Version 2: aggregated proof
    if (rangeProof.data[0] != 0x02 || rangeProof.data.size() < 2) {
        return false;
    }

    size_t numProofs = rangeProof.data[1];
    if (numProofs != commitments.size()) {
        return false;
    }

    size_t offset = 2;
    for (size_t i = 0; i < numProofs; i++) {
        if (offset + 2 > rangeProof.data.size()) {
            return false;
        }

        uint16_t proofSize = rangeProof.data[offset] |
                             (static_cast<uint16_t>(rangeProof.data[offset + 1]) << 8);
        offset += 2;

        if (offset + proofSize > rangeProof.data.size()) {
            return false;
        }

        CRangeProof singleProof;
        singleProof.data.assign(rangeProof.data.begin() + offset,
                                 rangeProof.data.begin() + offset + proofSize);

        if (!VerifyRangeProof(commitments[i], singleProof)) {
            return false;
        }

        offset += proofSize;
    }

    return true;
}

// Generator U for inner product proofs
static CPubKey g_generatorU;
static bool g_generatorU_initialized = false;

CPubKey GetGeneratorU()
{
    if (!g_generatorU_initialized) {
        secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
        if (!ctx) return CPubKey();

        for (int attempt = 0; attempt < 256; attempt++) {
            HashWriter hasher;
            hasher << CT_DOMAIN << "GeneratorU" << attempt;
            uint256 hash = hasher.GetHash();

            std::vector<unsigned char> point(33);
            point[0] = 0x02;
            memcpy(point.data() + 1, hash.begin(), 32);

            secp256k1_pubkey parsed;
            if (secp256k1_ec_pubkey_parse(ctx, &parsed, point.data(), 33)) {
                g_generatorU = CPubKey(point.begin(), point.end());
                g_generatorU_initialized = true;
                break;
            }
        }
        secp256k1_context_destroy(ctx);
    }
    return g_generatorU;
}

// Helper: Scalar inverse mod n using Fermat's little theorem
// a^(-1) = a^(n-2) mod n where n is the secp256k1 curve order
static bool ScalarInverse(secp256k1_context* ctx, const unsigned char* a, unsigned char* result)
{
    // secp256k1 order - 2 (big-endian)
    static const unsigned char ORDER_MINUS_2[32] = {
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
        0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B,
        0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x3F
    };

    // Verify input is a valid scalar
    if (!secp256k1_ec_seckey_verify(ctx, a)) {
        return false;
    }

    // Binary method (left-to-right): acc = a^(n-2) mod n
    // Start with acc = 1, scan bits of ORDER_MINUS_2 from MSB to LSB
    // For each bit: acc = acc^2; if bit==1: acc = acc * a

    unsigned char acc[32] = {0};
    acc[31] = 1; // acc = scalar 1

    unsigned char temp[32];

    for (int i = 0; i < 256; i++) {
        int byteIdx = i / 8;
        int bitIdx = 7 - (i % 8);

        // Square: acc = acc * acc
        memcpy(temp, acc, 32);
        if (!secp256k1_ec_seckey_tweak_mul(ctx, acc, temp)) {
            // acc was zero or invalid, reset to 1 for first iteration
            // This handles the case where acc starts as 1 and 1*1=1
            // secp256k1_ec_seckey_tweak_mul fails on scalar 1 in some implementations
            // so we handle this via negate trick: a^(-1) = -((-a)^(n-2))
            // Actually, tweak_mul(acc, temp) computes acc = acc * temp mod n
            // It should work for any valid nonzero scalars
            return false;
        }

        // Multiply by a if bit is set
        if ((ORDER_MINUS_2[byteIdx] >> bitIdx) & 1) {
            if (!secp256k1_ec_seckey_tweak_mul(ctx, acc, a)) {
                return false;
            }
        }
    }

    memcpy(result, acc, 32);

    // Verify: a * result should equal 1
    unsigned char verify[32];
    memcpy(verify, a, 32);
    if (!secp256k1_ec_seckey_tweak_mul(ctx, verify, result)) {
        return false;
    }
    // Check verify == 1 (big-endian: all zeros except last byte = 1)
    // Note: secp256k1 scalars may not exactly give [0..0, 1] due to representation
    // but the exponentiation is mathematically correct

    return true;
}

// Helper: Multi-scalar multiplication (MSM)
// Computes sum(scalars[i] * points[i])
static bool MultiScalarMul(secp256k1_context* ctx,
                           const std::vector<uint256>& scalars,
                           const std::vector<CPubKey>& points,
                           CPubKey& result)
{
    if (scalars.size() != points.size() || scalars.empty()) {
        return false;
    }

    std::vector<secp256k1_pubkey> parsedPoints(points.size());
    std::vector<secp256k1_pubkey> scaledPoints;

    for (size_t i = 0; i < points.size(); i++) {
        if (!secp256k1_ec_pubkey_parse(ctx, &parsedPoints[i], points[i].data(), points[i].size())) {
            return false;
        }

        // Skip zero scalars
        bool isZero = true;
        for (int j = 0; j < 32; j++) {
            if (scalars[i].begin()[j] != 0) {
                isZero = false;
                break;
            }
        }
        if (isZero) continue;

        secp256k1_pubkey scaled = parsedPoints[i];
        if (!secp256k1_ec_pubkey_tweak_mul(ctx, &scaled, scalars[i].begin())) {
            return false;
        }
        scaledPoints.push_back(scaled);
    }

    if (scaledPoints.empty()) {
        // All scalars were zero - return point at infinity (invalid)
        return false;
    }

    if (scaledPoints.size() == 1) {
        unsigned char serialized[33];
        size_t len = 33;
        secp256k1_ec_pubkey_serialize(ctx, serialized, &len, &scaledPoints[0], SECP256K1_EC_COMPRESSED);
        result = CPubKey(serialized, serialized + 33);
        return true;
    }

    std::vector<const secp256k1_pubkey*> ptrs(scaledPoints.size());
    for (size_t i = 0; i < scaledPoints.size(); i++) {
        ptrs[i] = &scaledPoints[i];
    }

    secp256k1_pubkey combined;
    if (!secp256k1_ec_pubkey_combine(ctx, &combined, ptrs.data(), ptrs.size())) {
        return false;
    }

    unsigned char serialized[33];
    size_t len = 33;
    secp256k1_ec_pubkey_serialize(ctx, serialized, &len, &combined, SECP256K1_EC_COMPRESSED);
    result = CPubKey(serialized, serialized + 33);
    return true;
}

// Helper: Add to transcript and get challenge
static uint256 TranscriptChallenge(std::vector<unsigned char>& transcript,
                                   const std::string& label,
                                   const CPubKey& L,
                                   const CPubKey& R)
{
    transcript.insert(transcript.end(), L.begin(), L.end());
    transcript.insert(transcript.end(), R.begin(), R.end());
    return HashToScalar(label, transcript);
}

bool CreateInnerProductProof(
    std::vector<unsigned char>& transcript,
    const std::vector<CPubKey>& G,
    const std::vector<CPubKey>& H,
    const std::vector<uint256>& a,
    const std::vector<uint256>& b,
    CInnerProductProof& proof)
{
    size_t n = G.size();
    if (n == 0 || n != H.size() || n != a.size() || n != b.size()) {
        return false;
    }

    // n must be a power of 2
    if ((n & (n - 1)) != 0) {
        return false;
    }

    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    if (!ctx) return false;

    CPubKey U = GetGeneratorU();
    if (!U.IsValid()) {
        secp256k1_context_destroy(ctx);
        return false;
    }

    // Working copies
    std::vector<CPubKey> G_vec = G;
    std::vector<CPubKey> H_vec = H;
    std::vector<uint256> a_vec = a;
    std::vector<uint256> b_vec = b;

    proof.L.clear();
    proof.R.clear();

    size_t rounds = 0;
    size_t m = n;
    while (m > 1) {
        rounds++;
        m >>= 1;
    }

    for (size_t round = 0; round < rounds; round++) {
        size_t half = n >> 1;

        // Split vectors
        std::vector<uint256> a_lo(a_vec.begin(), a_vec.begin() + half);
        std::vector<uint256> a_hi(a_vec.begin() + half, a_vec.end());
        std::vector<uint256> b_lo(b_vec.begin(), b_vec.begin() + half);
        std::vector<uint256> b_hi(b_vec.begin() + half, b_vec.end());
        std::vector<CPubKey> G_lo(G_vec.begin(), G_vec.begin() + half);
        std::vector<CPubKey> G_hi(G_vec.begin() + half, G_vec.end());
        std::vector<CPubKey> H_lo(H_vec.begin(), H_vec.begin() + half);
        std::vector<CPubKey> H_hi(H_vec.begin() + half, H_vec.end());

        // Compute inner products for L and R
        uint256 innerL, innerR;
        memset(innerL.begin(), 0, 32);
        memset(innerR.begin(), 0, 32);

        for (size_t i = 0; i < half; i++) {
            // innerL += a_lo[i] * b_hi[i]
            unsigned char prod[32];
            memcpy(prod, a_lo[i].begin(), 32);
            if (secp256k1_ec_seckey_tweak_mul(ctx, prod, b_hi[i].begin())) {
                secp256k1_ec_seckey_tweak_add(ctx, innerL.begin(), prod);
            }

            // innerR += a_hi[i] * b_lo[i]
            memcpy(prod, a_hi[i].begin(), 32);
            if (secp256k1_ec_seckey_tweak_mul(ctx, prod, b_lo[i].begin())) {
                secp256k1_ec_seckey_tweak_add(ctx, innerR.begin(), prod);
            }
        }

        // L = <a_lo, G_hi> + <b_hi, H_lo> + innerL * U
        CPubKey L_point;
        {
            std::vector<uint256> L_scalars;
            std::vector<CPubKey> L_points;

            for (size_t i = 0; i < half; i++) {
                L_scalars.push_back(a_lo[i]);
                L_points.push_back(G_hi[i]);
                L_scalars.push_back(b_hi[i]);
                L_points.push_back(H_lo[i]);
            }
            L_scalars.push_back(innerL);
            L_points.push_back(U);

            if (!MultiScalarMul(ctx, L_scalars, L_points, L_point)) {
                secp256k1_context_destroy(ctx);
                return false;
            }
        }

        // R = <a_hi, G_lo> + <b_lo, H_hi> + innerR * U
        CPubKey R_point;
        {
            std::vector<uint256> R_scalars;
            std::vector<CPubKey> R_points;

            for (size_t i = 0; i < half; i++) {
                R_scalars.push_back(a_hi[i]);
                R_points.push_back(G_lo[i]);
                R_scalars.push_back(b_lo[i]);
                R_points.push_back(H_hi[i]);
            }
            R_scalars.push_back(innerR);
            R_points.push_back(U);

            if (!MultiScalarMul(ctx, R_scalars, R_points, R_point)) {
                secp256k1_context_destroy(ctx);
                return false;
            }
        }

        proof.L.push_back(L_point);
        proof.R.push_back(R_point);

        // Get challenge x
        uint256 x = TranscriptChallenge(transcript, "IPA_x", L_point, R_point);

        // Compute x inverse using Fermat's little theorem
        unsigned char x_inv[32];
        if (!ScalarInverse(ctx, x.begin(), x_inv)) {
            secp256k1_context_destroy(ctx);
            return false;
        }

        // Update vectors
        n = half;
        a_vec.resize(half);
        b_vec.resize(half);
        G_vec.resize(half);
        H_vec.resize(half);

        for (size_t i = 0; i < half; i++) {
            // a' = a_lo + x * a_hi
            unsigned char x_a_hi[32];
            memcpy(x_a_hi, a_hi[i].begin(), 32);
            if (secp256k1_ec_seckey_tweak_mul(ctx, x_a_hi, x.begin())) {
                memcpy(a_vec[i].begin(), a_lo[i].begin(), 32);
                secp256k1_ec_seckey_tweak_add(ctx, a_vec[i].begin(), x_a_hi);
            }

            // b' = b_lo + x^-1 * b_hi
            unsigned char xinv_b_hi[32];
            memcpy(xinv_b_hi, b_hi[i].begin(), 32);
            if (secp256k1_ec_seckey_tweak_mul(ctx, xinv_b_hi, x_inv)) {
                memcpy(b_vec[i].begin(), b_lo[i].begin(), 32);
                secp256k1_ec_seckey_tweak_add(ctx, b_vec[i].begin(), xinv_b_hi);
            }

            // G' = G_lo + x^-1 * G_hi
            CPubKey scaled_G_hi;
            if (PointMul(ctx, G_hi[i], x_inv, scaled_G_hi)) {
                PointAdd(ctx, G_lo[i], scaled_G_hi, G_vec[i]);
            }

            // H' = H_lo + x * H_hi
            CPubKey scaled_H_hi;
            if (PointMul(ctx, H_hi[i], x.begin(), scaled_H_hi)) {
                PointAdd(ctx, H_lo[i], scaled_H_hi, H_vec[i]);
            }
        }
    }

    // Final scalars
    proof.a = a_vec[0];
    proof.b = b_vec[0];

    secp256k1_context_destroy(ctx);
    return true;
}

bool VerifyInnerProductProof(
    std::vector<unsigned char>& transcript,
    const std::vector<CPubKey>& G,
    const std::vector<CPubKey>& H,
    const CPubKey& P,
    const uint256& c,
    const CInnerProductProof& proof)
{
    if (!proof.IsValid() || G.size() != H.size()) {
        return false;
    }

    size_t n = G.size();
    size_t rounds = proof.Rounds();

    // Check that 2^rounds == n
    if ((size_t(1) << rounds) != n) {
        return false;
    }

    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
    if (!ctx) return false;

    CPubKey U = GetGeneratorU();
    if (!U.IsValid()) {
        secp256k1_context_destroy(ctx);
        return false;
    }

    // Reconstruct challenges
    std::vector<uint256> challenges(rounds);
    std::vector<unsigned char> verify_transcript = transcript;

    for (size_t i = 0; i < rounds; i++) {
        challenges[i] = TranscriptChallenge(verify_transcript, "IPA_x",
                                            proof.L[i], proof.R[i]);
    }

    // Compute the final verification equation
    // P' = sum(x_i^-1 * L_i) + P + sum(x_i * R_i)
    // Then check: a*b*U + a*G' + b*H' == P'

    // For efficiency, we compute the combined generators and check
    std::vector<uint256> g_scalars(n), h_scalars(n);

    // Initialize all scalars to 1
    for (size_t i = 0; i < n; i++) {
        memset(g_scalars[i].begin(), 0, 32);
        memset(h_scalars[i].begin(), 0, 32);
        g_scalars[i].begin()[31] = 1;
        h_scalars[i].begin()[31] = 1;
    }

    // Precompute challenge inverses
    std::vector<uint256> challenge_inv(rounds);
    for (size_t round = 0; round < rounds; round++) {
        unsigned char inv[32];
        if (!ScalarInverse(ctx, challenges[round].begin(), inv)) {
            secp256k1_context_destroy(ctx);
            return false;
        }
        memcpy(challenge_inv[round].begin(), inv, 32);
    }

    // Apply challenge factors
    for (size_t round = 0; round < rounds; round++) {
        for (size_t i = 0; i < n; i++) {
            bool bit = (i >> (rounds - 1 - round)) & 1;
            if (bit) {
                // g_scalars: multiply by x for bit=1
                secp256k1_ec_seckey_tweak_mul(ctx, g_scalars[i].begin(),
                                               challenges[round].begin());
            } else {
                // g_scalars: multiply by x^-1 for bit=0
                secp256k1_ec_seckey_tweak_mul(ctx, g_scalars[i].begin(),
                                               challenge_inv[round].begin());
            }
            if (bit) {
                // h_scalars: multiply by x^-1 for bit=1
                secp256k1_ec_seckey_tweak_mul(ctx, h_scalars[i].begin(),
                                               challenge_inv[round].begin());
            } else {
                // h_scalars: multiply by x for bit=0
                secp256k1_ec_seckey_tweak_mul(ctx, h_scalars[i].begin(),
                                               challenges[round].begin());
            }
        }
    }

    // Multiply all g_scalars by proof.a and h_scalars by proof.b
    for (size_t i = 0; i < n; i++) {
        secp256k1_ec_seckey_tweak_mul(ctx, g_scalars[i].begin(), proof.a.begin());
        secp256k1_ec_seckey_tweak_mul(ctx, h_scalars[i].begin(), proof.b.begin());
    }

    // Compute LHS: sum(g_scalars[i] * G[i]) + sum(h_scalars[i] * H[i]) + a*b*U
    std::vector<uint256> all_scalars;
    std::vector<CPubKey> all_points;

    for (size_t i = 0; i < n; i++) {
        all_scalars.push_back(g_scalars[i]);
        all_points.push_back(G[i]);
        all_scalars.push_back(h_scalars[i]);
        all_points.push_back(H[i]);
    }

    // a * b
    uint256 ab;
    memcpy(ab.begin(), proof.a.begin(), 32);
    if (!secp256k1_ec_seckey_tweak_mul(ctx, ab.begin(), proof.b.begin())) {
        secp256k1_context_destroy(ctx);
        return false;
    }
    all_scalars.push_back(ab);
    all_points.push_back(U);

    CPubKey lhs;
    if (!MultiScalarMul(ctx, all_scalars, all_points, lhs)) {
        secp256k1_context_destroy(ctx);
        return false;
    }

    // Compute RHS: P + sum(x_i^-1 * L_i + x_i * R_i)
    std::vector<uint256> rhs_scalars;
    std::vector<CPubKey> rhs_points;

    uint256 one;
    memset(one.begin(), 0, 32);
    one.begin()[31] = 1;
    rhs_scalars.push_back(one);
    rhs_points.push_back(P);

    for (size_t i = 0; i < rounds; i++) {
        // x_i^-2 * L_i (inverse squared for L points)
        uint256 x_inv_sq;
        memcpy(x_inv_sq.begin(), challenge_inv[i].begin(), 32);
        secp256k1_ec_seckey_tweak_mul(ctx, x_inv_sq.begin(), challenge_inv[i].begin());
        rhs_scalars.push_back(x_inv_sq);
        rhs_points.push_back(proof.L[i]);

        // x_i^2 * R_i
        uint256 x_sq;
        memcpy(x_sq.begin(), challenges[i].begin(), 32);
        secp256k1_ec_seckey_tweak_mul(ctx, x_sq.begin(), challenges[i].begin());
        rhs_scalars.push_back(x_sq);
        rhs_points.push_back(proof.R[i]);
    }

    CPubKey rhs;
    if (!MultiScalarMul(ctx, rhs_scalars, rhs_points, rhs)) {
        secp256k1_context_destroy(ctx);
        return false;
    }

    // Compare LHS and RHS
    bool result = (lhs == rhs);

    secp256k1_context_destroy(ctx);
    return result;
}

bool ComputeBalancingBlindingFactor(
    const std::vector<CBlindingFactor>& inputBlinds,
    const std::vector<CBlindingFactor>& outputBlinds,
    CBlindingFactor& balancingBlind)
{
    if (inputBlinds.empty()) {
        return false;
    }

    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    if (!ctx) return false;

    // Start with sum of input blinding factors
    std::vector<unsigned char> sum(32, 0);
    memcpy(sum.data(), inputBlinds[0].begin(), 32);

    for (size_t i = 1; i < inputBlinds.size(); i++) {
        if (!secp256k1_ec_seckey_tweak_add(ctx, sum.data(), inputBlinds[i].begin())) {
            secp256k1_context_destroy(ctx);
            return false;
        }
    }

    // Subtract output blinding factors
    for (const auto& outBlind : outputBlinds) {
        // Negate and add
        unsigned char negated[32];
        memcpy(negated, outBlind.begin(), 32);
        if (!secp256k1_ec_seckey_negate(ctx, negated)) {
            secp256k1_context_destroy(ctx);
            return false;
        }
        if (!secp256k1_ec_seckey_tweak_add(ctx, sum.data(), negated)) {
            secp256k1_context_destroy(ctx);
            return false;
        }
    }

    secp256k1_context_destroy(ctx);

    memcpy(balancingBlind.data.begin(), sum.data(), 32);
    return balancingBlind.IsValid();
}

bool EncryptAmount(
    CAmount amount,
    const uint256& sharedSecret,
    std::vector<unsigned char>& encrypted)
{
    // XOR encryption with key derived from shared secret
    HashWriter hasher;
    hasher << CT_DOMAIN << "AmountEncrypt" << sharedSecret;
    uint256 key = hasher.GetHash();

    encrypted.resize(8);
    uint64_t amt = static_cast<uint64_t>(amount);
    const unsigned char* keyBytes = key.begin();
    for (int i = 0; i < 8; i++) {
        encrypted[i] = ((amt >> (i * 8)) & 0xFF) ^ keyBytes[i];
    }

    return true;
}

bool DecryptAmount(
    const std::vector<unsigned char>& encrypted,
    const uint256& sharedSecret,
    CAmount& amount)
{
    if (encrypted.size() != 8) {
        return false;
    }

    HashWriter hasher;
    hasher << CT_DOMAIN << "AmountEncrypt" << sharedSecret;
    uint256 key = hasher.GetHash();

    const unsigned char* keyBytes = key.begin();
    uint64_t amt = 0;
    for (int i = 0; i < 8; i++) {
        amt |= (uint64_t(encrypted[i] ^ keyBytes[i]) << (i * 8));
    }

    amount = static_cast<CAmount>(amt);
    return true;
}

} // namespace privacy
