// Copyright (c) 2024-2026 The WATTx Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <privacy/ring_signature.h>
#include <hash.h>
#include <crypto/sha256.h>
#include <secp256k1.h>
#include <random.h>
#include <span.h>

#include <mutex>
#include <set>
#ifndef _USE_MATH_DEFINES
#define _USE_MATH_DEFINES
#endif
#include <cmath>
#ifndef M_PI
#define M_PI 3.14159265358979323846
#endif
#include <limits>

namespace privacy {

// Domain separator for ring signature hashing
static const std::string RING_DOMAIN = "WATTx_Ring_v1";

uint256 CKeyImage::GetHash() const
{
    return Hash(data);
}

bool HashToPoint(const CPubKey& pubKey, CPubKey& result)
{
    // Hash-to-point using try-and-increment method
    // H(pubKey) -> point on curve

    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
    if (!ctx) return false;

    uint256 hash;
    int counter = 0;
    const int maxAttempts = 256;

    while (counter < maxAttempts) {
        HashWriter hasher;
        hasher << RING_DOMAIN << "HashToPoint" << pubKey << counter;
        hash = hasher.GetHash();

        // Try to parse as compressed public key (prefix 0x02 or 0x03)
        std::vector<unsigned char> testPoint(33);
        testPoint[0] = 0x02 | (hash.GetUint64(0) & 1); // Alternate prefix
        memcpy(testPoint.data() + 1, hash.begin(), 32);

        secp256k1_pubkey parsed;
        if (secp256k1_ec_pubkey_parse(ctx, &parsed, testPoint.data(), 33)) {
            result = CPubKey(testPoint.begin(), testPoint.end());
            secp256k1_context_destroy(ctx);
            return true;
        }

        counter++;
    }

    secp256k1_context_destroy(ctx);
    return false;
}

bool GenerateKeyImage(
    const CKey& privKey,
    const CPubKey& pubKey,
    CKeyImage& keyImage)
{
    // Key Image: I = x * Hp(P)
    // where x is private key, P is public key, Hp is hash-to-point

    CPubKey hpP;
    if (!HashToPoint(pubKey, hpP)) {
        return false;
    }

    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    if (!ctx) return false;

    secp256k1_pubkey hpParsed;
    if (!secp256k1_ec_pubkey_parse(ctx, &hpParsed, hpP.data(), hpP.size())) {
        secp256k1_context_destroy(ctx);
        return false;
    }

    // Multiply Hp(P) by private key x
    if (!secp256k1_ec_pubkey_tweak_mul(ctx, &hpParsed, UCharCast(privKey.begin()))) {
        secp256k1_context_destroy(ctx);
        return false;
    }

    unsigned char serialized[33];
    size_t len = 33;
    secp256k1_ec_pubkey_serialize(ctx, serialized, &len, &hpParsed, SECP256K1_EC_COMPRESSED);

    secp256k1_context_destroy(ctx);

    keyImage.data.assign(serialized, serialized + 33);
    return true;
}

// Ring hash function: H(message || L1 || R1 || L2 || R2 || ...)
static uint256 RingHash(
    const uint256& message,
    const std::vector<CPubKey>& Ls,
    const std::vector<CPubKey>& Rs)
{
    HashWriter hasher;
    hasher << RING_DOMAIN << "RingHash" << message;
    for (size_t i = 0; i < Ls.size(); i++) {
        hasher << Ls[i] << Rs[i];
    }
    return hasher.GetHash();
}

// Helper: Compute L = s*G + c*P
static bool ComputeL(secp256k1_context* ctx, const uint256& s, const uint256& c,
                     const CPubKey& P, CPubKey& L)
{
    // s*G
    secp256k1_pubkey sG;
    if (!secp256k1_ec_pubkey_create(ctx, &sG, s.begin())) {
        return false;
    }

    // c*P
    secp256k1_pubkey cP;
    if (!secp256k1_ec_pubkey_parse(ctx, &cP, P.data(), P.size())) {
        return false;
    }
    if (!secp256k1_ec_pubkey_tweak_mul(ctx, &cP, c.begin())) {
        return false;
    }

    // L = s*G + c*P
    const secp256k1_pubkey* points[2] = {&sG, &cP};
    secp256k1_pubkey result;
    if (!secp256k1_ec_pubkey_combine(ctx, &result, points, 2)) {
        return false;
    }

    unsigned char serialized[33];
    size_t len = 33;
    secp256k1_ec_pubkey_serialize(ctx, serialized, &len, &result, SECP256K1_EC_COMPRESSED);
    L = CPubKey(serialized, serialized + 33);
    return true;
}

// Helper: Compute R = s*Hp(P) + c*I
static bool ComputeR(secp256k1_context* ctx, const uint256& s, const uint256& c,
                     const CPubKey& P, const CKeyImage& I, CPubKey& R)
{
    // Hp(P)
    CPubKey HpP;
    if (!HashToPoint(P, HpP)) {
        return false;
    }

    // s*Hp(P)
    secp256k1_pubkey sHp;
    if (!secp256k1_ec_pubkey_parse(ctx, &sHp, HpP.data(), HpP.size())) {
        return false;
    }
    if (!secp256k1_ec_pubkey_tweak_mul(ctx, &sHp, s.begin())) {
        return false;
    }

    // c*I
    secp256k1_pubkey cI;
    if (!secp256k1_ec_pubkey_parse(ctx, &cI, I.data.data(), I.data.size())) {
        return false;
    }
    if (!secp256k1_ec_pubkey_tweak_mul(ctx, &cI, c.begin())) {
        return false;
    }

    // R = s*Hp(P) + c*I
    const secp256k1_pubkey* points[2] = {&sHp, &cI};
    secp256k1_pubkey result;
    if (!secp256k1_ec_pubkey_combine(ctx, &result, points, 2)) {
        return false;
    }

    unsigned char serialized[33];
    size_t len = 33;
    secp256k1_ec_pubkey_serialize(ctx, serialized, &len, &result, SECP256K1_EC_COMPRESSED);
    R = CPubKey(serialized, serialized + 33);
    return true;
}

// Helper: Compute challenge for next ring member
static uint256 ComputeChallenge(const uint256& message, const CPubKey& L, const CPubKey& R)
{
    HashWriter hasher;
    hasher << RING_DOMAIN << "Challenge" << message << L << R;
    return hasher.GetHash();
}

// Helper: Scalar subtraction (a - b) mod n
static bool ScalarSub(secp256k1_context* ctx, const unsigned char* a,
                      const unsigned char* b, unsigned char* result)
{
    // result = a - b = a + (-b) mod n
    memcpy(result, a, 32);

    unsigned char negB[32];
    memcpy(negB, b, 32);
    if (!secp256k1_ec_seckey_negate(ctx, negB)) {
        return false;
    }

    return secp256k1_ec_seckey_tweak_add(ctx, result, negB);
}

// Helper: Scalar multiplication (a * b) mod n
static bool ScalarMul(secp256k1_context* ctx, const unsigned char* a,
                      const unsigned char* b, unsigned char* result)
{
    // Use the fact that a*b = (a*G) tweaked by b won't work directly
    // Instead, we use a different approach: interpret as big integers
    // For simplicity, we'll use secp256k1's facilities indirectly

    // Create a point a*G, then extract scalar relationship
    // Actually, secp256k1 doesn't have direct scalar multiplication
    // We need to implement modular multiplication manually

    // secp256k1 order n
    static const unsigned char ORDER[32] = {
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
        0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B,
        0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41
    };

    // Simple approach: use repeated addition (slow but correct)
    // For production, use a proper bignum library
    memset(result, 0, 32);

    unsigned char temp[32];
    memcpy(temp, a, 32);

    for (int bit = 0; bit < 256; bit++) {
        int byteIdx = 31 - (bit / 8);
        int bitIdx = bit % 8;

        if ((b[byteIdx] >> bitIdx) & 1) {
            // result += temp (mod n)
            if (!secp256k1_ec_seckey_tweak_add(ctx, result, temp)) {
                // Handle overflow - result becomes temp directly if result was 0
                memcpy(result, temp, 32);
            }
        }

        // temp = temp + temp = 2*temp (mod n)
        unsigned char doubled[32];
        memcpy(doubled, temp, 32);
        if (secp256k1_ec_seckey_tweak_add(ctx, doubled, temp)) {
            memcpy(temp, doubled, 32);
        }
    }

    return secp256k1_ec_seckey_verify(ctx, result);
}

bool CreateRingSignature(
    const uint256& message,
    const CRing& ring,
    size_t realIndex,
    const CKey& privKey,
    CRingSignature& sig)
{
    if (!ring.IsValid() || realIndex >= ring.Size()) {
        return false;
    }

    size_t n = ring.Size();
    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    if (!ctx) return false;

    // Generate key image I = x * Hp(P)
    CKeyImage keyImage;
    if (!GenerateKeyImage(privKey, ring.members[realIndex].pubKey, keyImage)) {
        secp256k1_context_destroy(ctx);
        return false;
    }

    // Initialize signature
    sig.ring = ring;
    sig.keyImage = keyImage;
    sig.s.resize(n);

    // Step 1: Generate random scalar alpha for the real signer
    CKey alpha;
    alpha.MakeNewKey(true);

    // Step 2: Compute L_pi = alpha * G
    CPubKey L_pi = alpha.GetPubKey();

    // Step 3: Compute R_pi = alpha * Hp(P_pi)
    CPubKey Hp_pi;
    if (!HashToPoint(ring.members[realIndex].pubKey, Hp_pi)) {
        secp256k1_context_destroy(ctx);
        return false;
    }

    secp256k1_pubkey Hp_pi_parsed;
    if (!secp256k1_ec_pubkey_parse(ctx, &Hp_pi_parsed, Hp_pi.data(), Hp_pi.size())) {
        secp256k1_context_destroy(ctx);
        return false;
    }
    if (!secp256k1_ec_pubkey_tweak_mul(ctx, &Hp_pi_parsed, UCharCast(alpha.begin()))) {
        secp256k1_context_destroy(ctx);
        return false;
    }

    unsigned char R_pi_data[33];
    size_t R_pi_len = 33;
    secp256k1_ec_pubkey_serialize(ctx, R_pi_data, &R_pi_len, &Hp_pi_parsed, SECP256K1_EC_COMPRESSED);
    CPubKey R_pi(R_pi_data, R_pi_data + 33);

    // Step 4: Compute c_{pi+1} = H(message || L_pi || R_pi)
    std::vector<uint256> c(n);
    c[(realIndex + 1) % n] = ComputeChallenge(message, L_pi, R_pi);

    // Step 5: For each non-real member, generate random s and propagate challenge
    std::vector<CPubKey> Ls(n), Rs(n);
    Ls[realIndex] = L_pi;
    Rs[realIndex] = R_pi;

    for (size_t offset = 1; offset < n; offset++) {
        size_t i = (realIndex + offset) % n;
        size_t next = (i + 1) % n;

        // Generate random s[i]
        GetStrongRandBytes(sig.s[i]);

        // Ensure s[i] is a valid scalar
        while (!secp256k1_ec_seckey_verify(ctx, sig.s[i].begin())) {
            GetStrongRandBytes(sig.s[i]);
        }

        // Compute L[i] = s[i]*G + c[i]*P[i]
        if (!ComputeL(ctx, sig.s[i], c[i], ring.members[i].pubKey, Ls[i])) {
            secp256k1_context_destroy(ctx);
            return false;
        }

        // Compute R[i] = s[i]*Hp(P[i]) + c[i]*I
        if (!ComputeR(ctx, sig.s[i], c[i], ring.members[i].pubKey, keyImage, Rs[i])) {
            secp256k1_context_destroy(ctx);
            return false;
        }

        // Compute c[next] = H(message || L[i] || R[i])
        if (next != realIndex) {
            c[next] = ComputeChallenge(message, Ls[i], Rs[i]);
        }
    }

    // Step 6: Close the ring by computing s[realIndex] = alpha - c[realIndex] * x (mod n)
    // First compute c[realIndex] from the last iteration
    size_t lastIdx = (realIndex + n - 1) % n;
    c[realIndex] = ComputeChallenge(message, Ls[lastIdx], Rs[lastIdx]);

    // s_pi = alpha - c_pi * x (mod n)
    unsigned char cx[32];
    if (!ScalarMul(ctx, c[realIndex].begin(), UCharCast(privKey.begin()), cx)) {
        secp256k1_context_destroy(ctx);
        return false;
    }

    unsigned char s_pi[32];
    if (!ScalarSub(ctx, UCharCast(alpha.begin()), cx, s_pi)) {
        secp256k1_context_destroy(ctx);
        return false;
    }

    sig.s[realIndex] = uint256(s_pi);

    // Store c0 for verification
    sig.c0 = c[0];

    secp256k1_context_destroy(ctx);
    return true;
}

bool VerifyRingSignature(
    const uint256& message,
    const CRingSignature& sig)
{
    if (!sig.IsValid()) {
        return false;
    }

    size_t n = sig.ring.Size();

    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
    if (!ctx) return false;

    // Reconstruct L and R values, propagating challenges
    std::vector<CPubKey> Ls(n), Rs(n);
    std::vector<uint256> c(n);
    c[0] = sig.c0;

    for (size_t i = 0; i < n; i++) {
        // Verify s[i] is a valid scalar
        if (!secp256k1_ec_seckey_verify(ctx, sig.s[i].begin())) {
            secp256k1_context_destroy(ctx);
            return false;
        }

        // Compute L[i] = s[i]*G + c[i]*P[i]
        if (!ComputeL(ctx, sig.s[i], c[i], sig.ring.members[i].pubKey, Ls[i])) {
            secp256k1_context_destroy(ctx);
            return false;
        }

        // Compute R[i] = s[i]*Hp(P[i]) + c[i]*I
        if (!ComputeR(ctx, sig.s[i], c[i], sig.ring.members[i].pubKey, sig.keyImage, Rs[i])) {
            secp256k1_context_destroy(ctx);
            return false;
        }

        // Compute c[i+1] = H(message || L[i] || R[i])
        if (i < n - 1) {
            c[i + 1] = ComputeChallenge(message, Ls[i], Rs[i]);
        }
    }

    // Compute what c[0] should be from the last L, R pair
    uint256 c0_computed = ComputeChallenge(message, Ls[n - 1], Rs[n - 1]);

    secp256k1_context_destroy(ctx);

    // Ring closes if computed c0 matches provided c0
    return c0_computed == sig.c0;
}

// Helper: Compute MLSAG challenge from all L and R values across rings
static uint256 ComputeMLSAGChallenge(const uint256& message,
                                      const std::vector<CPubKey>& Ls,
                                      const std::vector<CPubKey>& Rs)
{
    HashWriter hasher;
    hasher << RING_DOMAIN << "MLSAGChallenge" << message;
    for (size_t i = 0; i < Ls.size(); i++) {
        hasher << Ls[i] << Rs[i];
    }
    return hasher.GetHash();
}

bool CreateMLSAGSignature(
    const uint256& message,
    const std::vector<CRing>& rings,
    const std::vector<size_t>& realIndices,
    const std::vector<CKey>& privKeys,
    CMLSAGSignature& sig)
{
    if (rings.empty() || rings.size() != realIndices.size() ||
        rings.size() != privKeys.size()) {
        return false;
    }

    size_t m = rings.size();      // Number of inputs (rings)
    size_t n = rings[0].Size();   // Ring size (must be same for all)

    // Verify all rings have same size
    for (const auto& ring : rings) {
        if (ring.Size() != n) return false;
    }

    // Verify all real indices are valid
    for (size_t i = 0; i < m; i++) {
        if (realIndices[i] >= n) return false;
    }

    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    if (!ctx) return false;

    sig.rings = rings;
    sig.keyImages.resize(m);
    sig.s.resize(m);

    // Generate key image for each input
    for (size_t j = 0; j < m; j++) {
        if (!GenerateKeyImage(privKeys[j], rings[j].members[realIndices[j]].pubKey,
                              sig.keyImages[j])) {
            secp256k1_context_destroy(ctx);
            return false;
        }
        sig.s[j].resize(n);
    }

    // Generate random alpha for each ring (ephemeral secrets)
    std::vector<CKey> alphas(m);
    for (size_t j = 0; j < m; j++) {
        alphas[j].MakeNewKey(true);
    }

    // Compute initial L and R for each ring at the real index
    std::vector<std::vector<CPubKey>> Ls(m, std::vector<CPubKey>(n));
    std::vector<std::vector<CPubKey>> Rs(m, std::vector<CPubKey>(n));

    for (size_t j = 0; j < m; j++) {
        size_t pi = realIndices[j];

        // L_j,pi = alpha_j * G
        Ls[j][pi] = alphas[j].GetPubKey();

        // R_j,pi = alpha_j * Hp(P_j,pi)
        CPubKey Hp_pi;
        if (!HashToPoint(rings[j].members[pi].pubKey, Hp_pi)) {
            secp256k1_context_destroy(ctx);
            return false;
        }

        secp256k1_pubkey Hp_parsed;
        if (!secp256k1_ec_pubkey_parse(ctx, &Hp_parsed, Hp_pi.data(), Hp_pi.size())) {
            secp256k1_context_destroy(ctx);
            return false;
        }
        if (!secp256k1_ec_pubkey_tweak_mul(ctx, &Hp_parsed, UCharCast(alphas[j].begin()))) {
            secp256k1_context_destroy(ctx);
            return false;
        }

        unsigned char R_data[33];
        size_t R_len = 33;
        secp256k1_ec_pubkey_serialize(ctx, R_data, &R_len, &Hp_parsed, SECP256K1_EC_COMPRESSED);
        Rs[j][pi] = CPubKey(R_data, R_data + 33);
    }

    // All real indices should be the same column for linked signatures
    // (This is a simplification - full MLSAG allows different real indices)
    size_t pi = realIndices[0];

    // Compute c_{pi+1} from all L_j,pi and R_j,pi
    std::vector<uint256> c(n);
    {
        std::vector<CPubKey> allLs(m), allRs(m);
        for (size_t j = 0; j < m; j++) {
            allLs[j] = Ls[j][pi];
            allRs[j] = Rs[j][pi];
        }
        c[(pi + 1) % n] = ComputeMLSAGChallenge(message, allLs, allRs);
    }

    // For each column (except real), generate random s and compute L, R
    for (size_t offset = 1; offset < n; offset++) {
        size_t i = (pi + offset) % n;
        size_t next = (i + 1) % n;

        std::vector<CPubKey> allLs(m), allRs(m);

        for (size_t j = 0; j < m; j++) {
            // Generate random s[j][i]
            GetStrongRandBytes(sig.s[j][i]);
            while (!secp256k1_ec_seckey_verify(ctx, sig.s[j][i].begin())) {
                GetStrongRandBytes(sig.s[j][i]);
            }

            // Compute L[j][i] = s[j][i]*G + c[i]*P[j][i]
            if (!ComputeL(ctx, sig.s[j][i], c[i], rings[j].members[i].pubKey, Ls[j][i])) {
                secp256k1_context_destroy(ctx);
                return false;
            }

            // Compute R[j][i] = s[j][i]*Hp(P[j][i]) + c[i]*I[j]
            if (!ComputeR(ctx, sig.s[j][i], c[i], rings[j].members[i].pubKey,
                          sig.keyImages[j], Rs[j][i])) {
                secp256k1_context_destroy(ctx);
                return false;
            }

            allLs[j] = Ls[j][i];
            allRs[j] = Rs[j][i];
        }

        // Compute c[next]
        if (next != pi) {
            c[next] = ComputeMLSAGChallenge(message, allLs, allRs);
        }
    }

    // Compute c[pi] from last column
    {
        size_t lastIdx = (pi + n - 1) % n;
        std::vector<CPubKey> allLs(m), allRs(m);
        for (size_t j = 0; j < m; j++) {
            allLs[j] = Ls[j][lastIdx];
            allRs[j] = Rs[j][lastIdx];
        }
        c[pi] = ComputeMLSAGChallenge(message, allLs, allRs);
    }

    // Close each ring: s[j][pi] = alpha[j] - c[pi] * x[j] (mod n)
    for (size_t j = 0; j < m; j++) {
        unsigned char cx[32];
        if (!ScalarMul(ctx, c[pi].begin(), UCharCast(privKeys[j].begin()), cx)) {
            secp256k1_context_destroy(ctx);
            return false;
        }

        unsigned char s_pi[32];
        if (!ScalarSub(ctx, UCharCast(alphas[j].begin()), cx, s_pi)) {
            secp256k1_context_destroy(ctx);
            return false;
        }

        sig.s[j][pi] = uint256(s_pi);
    }

    sig.c0 = c[0];

    secp256k1_context_destroy(ctx);
    return true;
}

bool VerifyMLSAGSignature(
    const uint256& message,
    const CMLSAGSignature& sig)
{
    if (!sig.IsValid()) {
        return false;
    }

    size_t m = sig.rings.size();  // Number of inputs
    size_t n = sig.RingSize();    // Ring size

    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
    if (!ctx) return false;

    // Reconstruct all L and R values
    std::vector<std::vector<CPubKey>> Ls(m, std::vector<CPubKey>(n));
    std::vector<std::vector<CPubKey>> Rs(m, std::vector<CPubKey>(n));
    std::vector<uint256> c(n);
    c[0] = sig.c0;

    for (size_t i = 0; i < n; i++) {
        std::vector<CPubKey> allLs(m), allRs(m);

        for (size_t j = 0; j < m; j++) {
            // Verify s[j][i] is a valid scalar
            if (!secp256k1_ec_seckey_verify(ctx, sig.s[j][i].begin())) {
                secp256k1_context_destroy(ctx);
                return false;
            }

            // Compute L[j][i] = s[j][i]*G + c[i]*P[j][i]
            if (!ComputeL(ctx, sig.s[j][i], c[i], sig.rings[j].members[i].pubKey, Ls[j][i])) {
                secp256k1_context_destroy(ctx);
                return false;
            }

            // Compute R[j][i] = s[j][i]*Hp(P[j][i]) + c[i]*I[j]
            if (!ComputeR(ctx, sig.s[j][i], c[i], sig.rings[j].members[i].pubKey,
                          sig.keyImages[j], Rs[j][i])) {
                secp256k1_context_destroy(ctx);
                return false;
            }

            allLs[j] = Ls[j][i];
            allRs[j] = Rs[j][i];
        }

        // Compute c[i+1]
        if (i < n - 1) {
            c[i + 1] = ComputeMLSAGChallenge(message, allLs, allRs);
        }
    }

    // Compute what c[0] should be from the last column
    std::vector<CPubKey> lastLs(m), lastRs(m);
    for (size_t j = 0; j < m; j++) {
        lastLs[j] = Ls[j][n - 1];
        lastRs[j] = Rs[j][n - 1];
    }
    uint256 c0_computed = ComputeMLSAGChallenge(message, lastLs, lastRs);

    secp256k1_context_destroy(ctx);

    // Ring closes if computed c0 matches provided c0
    return c0_computed == sig.c0;
}

// Global decoy provider
static std::shared_ptr<IDecoyProvider> g_decoyProvider;
static std::mutex g_decoyProviderMutex;

void SetDecoyProvider(std::shared_ptr<IDecoyProvider> provider)
{
    std::lock_guard<std::mutex> lock(g_decoyProviderMutex);
    g_decoyProvider = provider;
}

void ClearDecoyProvider()
{
    std::lock_guard<std::mutex> lock(g_decoyProviderMutex);
    g_decoyProvider.reset();
}

std::shared_ptr<IDecoyProvider> GetDecoyProvider()
{
    std::lock_guard<std::mutex> lock(g_decoyProviderMutex);
    return g_decoyProvider;
}

// Helper: Get random double in [0, 1)
static double GetRandomDouble()
{
    uint64_t randVal;
    GetStrongRandBytes(Span<unsigned char>(reinterpret_cast<unsigned char*>(&randVal),
                                            sizeof(randVal)));
    return static_cast<double>(randVal) / static_cast<double>(UINT64_MAX);
}

// Helper: Get random uint64
static uint64_t GetRandomUint64()
{
    uint64_t randVal;
    GetStrongRandBytes(Span<unsigned char>(reinterpret_cast<unsigned char*>(&randVal),
                                            sizeof(randVal)));
    return randVal;
}

// Gamma distribution sampling for age selection (mimics Monero)
static uint64_t SampleGamma(double shape, double scale, uint64_t maxValue)
{
    // Simple gamma sampling using Marsaglia and Tsang's method
    // For shape >= 1
    if (shape < 1.0) shape = 1.0;

    double d = shape - 1.0/3.0;
    double c = 1.0 / sqrt(9.0 * d);

    while (true) {
        double x, v;
        do {
            // Generate standard normal using Box-Muller
            double u1 = GetRandomDouble();
            double u2 = GetRandomDouble();

            if (u1 <= 0) u1 = 1e-10;

            x = sqrt(-2.0 * log(u1)) * cos(2.0 * M_PI * u2);
            v = 1.0 + c * x;
        } while (v <= 0);

        v = v * v * v;

        double u = GetRandomDouble();

        if (u < 1.0 - 0.0331 * (x * x) * (x * x)) {
            double result = d * v * scale;
            if (result < 0) result = 0;
            if (result > static_cast<double>(maxValue)) result = static_cast<double>(maxValue);
            return static_cast<uint64_t>(result);
        }

        if (log(u) < 0.5 * x * x + d * (1.0 - v + log(v))) {
            double result = d * v * scale;
            if (result < 0) result = 0;
            if (result > static_cast<double>(maxValue)) result = static_cast<double>(maxValue);
            return static_cast<uint64_t>(result);
        }
    }
}

// Simple random sampling for fallback
static uint64_t SampleUniform(uint64_t maxValue)
{
    if (maxValue == 0) return 0;
    return GetRandomUint64() % (maxValue + 1);
}

bool SelectDecoys(
    const COutPoint& realOutput,
    size_t ringSize,
    CAmount realAmount,
    const CPubKey& realPubKey,
    const CDecoySelectionParams& params,
    std::vector<CRingMember>& decoys)
{
    decoys.clear();

    if (ringSize < 2) {
        return false;  // Need at least 1 decoy
    }

    auto provider = GetDecoyProvider();
    if (!provider) {
        // No provider registered - cannot select decoys
        return false;
    }

    uint64_t totalOutputs = provider->GetOutputCount();
    int currentHeight = provider->GetHeight();

    if (totalOutputs < ringSize) {
        // Not enough outputs in the chain
        return false;
    }

    size_t neededDecoys = ringSize - 1;  // Exclude real output
    std::set<uint256> selectedTxids;  // Avoid duplicates
    selectedTxids.insert(realOutput.hash);

    int minHeight = currentHeight - params.maxConfirmations;
    if (params.maxConfirmations == 0 || minHeight < 0) {
        minHeight = 0;
    }
    int maxHeight = currentHeight - params.minConfirmations;

    // Try to get random outputs
    std::vector<CDecoyCandidate> candidates;

    if (params.useGammaDistribution) {
        // Use gamma distribution to prefer recent outputs
        // This mimics real spending patterns

        int attempts = 0;
        const int maxAttempts = neededDecoys * 10;

        while (decoys.size() < neededDecoys && attempts < maxAttempts) {
            attempts++;

            // Sample an output index using gamma distribution
            // Gamma favors recent outputs (higher indices)
            uint64_t outputIndex;
            if (totalOutputs > 0) {
                uint64_t gammaResult = SampleGamma(params.gammaShape, 1.0, totalOutputs);
                // Invert so higher values (more recent) are more likely
                outputIndex = totalOutputs - 1 - gammaResult;
                if (outputIndex >= totalOutputs) outputIndex = 0;
            } else {
                continue;
            }

            CDecoyCandidate candidate;
            if (!provider->GetOutputByIndex(outputIndex, candidate)) {
                continue;
            }

            // Check height constraints
            if (candidate.height < (uint32_t)minHeight ||
                candidate.height > (uint32_t)maxHeight) {
                continue;
            }

            // Check for duplicates
            if (selectedTxids.count(candidate.outpoint.hash)) {
                continue;
            }

            // Optional: amount similarity check
            if (params.amountSimilarity < 1.0 && realAmount > 0) {
                double ratio = (double)candidate.amount / (double)realAmount;
                if (ratio < 1.0) ratio = 1.0 / ratio;

                // Check if within acceptable range
                double maxRatio = 1.0 + (10.0 * params.amountSimilarity);  // e.g., 0.5 -> 6x
                if (ratio > maxRatio) {
                    // Too different, but still accept with some probability
                    uint64_t r = SampleUniform(100);
                    if (r > 20) continue;  // 80% rejection for dissimilar amounts
                }
            }

            // Check for coinbase/coinstake if excluded
            // (This would require additional metadata from provider)

            // Valid decoy found
            selectedTxids.insert(candidate.outpoint.hash);

            CRingMember member;
            member.outpoint = candidate.outpoint;
            member.pubKey = candidate.pubKey;
            decoys.push_back(member);
        }
    } else {
        // Uniform random selection (fallback)
        size_t retrieved = provider->GetRandomOutputs(
            neededDecoys * 2,  // Get extra in case of filtering
            minHeight,
            maxHeight,
            candidates);

        for (const auto& candidate : candidates) {
            if (decoys.size() >= neededDecoys) break;

            if (selectedTxids.count(candidate.outpoint.hash)) {
                continue;
            }

            selectedTxids.insert(candidate.outpoint.hash);

            CRingMember member;
            member.outpoint = candidate.outpoint;
            member.pubKey = candidate.pubKey;
            decoys.push_back(member);
        }
    }

    return decoys.size() >= neededDecoys;
}

bool SelectDecoys(
    const COutPoint& realOutput,
    size_t ringSize,
    std::vector<CRingMember>& decoys)
{
    // Use default parameters
    CDecoySelectionParams params;
    return SelectDecoys(realOutput, ringSize, 0, CPubKey(), params, decoys);
}

bool BuildRing(
    const CRingMember& realOutput,
    const std::vector<CRingMember>& decoys,
    CRing& ring,
    size_t& realIndex)
{
    size_t ringSize = decoys.size() + 1;

    // Generate random position for real output
    uint64_t randPos = GetRandomUint64();
    realIndex = randPos % ringSize;

    // Build ring with real output at random position
    ring.members.clear();
    ring.members.reserve(ringSize);

    size_t decoyIdx = 0;
    for (size_t i = 0; i < ringSize; i++) {
        if (i == realIndex) {
            ring.members.push_back(realOutput);
        } else {
            if (decoyIdx >= decoys.size()) {
                return false;
            }
            ring.members.push_back(decoys[decoyIdx++]);
        }
    }

    return ring.IsValid();
}

} // namespace privacy
