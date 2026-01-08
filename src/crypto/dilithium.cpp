// Copyright (c) 2025 The WATTx Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <crypto/dilithium.h>
#include <hash.h>
#include <logging.h>
#include <random.h>
#include <support/cleanse.h>

#include <cstring>
#include <mutex>

#ifdef HAVE_LIBOQS
#include <oqs/oqs.h>
#endif

namespace dilithium {

// Thread-safe initialization flag
static std::once_flag g_init_flag;
static bool g_initialized = false;
static bool g_available = false;

bool Initialize()
{
#ifdef HAVE_LIBOQS
    std::call_once(g_init_flag, []() {
        // Check if liboqs supports ML-DSA-65
        if (OQS_SIG_alg_is_enabled(OQS_SIG_alg_ml_dsa_65)) {
            g_available = true;
            g_initialized = true;
            LogPrintf("Dilithium (ML-DSA-65) post-quantum signatures: enabled\n");
        } else {
            g_available = false;
            g_initialized = true;
            LogPrintf("Dilithium (ML-DSA-65): NOT available in liboqs build\n");
        }
    });
    return g_initialized && g_available;
#else
    std::call_once(g_init_flag, []() {
        g_available = false;
        g_initialized = true;
        LogPrintf("Dilithium (ML-DSA-65): liboqs not available at compile time\n");
    });
    return false;
#endif
}

bool IsAvailable()
{
    if (!g_initialized) {
        Initialize();
    }
    return g_available;
}

std::string GetAlgorithmName()
{
    return ALGORITHM_NAME;
}

// ============================================================================
// CPubKey implementation
// ============================================================================

uint256 CPubKey::GetHash() const
{
    if (!IsValid()) {
        return uint256();
    }
    return Hash(vchPubKey);
}

bool CPubKey::Verify(const uint256& hash, const std::vector<uint8_t>& sig) const
{
    return VerifyData(hash.begin(), 32, sig);
}

bool CPubKey::VerifyData(const uint8_t* data, size_t dataLen, const std::vector<uint8_t>& sig) const
{
#ifdef HAVE_LIBOQS
    if (!IsValid()) {
        LogPrintf( "Dilithium::Verify: invalid public key\n");
        return false;
    }

    if (sig.size() != SIGNATURE_SIZE) {
        LogPrintf( "Dilithium::Verify: invalid signature size %zu (expected %zu)\n",
                 sig.size(), SIGNATURE_SIZE);
        return false;
    }

    if (!IsAvailable()) {
        LogPrintf( "Dilithium::Verify: ML-DSA not available\n");
        return false;
    }

    OQS_SIG* sig_ctx = OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);
    if (!sig_ctx) {
        LogPrintf( "Dilithium::Verify: failed to create signature context\n");
        return false;
    }

    OQS_STATUS result = OQS_SIG_verify(
        sig_ctx,
        data, dataLen,
        sig.data(), sig.size(),
        vchPubKey.data()
    );

    OQS_SIG_free(sig_ctx);

    if (result != OQS_SUCCESS) {
        LogPrintf( "Dilithium::Verify: signature verification failed\n");
        return false;
    }

    return true;
#else
    (void)data;
    (void)dataLen;
    (void)sig;
    LogPrintf("Dilithium::Verify: liboqs not available\n");
    return false;
#endif
}

// ============================================================================
// CKey implementation
// ============================================================================

CKey::~CKey()
{
    Clear();
}

CKey::CKey(CKey&& other) noexcept
    : vchSecretKey(std::move(other.vchSecretKey))
    , fValid(other.fValid)
{
    other.fValid = false;
}

CKey& CKey::operator=(CKey&& other) noexcept
{
    if (this != &other) {
        Clear();
        vchSecretKey = std::move(other.vchSecretKey);
        fValid = other.fValid;
        other.fValid = false;
    }
    return *this;
}

void CKey::Clear()
{
    if (!vchSecretKey.empty()) {
        // Secure erase
        memory_cleanse(vchSecretKey.data(), vchSecretKey.size());
        vchSecretKey.clear();
    }
    fValid = false;
}

bool CKey::MakeNewKey()
{
#ifdef HAVE_LIBOQS
    Clear();

    if (!IsAvailable()) {
        LogPrintf( "Dilithium::MakeNewKey: ML-DSA not available\n");
        return false;
    }

    OQS_SIG* sig_ctx = OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);
    if (!sig_ctx) {
        LogPrintf( "Dilithium::MakeNewKey: failed to create signature context\n");
        return false;
    }

    std::vector<uint8_t> pubkey(sig_ctx->length_public_key);
    vchSecretKey.resize(sig_ctx->length_secret_key);

    OQS_STATUS result = OQS_SIG_keypair(sig_ctx, pubkey.data(), vchSecretKey.data());

    OQS_SIG_free(sig_ctx);

    if (result != OQS_SUCCESS) {
        Clear();
        LogPrintf( "Dilithium::MakeNewKey: key generation failed\n");
        return false;
    }

    fValid = true;
    return true;
#else
    LogPrintf("Dilithium::MakeNewKey: liboqs not available\n");
    return false;
#endif
}

bool CKey::SetSecretKey(const uint8_t* data, size_t len)
{
    Clear();

    if (len != SECRET_KEY_SIZE) {
        LogPrintf( "Dilithium::SetSecretKey: invalid key size %zu (expected %zu)\n",
                 len, SECRET_KEY_SIZE);
        return false;
    }

    vchSecretKey.assign(data, data + len);
    fValid = true;
    return true;
}

std::vector<uint8_t> CKey::GetSecretKey() const
{
    if (!IsValid()) {
        return {};
    }
    return vchSecretKey;
}

CPubKey CKey::GetPubKey() const
{
#ifdef HAVE_LIBOQS
    if (!IsValid()) {
        return CPubKey();
    }

    if (!IsAvailable()) {
        return CPubKey();
    }

    // Extract public key from secret key
    // In ML-DSA, the secret key contains the public key as a suffix
    // The structure is: rho || K || tr || s1 || s2 || t0 || pk
    // where pk is the last PUBLIC_KEY_SIZE bytes

    // For ML-DSA-65, we need to derive the public key
    // Alternatively, we can store both together
    // For simplicity, we'll regenerate from seed if needed

    OQS_SIG* sig_ctx = OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);
    if (!sig_ctx) {
        return CPubKey();
    }

    // The secret key in liboqs contains the public key
    // Extract it (the format depends on the implementation)
    // For ML-DSA, the public key is NOT directly embedded,
    // so we compute it by signing and using internal structures

    // Workaround: Sign a dummy message to verify the key is valid,
    // then extract pubkey using liboqs internal functions
    // Actually, liboqs provides OQS_SIG_keypair_from_seed for some algorithms

    // For now, we'll store public key separately in wallet
    // This is a placeholder - actual implementation would need
    // to store pubkey alongside secret key in wallet database

    OQS_SIG_free(sig_ctx);

    // Return empty - caller should store pubkey separately
    LogPrintf( "Dilithium::GetPubKey: public key must be stored separately\n");
    return CPubKey();
#else
    return CPubKey();
#endif
}

bool CKey::Sign(const uint256& hash, std::vector<uint8_t>& sig) const
{
    return SignData(hash.begin(), 32, sig);
}

bool CKey::SignData(const uint8_t* data, size_t dataLen, std::vector<uint8_t>& sig) const
{
#ifdef HAVE_LIBOQS
    if (!IsValid()) {
        LogPrintf( "Dilithium::Sign: invalid secret key\n");
        return false;
    }

    if (!IsAvailable()) {
        LogPrintf( "Dilithium::Sign: ML-DSA not available\n");
        return false;
    }

    OQS_SIG* sig_ctx = OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);
    if (!sig_ctx) {
        LogPrintf( "Dilithium::Sign: failed to create signature context\n");
        return false;
    }

    sig.resize(sig_ctx->length_signature);
    size_t sig_len = 0;

    OQS_STATUS result = OQS_SIG_sign(
        sig_ctx,
        sig.data(), &sig_len,
        data, dataLen,
        vchSecretKey.data()
    );

    OQS_SIG_free(sig_ctx);

    if (result != OQS_SUCCESS) {
        sig.clear();
        LogPrintf( "Dilithium::Sign: signing failed\n");
        return false;
    }

    sig.resize(sig_len);
    return true;
#else
    LogPrintf( "Dilithium::Sign: liboqs not available\n");
    return false;
#endif
}

} // namespace dilithium
