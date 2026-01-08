// Copyright (c) 2025 The WATTx Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef WATTX_CRYPTO_DILITHIUM_H
#define WATTX_CRYPTO_DILITHIUM_H

#include <uint256.h>
#include <vector>
#include <array>
#include <string>

/**
 * Dilithium (ML-DSA) Post-Quantum Digital Signature Wrapper
 *
 * This implements NIST's ML-DSA-65 (formerly CRYSTALS-Dilithium) for
 * quantum-resistant signatures in WATTx.
 *
 * ML-DSA-65 provides:
 * - 128-bit classical security
 * - 128-bit post-quantum security
 * - Fast signing and verification
 * - Reasonable signature sizes (~3.3KB)
 *
 * Uses liboqs (Open Quantum Safe) library for the underlying implementation.
 */

namespace dilithium {

// ML-DSA-65 (Dilithium3) sizes
static constexpr size_t PUBLIC_KEY_SIZE = 1952;
static constexpr size_t SECRET_KEY_SIZE = 4032;
static constexpr size_t SIGNATURE_SIZE = 3309;

// Algorithm identifier for ML-DSA-65
static const char* const ALGORITHM_NAME = "ML-DSA-65";

/**
 * Dilithium public key
 */
class CPubKey {
private:
    std::vector<uint8_t> vchPubKey;

public:
    CPubKey() = default;
    explicit CPubKey(const std::vector<uint8_t>& pubkey) : vchPubKey(pubkey) {}
    explicit CPubKey(std::vector<uint8_t>&& pubkey) : vchPubKey(std::move(pubkey)) {}

    bool IsValid() const { return vchPubKey.size() == PUBLIC_KEY_SIZE; }
    size_t size() const { return vchPubKey.size(); }
    const uint8_t* data() const { return vchPubKey.data(); }
    const uint8_t* begin() const { return vchPubKey.data(); }
    const uint8_t* end() const { return vchPubKey.data() + vchPubKey.size(); }

    std::vector<uint8_t> GetBytes() const { return vchPubKey; }

    /**
     * Get the hash of this public key (for address generation)
     */
    uint256 GetHash() const;

    /**
     * Verify a Dilithium signature
     * @param hash The message hash that was signed
     * @param sig The signature to verify
     * @return true if signature is valid
     */
    bool Verify(const uint256& hash, const std::vector<uint8_t>& sig) const;

    /**
     * Verify a signature over arbitrary data
     * @param data The data that was signed
     * @param dataLen Length of data
     * @param sig The signature to verify
     * @return true if signature is valid
     */
    bool VerifyData(const uint8_t* data, size_t dataLen, const std::vector<uint8_t>& sig) const;

    bool operator==(const CPubKey& other) const { return vchPubKey == other.vchPubKey; }
    bool operator!=(const CPubKey& other) const { return !(*this == other); }
    bool operator<(const CPubKey& other) const { return vchPubKey < other.vchPubKey; }

    // Serialization
    template<typename Stream>
    void Serialize(Stream& s) const {
        s.write(reinterpret_cast<const char*>(vchPubKey.data()), vchPubKey.size());
    }

    template<typename Stream>
    void Unserialize(Stream& s) {
        vchPubKey.resize(PUBLIC_KEY_SIZE);
        s.read(reinterpret_cast<char*>(vchPubKey.data()), PUBLIC_KEY_SIZE);
    }
};

/**
 * Dilithium secret/private key
 */
class CKey {
private:
    std::vector<uint8_t> vchSecretKey;
    bool fValid{false};

public:
    CKey() = default;
    ~CKey();

    // Disable copy to protect secret key material
    CKey(const CKey&) = delete;
    CKey& operator=(const CKey&) = delete;

    // Allow move
    CKey(CKey&& other) noexcept;
    CKey& operator=(CKey&& other) noexcept;

    bool IsValid() const { return fValid && vchSecretKey.size() == SECRET_KEY_SIZE; }

    /**
     * Generate a new random Dilithium key pair
     * @return true if key generation succeeded
     */
    bool MakeNewKey();

    /**
     * Set the secret key from raw bytes
     * @param data Secret key bytes
     * @param len Length (must be SECRET_KEY_SIZE)
     * @return true if valid
     */
    bool SetSecretKey(const uint8_t* data, size_t len);

    /**
     * Get the secret key bytes (for storage)
     * @return Secret key bytes
     */
    std::vector<uint8_t> GetSecretKey() const;

    /**
     * Get the corresponding public key
     * @return Public key
     */
    CPubKey GetPubKey() const;

    /**
     * Sign a 256-bit hash
     * @param hash The hash to sign
     * @param sig Output: the signature
     * @return true if signing succeeded
     */
    bool Sign(const uint256& hash, std::vector<uint8_t>& sig) const;

    /**
     * Sign arbitrary data
     * @param data The data to sign
     * @param dataLen Length of data
     * @param sig Output: the signature
     * @return true if signing succeeded
     */
    bool SignData(const uint8_t* data, size_t dataLen, std::vector<uint8_t>& sig) const;

private:
    void Clear();
};

/**
 * Initialize the Dilithium subsystem
 * Must be called before using any Dilithium functions
 * @return true if initialization succeeded
 */
bool Initialize();

/**
 * Check if Dilithium is available (liboqs compiled with ML-DSA support)
 * @return true if Dilithium is available
 */
bool IsAvailable();

/**
 * Get the algorithm name string
 * @return Algorithm name (e.g., "ML-DSA-65")
 */
std::string GetAlgorithmName();

} // namespace dilithium

#endif // WATTX_CRYPTO_DILITHIUM_H
