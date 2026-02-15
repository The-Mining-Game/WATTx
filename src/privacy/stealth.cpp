// Copyright (c) 2024-2026 The WATTx Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <privacy/stealth.h>
#include <hash.h>
#include <crypto/sha256.h>
#include <base58.h>
#include <secp256k1.h>
#include <secp256k1_extrakeys.h>
#include <random.h>

#include <string>
#include <vector>

namespace privacy {

// Domain separator for stealth address key derivation
static const std::string STEALTH_DOMAIN = "WATTx_Stealth_v1";

uint8_t ComputeViewTag(const CPubKey& sharedSecret)
{
    uint256 hash;
    CSHA256()
        .Write((const unsigned char*)STEALTH_DOMAIN.data(), STEALTH_DOMAIN.size())
        .Write(sharedSecret.data(), sharedSecret.size())
        .Finalize(hash.begin());

    return hash.GetUint64(0) & 0xFF;
}

uint256 HashSharedSecret(const CPubKey& sharedSecret, uint32_t outputIndex)
{
    uint256 result;
    HashWriter hasher;
    hasher << STEALTH_DOMAIN;
    hasher << sharedSecret;
    hasher << outputIndex;
    result = hasher.GetHash();
    return result;
}

bool GenerateStealthDestination(
    const CStealthAddress& stealthAddr,
    CKey& ephemeralPrivKey,
    CStealthOutput& output)
{
    if (!stealthAddr.IsValid()) {
        return false;
    }

    // Generate random ephemeral private key
    ephemeralPrivKey.MakeNewKey(true);
    if (!ephemeralPrivKey.IsValid()) {
        return false;
    }

    // R = r * G (ephemeral public key)
    CPubKey ephemeralPubKey = ephemeralPrivKey.GetPubKey();
    if (!ephemeralPubKey.IsValid()) {
        return false;
    }

    // Compute shared secret S = r * scan_pubkey
    // Using ECDH: shared_point = ephemeral_privkey * scan_pubkey
    unsigned char sharedSecretData[33];
    size_t sharedSecretLen = 33;

    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    if (!ctx) {
        return false;
    }

    secp256k1_pubkey scanPubKeyParsed;
    if (!secp256k1_ec_pubkey_parse(ctx, &scanPubKeyParsed,
                                    stealthAddr.scanPubKey.data(),
                                    stealthAddr.scanPubKey.size())) {
        secp256k1_context_destroy(ctx);
        return false;
    }

    // Multiply scan_pubkey by ephemeral_privkey to get shared secret
    if (!secp256k1_ec_pubkey_tweak_mul(ctx, &scanPubKeyParsed, UCharCast(ephemeralPrivKey.begin()))) {
        secp256k1_context_destroy(ctx);
        return false;
    }

    secp256k1_ec_pubkey_serialize(ctx, sharedSecretData, &sharedSecretLen,
                                   &scanPubKeyParsed, SECP256K1_EC_COMPRESSED);

    CPubKey sharedSecretPoint(sharedSecretData, sharedSecretData + sharedSecretLen);

    // Compute view tag for fast filtering
    uint8_t viewTag = ComputeViewTag(sharedSecretPoint);

    // Hash shared secret to get scalar: h = H(S || output_index)
    uint256 scalarHash = HashSharedSecret(sharedSecretPoint, output.outputIndex);

    // Compute one-time public key: P = spend_pubkey + h*G
    secp256k1_pubkey spendPubKeyParsed;
    if (!secp256k1_ec_pubkey_parse(ctx, &spendPubKeyParsed,
                                    stealthAddr.spendPubKey.data(),
                                    stealthAddr.spendPubKey.size())) {
        secp256k1_context_destroy(ctx);
        return false;
    }

    // Add h*G to spend_pubkey
    if (!secp256k1_ec_pubkey_tweak_add(ctx, &spendPubKeyParsed, scalarHash.begin())) {
        secp256k1_context_destroy(ctx);
        return false;
    }

    // Serialize the one-time public key
    unsigned char oneTimePubKeyData[33];
    size_t oneTimePubKeyLen = 33;
    secp256k1_ec_pubkey_serialize(ctx, oneTimePubKeyData, &oneTimePubKeyLen,
                                   &spendPubKeyParsed, SECP256K1_EC_COMPRESSED);

    secp256k1_context_destroy(ctx);

    // Build output
    output.oneTimePubKey = CPubKey(oneTimePubKeyData, oneTimePubKeyData + oneTimePubKeyLen);
    output.ephemeral = CEphemeralData(ephemeralPubKey, viewTag);

    return output.oneTimePubKey.IsValid();
}

bool ScanStealthOutput(
    const CStealthOutput& output,
    const CKey& scanPrivKey,
    const CPubKey& spendPubKey,
    CKey& derivedPrivKey)
{
    if (!output.oneTimePubKey.IsValid() || !output.ephemeral.ephemeralPubKey.IsValid()) {
        return false;
    }

    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    if (!ctx) {
        return false;
    }

    // Compute shared secret S' = scan_privkey * R
    secp256k1_pubkey ephemeralPubKeyParsed;
    if (!secp256k1_ec_pubkey_parse(ctx, &ephemeralPubKeyParsed,
                                    output.ephemeral.ephemeralPubKey.data(),
                                    output.ephemeral.ephemeralPubKey.size())) {
        secp256k1_context_destroy(ctx);
        return false;
    }

    if (!secp256k1_ec_pubkey_tweak_mul(ctx, &ephemeralPubKeyParsed, UCharCast(scanPrivKey.begin()))) {
        secp256k1_context_destroy(ctx);
        return false;
    }

    unsigned char sharedSecretData[33];
    size_t sharedSecretLen = 33;
    secp256k1_ec_pubkey_serialize(ctx, sharedSecretData, &sharedSecretLen,
                                   &ephemeralPubKeyParsed, SECP256K1_EC_COMPRESSED);

    CPubKey sharedSecretPoint(sharedSecretData, sharedSecretData + sharedSecretLen);

    // Quick check with view tag
    uint8_t expectedViewTag = ComputeViewTag(sharedSecretPoint);
    if (expectedViewTag != output.ephemeral.viewTag) {
        secp256k1_context_destroy(ctx);
        return false;
    }

    // Hash shared secret to get scalar: h = H(S' || output_index)
    uint256 scalarHash = HashSharedSecret(sharedSecretPoint, output.outputIndex);

    // Compute expected one-time public key: P' = spend_pubkey + h*G
    secp256k1_pubkey spendPubKeyParsed;
    if (!secp256k1_ec_pubkey_parse(ctx, &spendPubKeyParsed,
                                    spendPubKey.data(),
                                    spendPubKey.size())) {
        secp256k1_context_destroy(ctx);
        return false;
    }

    if (!secp256k1_ec_pubkey_tweak_add(ctx, &spendPubKeyParsed, scalarHash.begin())) {
        secp256k1_context_destroy(ctx);
        return false;
    }

    unsigned char expectedPubKeyData[33];
    size_t expectedPubKeyLen = 33;
    secp256k1_ec_pubkey_serialize(ctx, expectedPubKeyData, &expectedPubKeyLen,
                                   &spendPubKeyParsed, SECP256K1_EC_COMPRESSED);

    secp256k1_context_destroy(ctx);

    // Check if computed public key matches the output
    if (memcmp(expectedPubKeyData, output.oneTimePubKey.data(), 33) != 0) {
        return false;
    }

    // Match found! Caller needs to derive spending key separately
    // (requires spend_privkey which we don't have here)
    return true;
}

bool DeriveStealthSpendingKey(
    const CKey& scanPrivKey,
    const CKey& spendPrivKey,
    const CPubKey& ephemeralPubKey,
    uint32_t outputIndex,
    CKey& derivedKey)
{
    if (!scanPrivKey.IsValid() || !spendPrivKey.IsValid() || !ephemeralPubKey.IsValid()) {
        return false;
    }

    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    if (!ctx) {
        return false;
    }

    // Compute shared secret S = scan_privkey * R
    secp256k1_pubkey ephemeralPubKeyParsed;
    if (!secp256k1_ec_pubkey_parse(ctx, &ephemeralPubKeyParsed,
                                    ephemeralPubKey.data(),
                                    ephemeralPubKey.size())) {
        secp256k1_context_destroy(ctx);
        return false;
    }

    if (!secp256k1_ec_pubkey_tweak_mul(ctx, &ephemeralPubKeyParsed, UCharCast(scanPrivKey.begin()))) {
        secp256k1_context_destroy(ctx);
        return false;
    }

    unsigned char sharedSecretData[33];
    size_t sharedSecretLen = 33;
    secp256k1_ec_pubkey_serialize(ctx, sharedSecretData, &sharedSecretLen,
                                   &ephemeralPubKeyParsed, SECP256K1_EC_COMPRESSED);

    CPubKey sharedSecretPoint(sharedSecretData, sharedSecretData + sharedSecretLen);

    // Hash shared secret to get scalar: h = H(S || output_index)
    uint256 scalarHash = HashSharedSecret(sharedSecretPoint, outputIndex);

    // Derive spending key: privkey = spend_privkey + h (mod n)
    std::vector<unsigned char> derivedKeyData(UCharCast(spendPrivKey.begin()), UCharCast(spendPrivKey.end()));

    if (!secp256k1_ec_seckey_tweak_add(ctx, derivedKeyData.data(), scalarHash.begin())) {
        secp256k1_context_destroy(ctx);
        return false;
    }

    secp256k1_context_destroy(ctx);

    derivedKey.Set(derivedKeyData.begin(), derivedKeyData.end(), true);
    return derivedKey.IsValid();
}

std::string CStealthAddress::ToString() const
{
    if (!IsValid()) {
        return "";
    }

    std::vector<unsigned char> data;
    data.push_back(0x2A); // Stealth address version byte

    // Append scan and spend public keys
    data.insert(data.end(), scanPubKey.begin(), scanPubKey.end());
    data.insert(data.end(), spendPubKey.begin(), spendPubKey.end());

    // Append prefix options
    data.push_back(prefixLength);
    if (prefixLength > 0) {
        data.push_back((prefix >> 24) & 0xFF);
        data.push_back((prefix >> 16) & 0xFF);
        data.push_back((prefix >> 8) & 0xFF);
        data.push_back(prefix & 0xFF);
    }

    return "sx1" + EncodeBase58Check(data);
}

std::optional<CStealthAddress> CStealthAddress::FromString(const std::string& str)
{
    if (str.substr(0, 3) != "sx1") {
        return std::nullopt;
    }

    std::vector<unsigned char> data;
    if (!DecodeBase58Check(str.substr(3), data, 100)) {
        return std::nullopt;
    }

    if (data.size() < 67 || data[0] != 0x2A) {
        return std::nullopt;
    }

    CStealthAddress addr;
    addr.scanPubKey = CPubKey(data.begin() + 1, data.begin() + 34);
    addr.spendPubKey = CPubKey(data.begin() + 34, data.begin() + 67);

    if (data.size() > 67) {
        addr.prefixLength = data[67];
        if (addr.prefixLength > 0 && data.size() >= 72) {
            addr.prefix = (uint32_t(data[68]) << 24) |
                         (uint32_t(data[69]) << 16) |
                         (uint32_t(data[70]) << 8) |
                         uint32_t(data[71]);
        }
    }

    if (!addr.IsValid()) {
        return std::nullopt;
    }

    return addr;
}

} // namespace privacy
