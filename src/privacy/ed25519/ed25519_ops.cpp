// Copyright (c) 2024-2026 The WATTx Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <privacy/ed25519/ed25519_types.h>

#include <crypto/sha512.h>
#include <util/strencodings.h>

#include <sodium.h>

#include <cassert>
#include <cstring>
#include <stdexcept>

namespace ed25519 {

// ============================================================================
// Initialization
// ============================================================================

namespace {

class SodiumInit {
public:
    SodiumInit() {
        if (sodium_init() < 0) {
            throw std::runtime_error("Failed to initialize libsodium");
        }
    }
};

// Ensure sodium is initialized before any operations
static SodiumInit g_sodium_init;

} // anonymous namespace

// ============================================================================
// Scalar Implementation
// ============================================================================

Scalar::Scalar(uint64_t value) {
    data.fill(0);
    // Little-endian encoding
    for (int i = 0; i < 8 && value; ++i) {
        data[i] = value & 0xFF;
        value >>= 8;
    }
}

Scalar Scalar::One() {
    return Scalar(1);
}

Scalar Scalar::Random() {
    Scalar result;
    crypto_core_ed25519_scalar_random(result.data.data());
    return result;
}

Scalar Scalar::FromBytesModOrder(const uint8_t* bytes, size_t len) {
    Scalar result;
    if (len == 32) {
        // crypto_core_ed25519_scalar_reduce requires 64-byte input;
        // zero-pad 32-byte input to avoid reading stack garbage
        std::array<uint8_t, 64> padded{};
        std::memcpy(padded.data(), bytes, 32);
        crypto_core_ed25519_scalar_reduce(result.data.data(), padded.data());
        sodium_memzero(padded.data(), 64);
    } else if (len == 64) {
        // 64-byte input for hash outputs
        crypto_core_ed25519_scalar_reduce(result.data.data(), bytes);
    } else {
        // Hash to 64 bytes first, then reduce
        std::array<uint8_t, 64> hash;
        CSHA512 hasher;
        hasher.Write(bytes, len);
        hasher.Finalize(hash.data());
        crypto_core_ed25519_scalar_reduce(result.data.data(), hash.data());
        sodium_memzero(hash.data(), 64);
    }
    return result;
}

Scalar Scalar::FromBytesModOrder(const std::vector<uint8_t>& bytes) {
    return FromBytesModOrder(bytes.data(), bytes.size());
}

Scalar Scalar::operator+(const Scalar& other) const {
    Scalar result;
    crypto_core_ed25519_scalar_add(result.data.data(), data.data(), other.data.data());
    return result;
}

Scalar Scalar::operator-(const Scalar& other) const {
    Scalar result;
    crypto_core_ed25519_scalar_sub(result.data.data(), data.data(), other.data.data());
    return result;
}

Scalar Scalar::operator*(const Scalar& other) const {
    Scalar result;
    crypto_core_ed25519_scalar_mul(result.data.data(), data.data(), other.data.data());
    return result;
}

Scalar Scalar::operator-() const {
    Scalar result;
    crypto_core_ed25519_scalar_negate(result.data.data(), data.data());
    return result;
}

Scalar& Scalar::operator+=(const Scalar& other) {
    crypto_core_ed25519_scalar_add(data.data(), data.data(), other.data.data());
    return *this;
}

Scalar& Scalar::operator-=(const Scalar& other) {
    crypto_core_ed25519_scalar_sub(data.data(), data.data(), other.data.data());
    return *this;
}

Scalar& Scalar::operator*=(const Scalar& other) {
    crypto_core_ed25519_scalar_mul(data.data(), data.data(), other.data.data());
    return *this;
}

bool Scalar::operator==(const Scalar& other) const {
    return sodium_memcmp(data.data(), other.data.data(), SCALAR_SIZE) == 0;
}

bool Scalar::IsZero() const {
    return sodium_is_zero(data.data(), SCALAR_SIZE);
}

Scalar Scalar::Invert() const {
    Scalar result;
    if (crypto_core_ed25519_scalar_invert(result.data.data(), data.data()) != 0) {
        // Input was zero, return zero
        return Scalar::Zero();
    }
    return result;
}

std::vector<uint8_t> Scalar::GetBytes() const {
    return std::vector<uint8_t>(data.begin(), data.end());
}

std::string Scalar::GetHex() const {
    return HexStr(data);
}

void Scalar::Clear() {
    sodium_memzero(data.data(), SCALAR_SIZE);
}

// ============================================================================
// Point Implementation
// ============================================================================

Point Point::Identity() {
    Point result;
    // The identity point in Ed25519 compressed form is (0, 1)
    // which encodes to 0x01 followed by 31 zero bytes
    result.data.fill(0);
    result.data[0] = 0x01;
    return result;
}

Point Point::BasePoint() {
    Point result;
    // Get the base point by multiplying identity scalar (1) with base
    Scalar one = Scalar::One();
    if (crypto_scalarmult_ed25519_base_noclamp(result.data.data(), one.data.data()) != 0) {
        throw std::runtime_error("Failed to compute Ed25519 base point");
    }
    return result;
}

Point Point::Random() {
    Scalar s = Scalar::Random();
    Point result;
    if (crypto_scalarmult_ed25519_base_noclamp(result.data.data(), s.data.data()) != 0) {
        throw std::runtime_error("Failed to generate random Ed25519 point");
    }
    return result;
}

Point Point::HashToPoint(const uint8_t* data, size_t len) {
    Point result;
    // Use libsodium's hash-to-point (Elligator 2)
    if (crypto_core_ed25519_from_uniform(result.data.data(), data) != 0) {
        // If input is not 32 bytes, hash it first
        std::array<uint8_t, 64> hash;
        CSHA512 hasher;
        hasher.Write(data, len);
        hasher.Finalize(hash.data());

        if (crypto_core_ed25519_from_uniform(result.data.data(), hash.data()) != 0) {
            throw std::runtime_error("Failed to hash to Ed25519 point");
        }
        sodium_memzero(hash.data(), 64);
    }
    return result;
}

Point Point::HashToPoint(const std::vector<uint8_t>& data) {
    // Hash to 64 bytes first for uniformity
    std::array<uint8_t, 64> hash;
    CSHA512 hasher;
    hasher.Write(data.data(), data.size());
    hasher.Finalize(hash.data());

    Point result;
    if (crypto_core_ed25519_from_uniform(result.data.data(), hash.data()) != 0) {
        throw std::runtime_error("Failed to hash to Ed25519 point");
    }
    sodium_memzero(hash.data(), 64);
    return result;
}

Point Point::operator+(const Point& other) const {
    Point result;
    if (crypto_core_ed25519_add(result.data.data(), data.data(), other.data.data()) != 0) {
        throw std::runtime_error("Ed25519 point addition failed");
    }
    return result;
}

Point Point::operator-(const Point& other) const {
    Point result;
    if (crypto_core_ed25519_sub(result.data.data(), data.data(), other.data.data()) != 0) {
        throw std::runtime_error("Ed25519 point subtraction failed");
    }
    return result;
}

Point Point::operator-() const {
    // Negate by subtracting from identity
    return Identity() - *this;
}

Point& Point::operator+=(const Point& other) {
    if (crypto_core_ed25519_add(data.data(), data.data(), other.data.data()) != 0) {
        throw std::runtime_error("Ed25519 point addition failed");
    }
    return *this;
}

Point& Point::operator-=(const Point& other) {
    if (crypto_core_ed25519_sub(data.data(), data.data(), other.data.data()) != 0) {
        throw std::runtime_error("Ed25519 point subtraction failed");
    }
    return *this;
}

Point Point::operator*(const Scalar& scalar) const {
    Point result;
    if (crypto_scalarmult_ed25519_noclamp(result.data.data(), scalar.data.data(), data.data()) != 0) {
        // Result might be identity
        return Identity();
    }
    return result;
}

bool Point::operator==(const Point& other) const {
    return sodium_memcmp(data.data(), other.data.data(), POINT_SIZE) == 0;
}

bool Point::IsIdentity() const {
    return *this == Identity();
}

bool Point::IsValid() const {
    return crypto_core_ed25519_is_valid_point(data.data()) == 1;
}

std::vector<uint8_t> Point::GetBytes() const {
    return std::vector<uint8_t>(data.begin(), data.end());
}

std::string Point::GetHex() const {
    return HexStr(data);
}

bool Point::GetXY(Scalar& x, Scalar& y) const {
    // Ed25519 compressed format: y coordinate with x sign bit
    // y is the first 255 bits, x sign is bit 255

    // For FCMP we need the actual x,y coordinates
    // This requires decompression which libsodium doesn't directly expose
    // We'll compute it manually

    // Copy y (clear the sign bit)
    std::memcpy(y.data.data(), data.data(), 32);
    y.data[31] &= 0x7F;

    // x sign bit
    bool x_sign = (data[31] >> 7) != 0;

    // Compute x from curve equation: x^2 = (y^2 - 1) / (d*y^2 + 1)
    // where d = -121665/121666
    // This is complex - for now return false and use alternative approach
    // In production, implement full decompression or use extended coordinates

    // TODO: Implement full point decompression for coordinate extraction
    return false;
}

void Point::Clear() {
    sodium_memzero(data.data(), POINT_SIZE);
}

// ============================================================================
// Multi-Scalar Multiplication
// ============================================================================

Point MultiScalarMul(const std::vector<Scalar>& scalars, const std::vector<Point>& points) {
    if (scalars.size() != points.size()) {
        throw std::runtime_error("MultiScalarMul: mismatched sizes");
    }
    if (scalars.empty()) {
        return Point::Identity();
    }

    // Simple implementation: sum of individual products
    // TODO: Implement Pippenger's algorithm for better performance
    Point result = Point::Identity();
    for (size_t i = 0; i < scalars.size(); ++i) {
        result += points[i] * scalars[i];
    }
    return result;
}

Point DoubleScalarMulBase(const Scalar& a, const Scalar& b, const Point& P) {
    // Compute a*G + b*P where G is base point
    Point aG;
    if (crypto_scalarmult_ed25519_base_noclamp(aG.data.data(), a.data.data()) != 0) {
        aG = Point::Identity();
    }

    Point bP = P * b;
    return aG + bP;
}

// ============================================================================
// KeyPair Implementation
// ============================================================================

KeyPair KeyPair::Generate() {
    KeyPair kp;
    kp.secret = Scalar::Random();
    if (crypto_scalarmult_ed25519_base_noclamp(kp.public_key.data.data(), kp.secret.data.data()) != 0) {
        throw std::runtime_error("Failed to generate Ed25519 key pair");
    }
    return kp;
}

KeyPair KeyPair::FromSeed(const uint8_t* seed) {
    KeyPair kp;

    // Hash seed to get scalar
    std::array<uint8_t, 64> hash;
    CSHA512 hasher;
    hasher.Write(seed, SEED_SIZE);
    hasher.Write(reinterpret_cast<const uint8_t*>("ed25519_key"), 11);
    hasher.Finalize(hash.data());

    crypto_core_ed25519_scalar_reduce(kp.secret.data.data(), hash.data());
    sodium_memzero(hash.data(), 64);

    if (crypto_scalarmult_ed25519_base_noclamp(kp.public_key.data.data(), kp.secret.data.data()) != 0) {
        throw std::runtime_error("Failed to derive Ed25519 public key");
    }

    return kp;
}

KeyPair KeyPair::FromSeed(const std::array<uint8_t, SEED_SIZE>& seed) {
    return FromSeed(seed.data());
}

// ============================================================================
// Signature Implementation
// ============================================================================

Signature Signature::Sign(const KeyPair& keypair, const uint8_t* msg, size_t len) {
    Signature sig;

    // Use Schnorr-style signing compatible with arbitrary scalars
    // r = random scalar
    // R = r * G
    // e = H(R || pubkey || msg)
    // s = r + e * secret

    Scalar r = Scalar::Random();
    Point R;
    if (crypto_scalarmult_ed25519_base_noclamp(R.data.data(), r.data.data()) != 0) {
        throw std::runtime_error("Ed25519 signing failed: R computation");
    }

    // Compute challenge e = H(R || pubkey || msg)
    std::vector<uint8_t> hash_input;
    hash_input.insert(hash_input.end(), R.data.begin(), R.data.end());
    hash_input.insert(hash_input.end(), keypair.public_key.data.begin(), keypair.public_key.data.end());
    hash_input.insert(hash_input.end(), msg, msg + len);

    Scalar e = Scalar::FromBytesModOrder(hash_input);

    // s = r + e * secret
    Scalar s = r + e * keypair.secret;

    // Signature is (R, s)
    std::memcpy(sig.data.data(), R.data.data(), 32);
    std::memcpy(sig.data.data() + 32, s.data.data(), 32);

    r.Clear();
    return sig;
}

Signature Signature::Sign(const KeyPair& keypair, const std::vector<uint8_t>& msg) {
    return Sign(keypair, msg.data(), msg.size());
}

bool Signature::Verify(const Point& public_key, const uint8_t* msg, size_t len) const {
    // Extract R and s from signature
    Point R;
    Scalar s;
    std::memcpy(R.data.data(), data.data(), 32);
    std::memcpy(s.data.data(), data.data() + 32, 32);

    // Verify R is a valid point
    if (!R.IsValid()) {
        return false;
    }

    // Compute challenge e = H(R || pubkey || msg)
    std::vector<uint8_t> hash_input;
    hash_input.insert(hash_input.end(), R.data.begin(), R.data.end());
    hash_input.insert(hash_input.end(), public_key.data.begin(), public_key.data.end());
    hash_input.insert(hash_input.end(), msg, msg + len);

    Scalar e = Scalar::FromBytesModOrder(hash_input);

    // Verify: s * G == R + e * pubkey
    Point sG;
    if (crypto_scalarmult_ed25519_base_noclamp(sG.data.data(), s.data.data()) != 0) {
        return false;
    }

    Point R_plus_eP = R + (public_key * e);

    return sG == R_plus_eP;
}

bool Signature::Verify(const Point& public_key, const std::vector<uint8_t>& msg) const {
    return Verify(public_key, msg.data(), msg.size());
}

std::vector<uint8_t> Signature::GetBytes() const {
    return std::vector<uint8_t>(data.begin(), data.end());
}

} // namespace ed25519
