// Copyright (c) 2024-2026 The WATTx Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <privacy/ed25519/pedersen.h>

#include <crypto/sha512.h>

#include <stdexcept>
#include <mutex>

namespace ed25519 {

// ============================================================================
// PedersenGenerators Implementation
// ============================================================================

PedersenGenerators::PedersenGenerators()
    : m_seed("WATTx_FCMP_Pedersen_Generators_v1") {
    // G is the Ed25519 base point
    m_G = Point::BasePoint();

    // H is derived by hashing G
    // H is MONERO's value generator (H = keccak256(G) -> point -> *cofactor), hardcoded
    // as its compressed bytes so C++ Pedersen commitments match the ported Monero
    // Bulletproofs+ (rct::H) and the Rust fcmp_pedersen_commit EXACTLY. Was a custom
    // HashToPoint H — inconsistent with the range proof and the wallet, which is the
    // whole reason the FCMP amount layer couldn't verify. Do not change.
    static const uint8_t MONERO_H[32] = {
        0x8b,0x65,0x59,0x70,0x15,0x37,0x99,0xaf,0x2a,0xea,0xdc,0x9f,0xf1,0xad,0xd0,0xea,
        0x6c,0x72,0x51,0xd5,0x41,0x54,0xcf,0xa9,0x2c,0x17,0x3a,0x0d,0xd3,0x9c,0x1f,0x94};
    m_H = Point(MONERO_H);

    // Pre-generate some vector generators
    DeriveGenerators(64);
}

PedersenGenerators::PedersenGenerators(const std::string& seed)
    : m_seed(seed) {
    m_G = Point::BasePoint();

    // H is MONERO's value generator (H = keccak256(G) -> point -> *cofactor), hardcoded
    // as its compressed bytes so C++ Pedersen commitments match the ported Monero
    // Bulletproofs+ (rct::H) and the Rust fcmp_pedersen_commit EXACTLY. Was a custom
    // HashToPoint H — inconsistent with the range proof and the wallet, which is the
    // whole reason the FCMP amount layer couldn't verify. Do not change.
    static const uint8_t MONERO_H[32] = {
        0x8b,0x65,0x59,0x70,0x15,0x37,0x99,0xaf,0x2a,0xea,0xdc,0x9f,0xf1,0xad,0xd0,0xea,
        0x6c,0x72,0x51,0xd5,0x41,0x54,0xcf,0xa9,0x2c,0x17,0x3a,0x0d,0xd3,0x9c,0x1f,0x94};
    m_H = Point(MONERO_H);

    DeriveGenerators(64);
}

void PedersenGenerators::DeriveGenerators(size_t n) {
    while (m_G_bold.size() < n) {
        // Derive G_i by hashing seed with index
        std::vector<uint8_t> gi_seed;
        gi_seed.insert(gi_seed.end(), m_seed.begin(), m_seed.end());
        gi_seed.push_back('G');

        // Add index as little-endian bytes
        uint64_t idx = m_G_bold.size();
        for (int i = 0; i < 8; ++i) {
            gi_seed.push_back(idx & 0xFF);
            idx >>= 8;
        }

        m_G_bold.push_back(Point::HashToPoint(gi_seed));
    }
}

const Point& PedersenGenerators::G_bold(size_t i) const {
    if (i >= m_G_bold.size()) {
        throw std::out_of_range("Generator index out of range");
    }
    return m_G_bold[i];
}

void PedersenGenerators::EnsureGenerators(size_t n) {
    if (m_G_bold.size() < n) {
        DeriveGenerators(n);
    }
}

static std::mutex g_default_generators_mutex;
static std::unique_ptr<PedersenGenerators> g_default_generators;

PedersenGenerators& PedersenGenerators::Default() {
    std::lock_guard<std::mutex> lock(g_default_generators_mutex);
    if (!g_default_generators) {
        g_default_generators = std::make_unique<PedersenGenerators>();
    }
    return *g_default_generators;
}

// ============================================================================
// PedersenCommitment Implementation
// ============================================================================

PedersenCommitment PedersenCommitment::Commit(const Scalar& value) {
    return Commit(value, Scalar::Random());
}

PedersenCommitment PedersenCommitment::Commit(const Scalar& value, const Scalar& blinding) {
    PedersenGenerators& gens = PedersenGenerators::Default();

    // C = v*H + r*G  (Monero convention: VALUE on H, BLINDING on G). This matches
    // Monero Bulletproofs+ and fcmp_pedersen_commit, so a commitment made here can be
    // range-proven and balance-checked consistently. (Was v*G + r*H — reversed.)
    Point vH = gens.H() * value;
    Point rG = gens.G() * blinding;

    return PedersenCommitment(vH + rG);
}

PedersenCommitment PedersenCommitment::CommitAmount(uint64_t amount) {
    return Commit(Scalar(amount));
}

PedersenCommitment PedersenCommitment::CommitAmount(uint64_t amount, const Scalar& blinding) {
    return Commit(Scalar(amount), blinding);
}

PedersenCommitment PedersenCommitment::operator+(const PedersenCommitment& other) const {
    return PedersenCommitment(commitment + other.commitment);
}

PedersenCommitment PedersenCommitment::operator-(const PedersenCommitment& other) const {
    return PedersenCommitment(commitment - other.commitment);
}

PedersenCommitment& PedersenCommitment::operator+=(const PedersenCommitment& other) {
    commitment += other.commitment;
    return *this;
}

PedersenCommitment& PedersenCommitment::operator-=(const PedersenCommitment& other) {
    commitment -= other.commitment;
    return *this;
}

PedersenCommitment PedersenCommitment::operator*(const Scalar& s) const {
    return PedersenCommitment(commitment * s);
}

bool PedersenCommitment::operator==(const PedersenCommitment& other) const {
    return commitment == other.commitment;
}

// ============================================================================
// PedersenVectorCommitment Implementation
// ============================================================================

PedersenVectorCommitment PedersenVectorCommitment::Commit(const std::vector<Scalar>& values) {
    return Commit(values, Scalar::Random());
}

PedersenVectorCommitment PedersenVectorCommitment::Commit(const std::vector<Scalar>& values, const Scalar& blinding) {
    if (values.empty()) {
        // Just the blinding: r*H
        return PedersenVectorCommitment(PedersenGenerators::Default().H() * blinding);
    }

    PedersenGenerators& gens = PedersenGenerators::Default();
    gens.EnsureGenerators(values.size());

    // C = v1*G1 + v2*G2 + ... + vn*Gn + r*H
    std::vector<Scalar> scalars;
    std::vector<Point> points;

    for (size_t i = 0; i < values.size(); ++i) {
        scalars.push_back(values[i]);
        points.push_back(gens.G_bold(i));
    }

    // Add blinding term
    scalars.push_back(blinding);
    points.push_back(gens.H());

    return PedersenVectorCommitment(MultiScalarMul(scalars, points));
}

PedersenVectorCommitment PedersenVectorCommitment::operator+(const PedersenVectorCommitment& other) const {
    return PedersenVectorCommitment(commitment + other.commitment);
}

PedersenVectorCommitment PedersenVectorCommitment::operator-(const PedersenVectorCommitment& other) const {
    return PedersenVectorCommitment(commitment - other.commitment);
}

bool PedersenVectorCommitment::operator==(const PedersenVectorCommitment& other) const {
    return commitment == other.commitment;
}

// ============================================================================
// PedersenOpening Implementation
// ============================================================================

bool PedersenOpening::Verify(const PedersenCommitment& commitment) const {
    return Verify(commitment, PedersenGenerators::Default());
}

bool PedersenOpening::Verify(const PedersenCommitment& commitment, const PedersenGenerators& gens) const {
    // Check: C == v*H + r*G  (must match Commit's Monero convention above).
    Point expected = gens.H() * value + gens.G() * blinding;
    return expected == commitment.GetPoint();
}

bool PedersenVectorOpening::Verify(const PedersenVectorCommitment& commitment) const {
    return Verify(commitment, PedersenGenerators::Default());
}

bool PedersenVectorOpening::Verify(const PedersenVectorCommitment& commitment, const PedersenGenerators& gens) const {
    if (values.empty()) {
        Point expected = gens.H() * blinding;
        return expected == commitment.GetPoint();
    }

    const_cast<PedersenGenerators&>(gens).EnsureGenerators(values.size());

    std::vector<Scalar> scalars;
    std::vector<Point> points;

    for (size_t i = 0; i < values.size(); ++i) {
        scalars.push_back(values[i]);
        points.push_back(gens.G_bold(i));
    }
    scalars.push_back(blinding);
    points.push_back(gens.H());

    Point expected = MultiScalarMul(scalars, points);
    return expected == commitment.GetPoint();
}

// ============================================================================
// PedersenHash Implementation
// ============================================================================

PedersenHash::PedersenHash()
    : m_generators("WATTx_FCMP_CurveTree_v1") {
    // Derive initialization point
    std::vector<uint8_t> init_seed;
    std::string seed = "WATTx_FCMP_CurveTree_Init_v1";
    init_seed.insert(init_seed.end(), seed.begin(), seed.end());
    m_init = Point::HashToPoint(init_seed);
}

PedersenHash::PedersenHash(const std::string& seed)
    : m_generators(seed) {
    std::vector<uint8_t> init_seed;
    init_seed.insert(init_seed.end(), seed.begin(), seed.end());
    init_seed.push_back('I'); // Init marker
    m_init = Point::HashToPoint(init_seed);
}

Point PedersenHash::Hash(const std::vector<Scalar>& inputs) const {
    if (inputs.empty()) {
        return m_init;
    }

    const_cast<PedersenGenerators&>(m_generators).EnsureGenerators(inputs.size());

    // H(inputs) = H_init + sum(input[i] * G[i])
    std::vector<Scalar> scalars = inputs;
    std::vector<Point> points;

    for (size_t i = 0; i < inputs.size(); ++i) {
        points.push_back(m_generators.G_bold(i));
    }

    return m_init + MultiScalarMul(scalars, points);
}

Point PedersenHash::HashGrow(const Point& existing, size_t offset,
                              const Scalar& existing_at_offset,
                              const std::vector<Scalar>& new_elements) const {
    if (new_elements.empty()) {
        return existing;
    }

    const_cast<PedersenGenerators&>(m_generators).EnsureGenerators(offset + new_elements.size());

    // Add: (new[0] - existing_at_offset)*G[offset] + new[1]*G[offset+1] + ...
    std::vector<Scalar> scalars;
    std::vector<Point> points;

    // First element replaces existing at offset
    scalars.push_back(new_elements[0] - existing_at_offset);
    points.push_back(m_generators.G_bold(offset));

    // Remaining elements are additions
    for (size_t i = 1; i < new_elements.size(); ++i) {
        scalars.push_back(new_elements[i]);
        points.push_back(m_generators.G_bold(offset + i));
    }

    return existing + MultiScalarMul(scalars, points);
}

Point PedersenHash::HashTrim(const Point& existing, size_t offset,
                              const std::vector<Scalar>& elements_to_remove,
                              const Scalar& element_to_grow_back) const {
    if (elements_to_remove.empty()) {
        return existing;
    }

    const_cast<PedersenGenerators&>(m_generators).EnsureGenerators(offset + elements_to_remove.size());

    // Remove: -(elem[0] - grow_back)*G[offset] - elem[1]*G[offset+1] - ...
    std::vector<Scalar> scalars;
    std::vector<Point> points;

    // First element: subtract difference from grow_back
    scalars.push_back(elements_to_remove[0] - element_to_grow_back);
    points.push_back(m_generators.G_bold(offset));

    // Remaining elements are subtractions
    for (size_t i = 1; i < elements_to_remove.size(); ++i) {
        scalars.push_back(elements_to_remove[i]);
        points.push_back(m_generators.G_bold(offset + i));
    }

    return existing - MultiScalarMul(scalars, points);
}

} // namespace ed25519
