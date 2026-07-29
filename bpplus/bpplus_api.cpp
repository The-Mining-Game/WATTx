// Implementation of the clean byte-buffer API over Monero's Bulletproofs+.
// Compiled inside the isolated wattx_bpplus lib, so it may use rct:: types freely;
// the public header (bpplus_api.h) exposes none of them.
#include "bpplus_api.h"

#include <vector>
#include <cstring>
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"
#include "ringct/bulletproofs_plus.h"

namespace {

// ---- minimal length-prefixed serialization for rct::BulletproofPlus ----
// Layout: [u32 nV][nV*32 V][A][A1][B][r1][s1][d1][u32 nL][nL*32 L][u32 nR][nR*32 R]
void put_u32(std::vector<uint8_t>& b, uint32_t v) {
    b.push_back(v & 0xFF); b.push_back((v >> 8) & 0xFF);
    b.push_back((v >> 16) & 0xFF); b.push_back((v >> 24) & 0xFF);
}
void put_key(std::vector<uint8_t>& b, const rct::key& k) {
    b.insert(b.end(), k.bytes, k.bytes + 32);
}
void put_keyv(std::vector<uint8_t>& b, const rct::keyV& v) {
    put_u32(b, (uint32_t)v.size());
    for (const auto& k : v) put_key(b, k);
}

struct Reader {
    const uint8_t* p; size_t n; size_t off = 0; bool ok = true;
    Reader(const uint8_t* p_, size_t n_) : p(p_), n(n_) {}
    uint32_t u32() {
        if (off + 4 > n) { ok = false; return 0; }
        uint32_t v = p[off] | (p[off+1] << 8) | (p[off+2] << 16) | ((uint32_t)p[off+3] << 24);
        off += 4; return v;
    }
    rct::key key() {
        rct::key k = rct::zero();
        if (off + 32 > n) { ok = false; return k; }
        std::memcpy(k.bytes, p + off, 32); off += 32; return k;
    }
    rct::keyV keyv(uint32_t cap) {
        rct::keyV v; uint32_t cnt = u32();
        if (!ok || cnt > cap) { ok = false; return v; }   // cap guards against huge allocs
        v.reserve(cnt);
        for (uint32_t i = 0; i < cnt && ok; i++) v.push_back(key());
        return v;
    }
};

std::vector<uint8_t> serialize(const rct::BulletproofPlus& p) {
    std::vector<uint8_t> b;
    put_keyv(b, p.V);
    put_key(b, p.A); put_key(b, p.A1); put_key(b, p.B);
    put_key(b, p.r1); put_key(b, p.s1); put_key(b, p.d1);
    put_keyv(b, p.L); put_keyv(b, p.R);
    return b;
}

// Returns false if malformed. cap limits vector sizes (proofs are small: V<=~16,
// L/R are ~log2 rounds, well under 64).
bool deserialize(const uint8_t* data, size_t len, rct::BulletproofPlus& p) {
    Reader r(data, len);
    p.V  = r.keyv(4096);
    p.A  = r.key(); p.A1 = r.key(); p.B = r.key();
    p.r1 = r.key(); p.s1 = r.key(); p.d1 = r.key();
    p.L  = r.keyv(64); p.R = r.keyv(64);
    return r.ok && r.off == len && !p.V.empty();
}

} // namespace

namespace wattx_bpplus {

int prove(const uint64_t* amounts, const uint8_t (*blindings)[32], size_t n,
          uint8_t* out, size_t out_cap, size_t* out_len) {
    if (!amounts || !blindings || !out || !out_len || n == 0) return -1;
    try {
        std::vector<uint64_t> vals(amounts, amounts + n);
        rct::keyV gammas(n);
        for (size_t i = 0; i < n; i++) std::memcpy(gammas[i].bytes, blindings[i], 32);
        rct::BulletproofPlus proof = rct::bulletproof_plus_PROVE(vals, gammas);
        std::vector<uint8_t> bytes = serialize(proof);
        if (bytes.size() > out_cap) { *out_len = bytes.size(); return -2; } // too small
        std::memcpy(out, bytes.data(), bytes.size());
        *out_len = bytes.size();
        return 0;
    } catch (...) { return -3; }
}

bool verify(const uint8_t* commitments, size_t n,
            const uint8_t* proof_bytes, size_t proof_len) {
    if (!commitments || !proof_bytes || n == 0) return false;
    try {
        rct::BulletproofPlus proof;
        if (!deserialize(proof_bytes, proof_len, proof)) return false;
        if (proof.V.size() != n) return false;
        // Each embedded commitment (after cofactor: 8*V[i]) must equal the caller's C[i].
        for (size_t i = 0; i < n; i++) {
            rct::key c8 = rct::scalarmult8(proof.V[i]);
            if (std::memcmp(c8.bytes, commitments + i * 32, 32) != 0) return false;
        }
        return rct::bulletproof_plus_VERIFY(proof);
    } catch (...) { return false; }
}

} // namespace wattx_bpplus
