// Copyright (c) 2026 The WATTx Core developers
// Distributed under the MIT software license.

#include <crypto/kheavyhash/kheavyhash.h>

#include <randomx/src/blake2/blake2.h>

#include <cmath>
#include <cstring>

namespace kheavyhash {

namespace {

// ── keccak-f1600 (self-contained; ethash's is static-linkage) ────────────────
constexpr uint64_t RC[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL, 0x8000000080008000ULL,
    0x000000000000808bULL, 0x0000000080000001ULL, 0x8000000080008081ULL, 0x8000000000008009ULL,
    0x000000000000008aULL, 0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL, 0x8000000000008003ULL,
    0x8000000000008002ULL, 0x8000000000000080ULL, 0x000000000000800aULL, 0x800000008000000aULL,
    0x8000000080008081ULL, 0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL,
};
constexpr int RHO[24] = {1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14,
                         27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44};
constexpr int PI[24] = {10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4,
                        15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1};

inline uint64_t rotl64(uint64_t x, int n) { return (x << n) | (x >> (64 - n)); }

void f1600(uint64_t a[25]) {
    for (int round = 0; round < 24; round++) {
        uint64_t c[5], d;
        for (int x = 0; x < 5; x++) c[x] = a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20];
        for (int x = 0; x < 5; x++) {
            d = c[(x + 4) % 5] ^ rotl64(c[(x + 1) % 5], 1);
            for (int y = 0; y < 25; y += 5) a[x + y] ^= d;
        }
        uint64_t last = a[1];
        for (int i = 0; i < 24; i++) {
            uint64_t tmp = a[PI[i]];
            a[PI[i]] = rotl64(last, RHO[i]);
            last = tmp;
        }
        for (int y = 0; y < 25; y += 5) {
            uint64_t b[5];
            for (int x = 0; x < 5; x++) b[x] = a[y + x];
            for (int x = 0; x < 5; x++) a[y + x] = b[x] ^ (~b[(x + 1) % 5] & b[(x + 2) % 5]);
        }
        a[0] ^= RC[round];
    }
}

// cSHAKE256("ProofOfWorkHash") / cSHAKE256("HeavyHash") initial states with the
// single-block padding pre-XORed — inputs are 80B / 32B, well under the 136B
// rate, so each hash is exactly one permutation (rusty-kaspa pow_hashers.rs).
constexpr uint64_t POW_STATE[25] = {
    1242148031264380989ULL, 3008272977830772284ULL, 2188519011337848018ULL, 1992179434288343456ULL, 8876506674959887717ULL,
    5399642050693751366ULL, 1745875063082670864ULL, 8605242046444978844ULL, 17936695144567157056ULL, 3343109343542796272ULL,
    1123092876221303306ULL, 4963925045340115282ULL, 17037383077651887893ULL, 16629644495023626889ULL, 12833675776649114147ULL,
    3784524041015224902ULL, 1082795874807940378ULL, 13952716920571277634ULL, 13411128033953605860ULL, 15060696040649351053ULL,
    9928834659948351306ULL, 5237849264682708699ULL, 12825353012139217522ULL, 6706187291358897596ULL, 196324915476054915ULL,
};
constexpr uint64_t HEAVY_STATE[25] = {
    4239941492252378377ULL, 8746723911537738262ULL, 8796936657246353646ULL, 1272090201925444760ULL, 16654558671554924250ULL,
    8270816933120786537ULL, 13907396207649043898ULL, 6782861118970774626ULL, 9239690602118867528ULL, 11582319943599406348ULL,
    17596056728278508070ULL, 15212962468105129023ULL, 7812475424661425213ULL, 3370482334374859748ULL, 5690099369266491460ULL,
    8596393687355028144ULL, 570094237299545110ULL, 9119540418498120711ULL, 16901969272480492857ULL, 13372017233735502424ULL,
    14372891883993151831ULL, 5171152063242093102ULL, 10573107899694386186ULL, 6096431547456407061ULL, 1592359455985097269ULL,
};

inline uint64_t le64(const uint8_t* p) {
    uint64_t v;
    std::memcpy(&v, p, 8);
    return v;  // little-endian hosts only (matches the rest of the codebase)
}

// ── xoshiro256++ + heavy matrix (matrix.rs / xoshiro.rs) ─────────────────────
struct Xoshiro {
    uint64_t s0, s1, s2, s3;
    explicit Xoshiro(const uint8_t seed[32])
        : s0(le64(seed)), s1(le64(seed + 8)), s2(le64(seed + 16)), s3(le64(seed + 24)) {}
    uint64_t Next() {
        uint64_t res = s0 + rotl64(s0 + s3, 23);
        uint64_t t = s1 << 17;
        s2 ^= s0;
        s3 ^= s1;
        s1 ^= s2;
        s0 ^= s3;
        s2 ^= t;
        s3 = rotl64(s3, 45);
        return res;
    }
};

int MatrixRank(const uint16_t mat[64][64]) {
    constexpr double EPS = 1e-9;
    static thread_local double m[64][64];
    for (int i = 0; i < 64; i++)
        for (int j = 0; j < 64; j++) m[i][j] = static_cast<double>(mat[i][j]);
    int rank = 0;
    bool selected[64] = {false};
    for (int i = 0; i < 64; i++) {
        int j = 0;
        while (j < 64 && (selected[j] || std::abs(m[j][i]) <= EPS)) j++;
        if (j != 64) {
            rank++;
            selected[j] = true;
            for (int p = i + 1; p < 64; p++) m[j][p] /= m[j][i];
            for (int k = 0; k < 64; k++) {
                if (k != j && std::abs(m[k][i]) > EPS) {
                    for (int p = i + 1; p < 64; p++) m[k][p] -= m[j][p] * m[k][i];
                }
            }
        }
    }
    return rank;
}

void GenerateMatrix(const uint8_t pre_pow[32], uint16_t mat[64][64]) {
    Xoshiro gen(pre_pow);
    for (;;) {
        for (int i = 0; i < 64; i++) {
            for (int j = 0; j < 64; j += 16) {
                uint64_t val = gen.Next();
                for (int shift = 0; shift < 16; shift++)
                    mat[i][j + shift] = static_cast<uint16_t>((val >> (4 * shift)) & 0x0F);
            }
        }
        if (MatrixRank(mat) == 64) return;
    }
}

}  // namespace

void Blake2bKeyed(const char* key, const uint8_t* data, size_t len, uint8_t out[32]) {
    blake2b_state st;
    blake2b_init_key(&st, 32, key, std::strlen(key));
    blake2b_update(&st, data, len);
    blake2b_final(&st, out, 32);
}

void Pow(const uint8_t pre_pow[32], uint64_t timestamp, uint64_t nonce, uint8_t out[32]) {
    // cSHAKE256("ProofOfWorkHash") over PRE_POW_HASH || TIME || 32 zeros || NONCE
    uint64_t s[25];
    std::memcpy(s, POW_STATE, sizeof(s));
    for (int i = 0; i < 4; i++) s[i] ^= le64(pre_pow + 8 * i);
    s[4] ^= timestamp;
    s[9] ^= nonce;
    f1600(s);

    uint8_t pow32[32];
    std::memcpy(pow32, s, 32);

    // heavy matrix multiply on 4-bit nibbles, xor back, then cSHAKE256("HeavyHash")
    uint16_t mat[64][64];
    GenerateMatrix(pre_pow, mat);

    uint16_t vec[64];
    for (int i = 0; i < 32; i++) {
        vec[2 * i] = pow32[i] >> 4;
        vec[2 * i + 1] = pow32[i] & 0x0F;
    }
    uint8_t product[32];
    for (int i = 0; i < 32; i++) {
        uint16_t sum1 = 0, sum2 = 0;
        for (int j = 0; j < 64; j++) {
            sum1 += mat[2 * i][j] * vec[j];
            sum2 += mat[2 * i + 1][j] * vec[j];
        }
        product[i] = static_cast<uint8_t>(((sum1 >> 10) << 4) | (sum2 >> 10)) ^ pow32[i];
    }

    uint64_t h[25];
    std::memcpy(h, HEAVY_STATE, sizeof(h));
    for (int i = 0; i < 4; i++) h[i] ^= le64(product + 8 * i);
    f1600(h);
    std::memcpy(out, h, 32);
}

bool ParseHeaderPreimage(const uint8_t* d, size_t len, HeaderPreimageInfo& out) {
    if (len < 2 + 8) return false;
    uint64_t levels = le64(d + 2);
    if (levels > 64) return false;
    size_t pos = 10;
    for (uint64_t l = 0; l < levels; l++) {
        if (pos + 8 > len) return false;
        uint64_t count = le64(d + pos);
        if (count > 512) return false;
        pos += 8 + 32 * count;
        if (pos > len) return false;
    }
    // 3 roots + ts(8) + bits(4) + nonce(8) + daa(8) + blue(8) + bw_len(8)
    if (pos + 96 + 8 + 4 + 8 + 8 + 8 + 8 > len) return false;
    out.merkle_root_off = pos;
    out.ts_off = pos + 96;
    out.nonce_off = pos + 108;
    uint64_t bw_len = le64(d + pos + 132);
    if (bw_len > 64) return false;
    // exact total: fields above + blue_work bytes + 32B pruning point
    if (pos + 140 + bw_len + 32 != len) return false;
    return true;
}

bool PowFromPreimage(const std::vector<uint8_t>& preimage, uint8_t out[32]) {
    HeaderPreimageInfo info;
    if (!ParseHeaderPreimage(preimage.data(), preimage.size(), info)) return false;

    uint64_t timestamp = le64(preimage.data() + info.ts_off);
    uint64_t nonce = le64(preimage.data() + info.nonce_off);

    std::vector<uint8_t> zeroed = preimage;
    std::memset(zeroed.data() + info.ts_off, 0, 8);
    std::memset(zeroed.data() + info.nonce_off, 0, 8);

    uint8_t pre_pow[32];
    Blake2bKeyed("BlockHash", zeroed.data(), zeroed.size(), pre_pow);
    Pow(pre_pow, timestamp, nonce, out);
    return true;
}

void HeaderHash(const uint8_t* preimage, size_t len, uint8_t out[32]) {
    Blake2bKeyed("BlockHash", preimage, len, out);
}

void TransactionHash(const uint8_t* data, size_t len, uint8_t out[32]) {
    Blake2bKeyed("TransactionHash", data, len, out);
}

void MerkleFold(const uint8_t leaf[32],
                const std::vector<std::vector<uint8_t>>& branch,
                uint32_t index, uint8_t out[32]) {
    uint8_t current[32];
    std::memcpy(current, leaf, 32);
    for (const auto& sibling : branch) {
        uint8_t pair[64];
        if (sibling.size() != 32) {
            std::memset(out, 0xFF, 32);  // fail closed
            return;
        }
        if (index & 1) {
            std::memcpy(pair, sibling.data(), 32);
            std::memcpy(pair + 32, current, 32);
        } else {
            std::memcpy(pair, current, 32);
            std::memcpy(pair + 32, sibling.data(), 32);
        }
        Blake2bKeyed("MerkleBranchHash", pair, 64, current);
        index >>= 1;
    }
    std::memcpy(out, current, 32);
}

}  // namespace kheavyhash
