// Exercises the clean byte-buffer wrapper (bpplus_api.h): prove -> verify through
// the public interface, plus the commitment-match and negative cases that matter
// for consensus (wrong commitment, tampered proof, wrong count).
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <vector>
#include "bpplus_api.h"
// rct only for test setup (compute the same commitments a wallet would):
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"

int main() {
    int fail = 0;
    const size_t n = 3;
    uint64_t amounts[n] = {5ULL, 250000ULL, 0xFFFFFFFFFFFFFFFFULL};
    uint8_t blindings[n][32];
    uint8_t commitments[n * 32];

    // Wallet-equivalent: gamma = random scalar; C = commit(amount, gamma) = a*H + gamma*G.
    for (size_t i = 0; i < n; i++) {
        rct::key gamma = rct::skGen();
        std::memcpy(blindings[i], gamma.bytes, 32);
        rct::key C = rct::commit(amounts[i], gamma);
        std::memcpy(commitments + i * 32, C.bytes, 32);
    }

    // prove
    uint8_t proof[4096]; size_t plen = 0;
    int pr = wattx_bpplus::prove(amounts, blindings, n, proof, sizeof(proof), &plen);
    printf("[1] prove ok (rc=%d, %zu bytes): %s\n", pr, plen, pr == 0 ? "PASS" : "FAIL");
    if (pr != 0) { printf("cannot continue\n"); return 1; }

    // verify with correct commitments -> true
    bool v1 = wattx_bpplus::verify(commitments, n, proof, plen);
    printf("[2] verify(correct commitments): %s\n", v1 ? "PASS" : "FAIL");
    if (!v1) fail++;

    // wrong commitment (flip a byte of C[1]) -> false (proof no longer matches C)
    {
        uint8_t bad[n * 32]; std::memcpy(bad, commitments, sizeof(bad));
        bad[1 * 32] ^= 0x01;
        bool v = wattx_bpplus::verify(bad, n, proof, plen);
        printf("[3] verify(wrong commitment) rejected: %s\n", v ? "FAIL" : "PASS");
        if (v) fail++;
    }

    // tampered proof -> false
    {
        uint8_t bad[4096]; std::memcpy(bad, proof, plen);
        bad[plen / 2] ^= 0x01;
        bool v = wattx_bpplus::verify(commitments, n, bad, plen);
        printf("[4] verify(tampered proof) rejected: %s\n", v ? "FAIL" : "PASS");
        if (v) fail++;
    }

    // wrong count -> false
    {
        bool v = wattx_bpplus::verify(commitments, n - 1, proof, plen);
        printf("[5] verify(wrong count) rejected: %s\n", v ? "FAIL" : "PASS");
        if (v) fail++;
    }

    // truncated / garbage proof -> false (no crash)
    {
        bool v = wattx_bpplus::verify(commitments, n, proof, plen / 2);
        printf("[6] verify(truncated proof) rejected: %s\n", v ? "FAIL" : "PASS");
        if (v) fail++;
    }

    printf("\n=== bpplus_api wrapper: %s (%d failure%s) ===\n",
           fail == 0 ? "ALL PASS" : "FAILURES", fail, fail == 1 ? "" : "s");
    return fail == 0 ? 0 : 1;
}
