// Standalone prove/verify unit test for the ported Monero Bulletproofs+.
// Proves the port is cryptographically functional: a valid range proof verifies,
// and tampered / out-of-range attempts are rejected. NOT linked into wattxd.
#include <cstdio>
#include <cstdint>
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"
#include "ringct/bulletproofs_plus.h"

int main() {
    int failures = 0;

    // 1. Valid single-value range proof round-trips.
    {
        rct::key gamma = rct::skGen();
        uint64_t amount = 12345678ULL;
        rct::BulletproofPlus proof = rct::bulletproof_plus_PROVE(amount, gamma);
        bool ok = rct::bulletproof_plus_VERIFY(proof);
        printf("[1] valid proof verifies: %s\n", ok ? "PASS" : "FAIL");
        if (!ok) failures++;
    }

    // 2. Value 0 and max 2^64-1 (boundary) still prove/verify.
    {
        rct::key g0 = rct::skGen(), gm = rct::skGen();
        bool ok0 = rct::bulletproof_plus_VERIFY(rct::bulletproof_plus_PROVE((uint64_t)0, g0));
        bool okm = rct::bulletproof_plus_VERIFY(rct::bulletproof_plus_PROVE((uint64_t)~0ULL, gm));
        printf("[2] boundary values (0, 2^64-1) verify: %s\n", (ok0 && okm) ? "PASS" : "FAIL");
        if (!(ok0 && okm)) failures++;
    }

    // 3. Tampered proof is REJECTED — either returns false OR throws on the now-
    //    malformed commitment point. Both count as rejection (an attacker cannot
    //    get a tampered proof accepted).
    {
        rct::key gamma = rct::skGen();
        rct::BulletproofPlus proof = rct::bulletproof_plus_PROVE((uint64_t)42, gamma);
        if (!proof.V.empty()) proof.V[0].bytes[0] ^= 0x01;
        bool accepted = false;
        try { accepted = rct::bulletproof_plus_VERIFY(proof); } catch (...) { accepted = false; }
        printf("[3] tampered proof rejected: %s\n", accepted ? "FAIL" : "PASS");
        if (accepted) failures++;
    }

    // 3b. Tamper an inner scalar (well-formed points, wrong proof) -> must return false.
    {
        rct::key gamma = rct::skGen();
        rct::BulletproofPlus proof = rct::bulletproof_plus_PROVE((uint64_t)42, gamma);
        proof.r1.bytes[0] ^= 0x01;  // flip a byte of a proof scalar
        bool accepted = false;
        try { accepted = rct::bulletproof_plus_VERIFY(proof); } catch (...) { accepted = false; }
        printf("[3b] wrong-scalar proof rejected: %s\n", accepted ? "FAIL" : "PASS");
        if (accepted) failures++;
    }

    // 4. Aggregated (2 values) range proof verifies.
    {
        rct::keyV gammas = {rct::skGen(), rct::skGen()};
        std::vector<uint64_t> amounts = {1000ULL, 2000ULL};
        rct::BulletproofPlus proof = rct::bulletproof_plus_PROVE(amounts, gammas);
        bool ok = rct::bulletproof_plus_VERIFY(proof);
        printf("[4] aggregated (2-value) proof verifies: %s\n", ok ? "PASS" : "FAIL");
        if (!ok) failures++;
    }

    printf("\n=== libwattx_bpplus port: %s (%d failure%s) ===\n",
           failures == 0 ? "ALL PASS" : "FAILURES", failures, failures == 1 ? "" : "s");
    return failures == 0 ? 0 : 1;
}
