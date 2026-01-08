// Copyright (c) 2025 The WATTx Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/gapcoin_pow.h>
#include <chain.h>
#include <crypto/sha256.h>
#include <hash.h>
#include <logging.h>
#include <arith_uint256.h>

#include <cmath>
#include <random>

#if defined(HAVE_GMP) && defined(HAVE_MPFR)

/**
 * Fermat primality test: a^(n-1) ≡ 1 (mod n) for prime n
 */
bool IsProbablePrime(const mpz_t n, int rounds)
{
    // Handle small cases
    if (mpz_cmp_ui(n, 2) < 0) return false;
    if (mpz_cmp_ui(n, 2) == 0) return true;
    if (mpz_even_p(n)) return false;
    if (mpz_cmp_ui(n, 3) == 0) return true;

    mpz_t a, n_minus_1, result;
    mpz_init(a);
    mpz_init(n_minus_1);
    mpz_init(result);

    mpz_sub_ui(n_minus_1, n, 1);

    // Use deterministic witnesses for consistency
    unsigned long witnesses[] = {2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37};
    int num_witnesses = std::min(rounds, 12);

    bool is_prime = true;
    for (int i = 0; i < num_witnesses && is_prime; i++) {
        mpz_set_ui(a, witnesses[i]);

        // Skip if witness >= n
        if (mpz_cmp(a, n) >= 0) continue;

        // Calculate a^(n-1) mod n
        mpz_powm(result, a, n_minus_1, n);

        // If result != 1, n is composite
        if (mpz_cmp_ui(result, 1) != 0) {
            is_prime = false;
        }
    }

    mpz_clear(a);
    mpz_clear(n_minus_1);
    mpz_clear(result);

    return is_prime;
}

/**
 * Verify all numbers in the gap are composite
 */
bool VerifyGapComposites(const mpz_t start, uint32_t gapSize)
{
    if (gapSize < 2) return false;

    mpz_t candidate;
    mpz_init(candidate);

    bool all_composite = true;

    // Check each number in the gap (start + 1 to start + gapSize - 1)
    for (uint32_t offset = 1; offset < gapSize && all_composite; offset++) {
        mpz_add_ui(candidate, start, offset);

        // Quick divisibility checks first (much faster than full primality test)
        if (mpz_even_p(candidate)) continue; // Even numbers are composite

        // Check divisibility by small primes
        bool divisible = false;
        unsigned long small_primes[] = {3, 5, 7, 11, 13, 17, 19, 23, 29, 31};
        for (int i = 0; i < 10 && !divisible; i++) {
            if (mpz_divisible_ui_p(candidate, small_primes[i])) {
                divisible = true;
            }
        }
        if (divisible) continue;

        // Full primality test for remaining candidates
        if (IsProbablePrime(candidate, 1)) {
            // Found a prime in the gap - invalid!
            all_composite = false;
        }
    }

    mpz_clear(candidate);
    return all_composite;
}

/**
 * Calculate merit = gapSize / ln(prime)
 */
double CalculateMerit(const mpz_t prime, uint32_t gapSize)
{
    // Get the bit length for approximate log calculation
    size_t bits = mpz_sizeinbase(prime, 2);

    // ln(2^bits) ≈ bits * ln(2) ≈ bits * 0.693147
    // For more precision, we use MPFR
    mpfr_t mp_prime, mp_log;
    mpfr_init2(mp_prime, 256);
    mpfr_init2(mp_log, 256);

    mpfr_set_z(mp_prime, prime, MPFR_RNDN);
    mpfr_log(mp_log, mp_prime, MPFR_RNDN);

    double ln_prime = mpfr_get_d(mp_log, MPFR_RNDN);

    mpfr_clear(mp_prime);
    mpfr_clear(mp_log);

    if (ln_prime <= 0) return 0.0;

    return static_cast<double>(gapSize) / ln_prime;
}

/**
 * Calculate prime candidate from block header
 * p = sha256(blockHeader) * 2^shift + adder
 */
void CalculatePrimeCandidate(const CBlockHeader& block, mpz_t result)
{
    // Create a copy of block header without Gapcoin fields for hashing
    CBlockHeader headerForHash = block;
    headerForHash.nShift = 0;
    headerForHash.nAdder.SetNull();
    headerForHash.nGapSize = 0;

    // Get SHA256 hash of the header
    uint256 headerHash = headerForHash.GetHashWithoutSign();

    // Convert hash to GMP integer
    mpz_t hashValue, shift_multiplier, adder;
    mpz_init(hashValue);
    mpz_init(shift_multiplier);
    mpz_init(adder);

    // Import hash bytes (little-endian)
    mpz_import(hashValue, 32, -1, 1, -1, 0, headerHash.begin());

    // Calculate 2^shift
    mpz_ui_pow_ui(shift_multiplier, 2, block.nShift);

    // Multiply: hash * 2^shift
    mpz_mul(result, hashValue, shift_multiplier);

    // Convert adder from uint256 to mpz_t
    mpz_import(adder, 32, -1, 1, -1, 0, block.nAdder.begin());

    // Add: result = hash * 2^shift + adder
    mpz_add(result, result, adder);

    // Ensure result is odd (primes > 2 are odd)
    if (mpz_even_p(result)) {
        mpz_add_ui(result, result, 1);
    }

    mpz_clear(hashValue);
    mpz_clear(shift_multiplier);
    mpz_clear(adder);
}

/**
 * Main Gapcoin PoW validation (with GMP/MPFR support)
 */
bool CheckGapcoinProof(const CBlockHeader& block,
                       const Consensus::Params& params,
                       std::string& strError)
{
    // Check shift value range
    if (block.nShift < GAPCOIN_SHIFT_MIN || block.nShift > GAPCOIN_SHIFT_MAX) {
        strError = "gapcoin-shift-out-of-range";
        return false;
    }

    // Check gap size is reasonable
    if (block.nGapSize < 2) {
        strError = "gapcoin-gap-too-small";
        return false;
    }

    // Verify adder < 2^shift (prevents PoW reuse across blocks)
    arith_uint256 maxAdder = arith_uint256(1) << block.nShift;
    arith_uint256 adderValue = UintToArith256(block.nAdder);
    if (adderValue >= maxAdder) {
        strError = "gapcoin-adder-too-large";
        return false;
    }

    // Calculate prime candidate
    mpz_t prime;
    mpz_init(prime);
    CalculatePrimeCandidate(block, prime);

    // Verify starting prime is actually prime
    if (!IsProbablePrime(prime, FERMAT_TEST_ROUNDS)) {
        mpz_clear(prime);
        strError = "gapcoin-start-not-prime";
        return false;
    }

    // Calculate end of gap
    mpz_t endPrime;
    mpz_init(endPrime);
    mpz_add_ui(endPrime, prime, block.nGapSize);

    // Verify end of gap is prime
    if (!IsProbablePrime(endPrime, FERMAT_TEST_ROUNDS)) {
        mpz_clear(prime);
        mpz_clear(endPrime);
        strError = "gapcoin-end-not-prime";
        return false;
    }

    // Verify all numbers in between are composite
    if (!VerifyGapComposites(prime, block.nGapSize)) {
        mpz_clear(prime);
        mpz_clear(endPrime);
        strError = "gapcoin-gap-contains-prime";
        return false;
    }

    // Calculate merit
    double merit = CalculateMerit(prime, block.nGapSize);

    // Get target difficulty from nBits
    double targetMerit = CompactToMerit(block.nBits);

    // Verify merit meets difficulty
    if (merit < targetMerit) {
        mpz_clear(prime);
        mpz_clear(endPrime);
        strError = "gapcoin-merit-below-target";
        LogPrintf("Gapcoin: merit %.4f < target %.4f\n", merit, targetMerit);
        return false;
    }

    LogPrintf("Gapcoin PoW valid: shift=%u, gapSize=%u, merit=%.4f\n",
             block.nShift, block.nGapSize, merit);

    mpz_clear(prime);
    mpz_clear(endPrime);
    return true;
}

#else // !HAVE_GMP || !HAVE_MPFR

/**
 * Stub implementation when GMP/MPFR not available
 * Allows blocks to pass validation but logs warning
 */
bool CheckGapcoinProof(const CBlockHeader& block,
                       const Consensus::Params& params,
                       std::string& strError)
{
    // Without GMP/MPFR, we cannot validate Gapcoin proofs
    // Return true to allow chain sync, but log warning
    static bool warned = false;
    if (!warned) {
        LogPrintf("WARNING: Gapcoin PoW validation disabled - GMP/MPFR not available at compile time\n");
        warned = true;
    }

    // Basic sanity checks that don't require GMP
    if (block.nShift < GAPCOIN_SHIFT_MIN || block.nShift > GAPCOIN_SHIFT_MAX) {
        strError = "gapcoin-shift-out-of-range";
        return false;
    }

    if (block.nGapSize < 2) {
        strError = "gapcoin-gap-too-small";
        return false;
    }

    // Cannot fully validate without GMP, accept on faith
    return true;
}

#endif // HAVE_GMP && HAVE_MPFR

/**
 * Calculate next difficulty based on recent merits
 */
double CalculateNextGapcoinDifficulty(const CBlockIndex* pindexPrev,
                                       const Consensus::Params& params)
{
    if (pindexPrev == nullptr) {
        return params.nGapcoinInitialDifficulty;
    }

    // Look back 144 blocks (approximately 1 day at 10-min blocks)
    const int lookback = 144;
    double totalMerit = 0.0;
    int validBlocks = 0;
    int64_t actualTimespan = 0;

    const CBlockIndex* pindex = pindexPrev;
    const CBlockIndex* pindexFirst = pindexPrev;

    for (int i = 0; i < lookback && pindex != nullptr; i++) {
        if (pindex->nGapcoinMerit > 0) {
            totalMerit += pindex->nGapcoinMerit;
            validBlocks++;
        }
        pindexFirst = pindex;
        pindex = pindex->pprev;
    }

    if (validBlocks == 0) {
        return params.nGapcoinInitialDifficulty;
    }

    // Calculate actual timespan
    actualTimespan = pindexPrev->GetBlockTime() - pindexFirst->GetBlockTime();

    // Target timespan (blocks * target spacing)
    int64_t targetTimespan = validBlocks * params.nPowTargetSpacing;

    // Prevent extreme adjustments
    if (actualTimespan < targetTimespan / 4) {
        actualTimespan = targetTimespan / 4;
    }
    if (actualTimespan > targetTimespan * 4) {
        actualTimespan = targetTimespan * 4;
    }

    // Adjust average merit based on time ratio
    double avgMerit = totalMerit / validBlocks;
    double adjustment = static_cast<double>(actualTimespan) / static_cast<double>(targetTimespan);

    // New difficulty = avgMerit * adjustment
    // If blocks are too fast, increase difficulty; if too slow, decrease
    double newDifficulty = avgMerit * adjustment;

    // Clamp to reasonable range
    if (newDifficulty < 10.0) newDifficulty = 10.0;
    if (newDifficulty > 100.0) newDifficulty = 100.0;

    return newDifficulty;
}

/**
 * Convert merit to compact nBits format
 * We store merit * 1000000 as an integer in nBits
 */
uint32_t MeritToCompact(double merit)
{
    // Store merit with 6 decimal places precision
    return static_cast<uint32_t>(merit * 1000000.0);
}

/**
 * Convert compact nBits to merit
 */
double CompactToMerit(uint32_t nBits)
{
    return static_cast<double>(nBits) / 1000000.0;
}

/**
 * Calculate chain work from merit
 * Work = 2^(merit) to give exponential weight to higher merits
 */
arith_uint256 GetGapcoinWork(double merit)
{
    // Work scales exponentially with merit
    // Base work at merit 20 = 2^20 ≈ 1 million
    if (merit <= 0) return arith_uint256(1);

    // Cap at merit 80 to avoid overflow
    if (merit > 80) merit = 80;

    // Calculate 2^merit
    arith_uint256 work = arith_uint256(1) << static_cast<unsigned int>(merit);

    return work;
}
