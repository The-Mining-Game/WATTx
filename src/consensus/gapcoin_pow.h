// Copyright (c) 2025 The WATTx Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef WATTX_CONSENSUS_GAPCOIN_POW_H
#define WATTX_CONSENSUS_GAPCOIN_POW_H

#include <primitives/block.h>
#include <consensus/params.h>
#include <uint256.h>
#include <arith_uint256.h>

// Forward declaration
class CBlockIndex;

#include <string>
#include <vector>

// Forward declare GMP types if available
#ifdef HAVE_GMP
#include <gmp.h>
#endif

#ifdef HAVE_MPFR
#include <mpfr.h>
#endif

namespace Consensus {
    struct Params;
}

/**
 * Gapcoin Prime Gap Proof-of-Work
 *
 * This implements a "useful" proof-of-work based on finding large prime gaps.
 * A prime gap is the distance between two consecutive prime numbers.
 *
 * Algorithm:
 * 1. Calculate prime candidate: p = sha256(blockHeader) * 2^shift + adder
 * 2. Verify p is prime
 * 3. Verify p + gapSize is prime
 * 4. Verify all numbers between p and p + gapSize are composite
 * 5. Calculate merit = gapSize / ln(p)
 * 6. Verify merit >= target difficulty
 *
 * The merit measures how exceptional a gap is relative to the average gap
 * at that prime magnitude (Prime Number Theorem: average gap ~ ln(p)).
 */

/** Minimum shift value (controls search space) */
static constexpr uint32_t GAPCOIN_SHIFT_MIN = 14;

/** Maximum shift value */
static constexpr uint32_t GAPCOIN_SHIFT_MAX = 65536;

/** Default initial difficulty (merit target) */
static constexpr double GAPCOIN_INITIAL_DIFFICULTY = 20.0;

/** Number of Fermat test rounds for primality testing */
static constexpr int FERMAT_TEST_ROUNDS = 3;

#ifdef HAVE_GMP
/**
 * Check if a number is probably prime using Fermat's little theorem.
 * Faster than Miller-Rabin but with rare false positives.
 *
 * @param n The number to test (as GMP mpz_t)
 * @param rounds Number of test rounds (more = more accurate)
 * @return true if probably prime, false if definitely composite
 */
bool IsProbablePrime(const mpz_t n, int rounds = FERMAT_TEST_ROUNDS);

/**
 * Check if all numbers in range (start, end) exclusive are composite.
 * This verifies the prime gap is valid.
 *
 * @param start Start of gap (prime)
 * @param gapSize Size of the gap
 * @return true if all intermediate numbers are composite
 */
bool VerifyGapComposites(const mpz_t start, uint32_t gapSize);

/**
 * Calculate the merit of a prime gap.
 * Merit = gapSize / ln(prime)
 *
 * @param prime The starting prime of the gap
 * @param gapSize The size of the gap
 * @return The merit value
 */
double CalculateMerit(const mpz_t prime, uint32_t gapSize);

/**
 * Calculate the prime candidate from block header data.
 * p = sha256(blockHeaderWithoutGapcoinFields) * 2^shift + adder
 *
 * @param block The block header
 * @param result Output: the calculated prime candidate
 */
void CalculatePrimeCandidate(const CBlockHeader& block, mpz_t result);
#endif // HAVE_GMP

/**
 * Main Gapcoin proof-of-work validation function.
 *
 * Validates that:
 * 1. adder < 2^shift (prevents PoW reuse)
 * 2. The calculated prime candidate p is actually prime
 * 3. p + gapSize is also prime
 * 4. All numbers between p and p + gapSize are composite
 * 5. The merit meets the difficulty target
 *
 * @param block The block header to validate
 * @param params Consensus parameters
 * @param strError Output: error message if validation fails
 * @return true if the Gapcoin PoW is valid
 */
bool CheckGapcoinProof(const CBlockHeader& block,
                       const Consensus::Params& params,
                       std::string& strError);

/**
 * Calculate the next Gapcoin difficulty based on recent block merits.
 * Adjusts every block to maintain target block time.
 *
 * @param pindexPrev The previous block index
 * @param params Consensus parameters
 * @return The target merit for the next block
 */
double CalculateNextGapcoinDifficulty(const CBlockIndex* pindexPrev,
                                       const Consensus::Params& params);

/**
 * Convert merit to compact difficulty representation (nBits format).
 *
 * @param merit The merit value
 * @return Compact difficulty representation
 */
uint32_t MeritToCompact(double merit);

/**
 * Convert compact difficulty representation to merit.
 *
 * @param nBits Compact difficulty
 * @return Merit value
 */
double CompactToMerit(uint32_t nBits);

/**
 * Get the Gapcoin chain work contribution for a block.
 * Work is derived from the merit achieved.
 *
 * @param merit The block's merit
 * @return Chain work value
 */
arith_uint256 GetGapcoinWork(double merit);

#endif // WATTX_CONSENSUS_GAPCOIN_POW_H
