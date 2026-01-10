// Copyright (c) 2026 WATTx Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef WATTX_OPENCL_SIEVE_KERNEL_H
#define WATTX_OPENCL_SIEVE_KERNEL_H

// OpenCL kernel for prime sieving
// This kernel marks composite numbers in a sieve array using multiple small primes

static const char* SIEVE_KERNEL_SOURCE = R"(
// Sieve kernel - marks composite numbers
// Each work item handles one small prime
__kernel void sieve_segment(
    __global uchar* sieve,          // Output sieve array (bit array)
    __global const uint* primes,    // Small primes array
    const ulong segmentStart,       // Start offset of this segment
    const uint sieveSize,           // Size of sieve in bytes
    const uint numPrimes            // Number of primes to use
) {
    uint gid = get_global_id(0);
    if (gid >= numPrimes) return;

    uint p = primes[gid];
    if (p < 2) return;

    // Calculate first multiple of p in this segment
    ulong firstMultiple;
    if (segmentStart == 0) {
        firstMultiple = (ulong)p * p;  // Start from p^2
    } else {
        ulong remainder = segmentStart % p;
        if (remainder == 0) {
            firstMultiple = segmentStart;
        } else {
            firstMultiple = segmentStart + (p - remainder);
        }
        // Make sure we start at an odd multiple
        if (firstMultiple < (ulong)p * p) {
            firstMultiple = (ulong)p * p;
        }
    }

    // Convert to local index
    if (firstMultiple < segmentStart) return;
    ulong localStart = firstMultiple - segmentStart;
    ulong segmentBits = (ulong)sieveSize * 8;

    // Mark all multiples of p as composite
    for (ulong j = localStart; j < segmentBits; j += p) {
        uint byteIdx = j / 8;
        uint bitIdx = j % 8;
        atomic_or(&sieve[byteIdx], (uchar)(1 << bitIdx));
    }
}

// Gap finding kernel - finds gaps between primes
// Returns gap sizes for each starting position
__kernel void find_gaps(
    __global const uchar* sieve,    // Input sieve array
    __global uint* gaps,            // Output gap sizes
    __global uint* primePositions,  // Output prime positions
    const uint sieveSize,           // Size of sieve in bytes
    __global uint* gapCount         // Atomic counter for gaps found
) {
    uint gid = get_global_id(0);
    uint segmentBits = sieveSize * 8;

    // Each work item checks one byte
    if (gid >= sieveSize) return;

    uchar byte = sieve[gid];
    if (byte == 0xFF) return;  // All composite

    // Check each bit in this byte
    for (int bit = 0; bit < 8; bit++) {
        if ((byte & (1 << bit)) == 0) {
            // Found a probable prime
            uint pos = gid * 8 + bit;
            uint idx = atomic_inc(gapCount);
            if (idx < 65536) {  // Limit output size
                primePositions[idx] = pos;
            }
        }
    }
}

// Simple bit count kernel for statistics
__kernel void count_primes(
    __global const uchar* sieve,
    const uint sieveSize,
    __global uint* count
) {
    uint gid = get_global_id(0);
    if (gid >= sieveSize) return;

    uchar byte = sieve[gid];
    // Count zero bits (primes)
    uint primes = 0;
    for (int i = 0; i < 8; i++) {
        if ((byte & (1 << i)) == 0) primes++;
    }
    atomic_add(count, primes);
}
)";

#endif // WATTX_OPENCL_SIEVE_KERNEL_H
