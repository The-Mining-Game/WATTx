// Copyright (c) 2026 The WATTx Core developers
// Distributed under the MIT software license.
//
// Canonical Zcash/BitcoinZ Equihash solution validator, parameterized for any
// (n,k). Matches the reference algorithm from btcz/bitcoinz and zcash exactly:
// ExpandArray + Blake2b(person="ZcashPoW"|"BitcoinZ", n, k) + Wagner-tree check
// (collision, ordering, distinctness, final XOR == 0). Verified against a real
// BitcoinZ 48,5 block. Unlike src/crypto/equihash/equihash.cpp (hardcoded 200,9
// and non-canonical GenerateHash), this validates real parent-chain blocks and
// is the one the X11-style merged-mining parent path must use.

#ifndef BITCOIN_CRYPTO_EQUIHASH_EQUIHASH_CANON_H
#define BITCOIN_CRYPTO_EQUIHASH_EQUIHASH_CANON_H

#include <cstddef>

namespace equihash_canon {

// Verify an Equihash(n,k) solution over `input` (the parent block header up to
// and including the 32-byte nonce, i.e. the 140-byte Zcash header without the
// solution). `solution` is the raw (compressed, non-compactsize-prefixed)
// solution of exactly (2^k)*(n/(k+1)+1)/8 bytes. Returns true iff canonical.
bool Verify(unsigned int n, unsigned int k,
            const unsigned char* input, size_t input_len,
            const unsigned char* solution, size_t solution_len);

} // namespace equihash_canon

#endif // BITCOIN_CRYPTO_EQUIHASH_EQUIHASH_CANON_H
