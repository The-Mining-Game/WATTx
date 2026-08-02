// Copyright (c) 2010-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

//! @file node/types.h is a home for public enum and struct type definitions
//! that are used internally by node code, but also used externally by wallet,
//! mining or GUI code.
//!
//! This file is intended to define only simple types that do not have external
//! dependencies. More complicated types should be defined in dedicated header
//! files.

#ifndef BITCOIN_NODE_TYPES_H
#define BITCOIN_NODE_TYPES_H

#include <cstddef>
#include <optional>
#include <vector>
#include <policy/policy.h>
#include <script/script.h>

namespace wallet { class CWallet; }

namespace node {
enum class TransactionError {
    OK, //!< No error
    MISSING_INPUTS,
    ALREADY_IN_UTXO_SET,
    MEMPOOL_REJECTED,
    MEMPOOL_ERROR,
    MAX_FEE_EXCEEDED,
    MAX_BURN_EXCEEDED,
    INVALID_PACKAGE,
};

struct BlockCreateOptions {
    /**
     * Proof-of-work algorithm this template is for, as the id consensus stores
     * in block version bits 8-15.
     *
     * It must be known before the template's nBits is computed: with
     * per-algorithm difficulty each algorithm retargets separately, so a
     * template built as SHA256D and later stamped as, say, RandomX would carry
     * the wrong nBits and be rejected as bad-diffbits.
     */
    uint8_t pow_algo{0};
    /**
     * Set false to omit mempool transactions
     */
    bool use_mempool{true};
    /**
     * The default reserved weight for the fixed-size block header,
     * transaction count and coinbase transaction.
     */
    size_t block_reserved_weight{DEFAULT_BLOCK_RESERVED_WEIGHT};
    /**
     * The maximum additional sigops which the pool will add in coinbase
     * transaction outputs.
     */
    size_t coinbase_output_max_additional_sigops{400};
    /**
     * Script to put in the coinbase transaction. The default is an
     * anyone-can-spend dummy.
     *
     * Should only be used for tests, when the default doesn't suffice.
     *
     * Note that higher level code like the getblocktemplate RPC may omit the
     * coinbase transaction entirely. It's instead constructed by pool software
     * using fields like coinbasevalue, coinbaseaux and default_witness_commitment.
     * This software typically also controls the payout outputs, even for solo
     * mining.
     *
     * The size and sigops are not checked against
     * coinbase_max_additional_weight and coinbase_output_max_additional_sigops.
     */
    CScript coinbase_output_script{CScript() << OP_TRUE};
    /**
     * Whether to create FCMP reward outputs instead of transparent ones.
     * When true, the block reward goes to an FCMP OP_RETURN output
     * containing (O, I, C, R) curve tree data.
     */
    bool use_fcmp_reward{false};
    /**
     * Stealth address data for FCMP reward output.
     * scan_pubkey (33 bytes) + spend_pubkey (33 bytes).
     * If empty and use_fcmp_reward is true, falls back to transparent.
     */
    std::vector<uint8_t> fcmp_stealth_scan_pubkey;
    std::vector<uint8_t> fcmp_stealth_spend_pubkey;
    /**
     * Optional wallet pointer for FCMP stealth address auto-discovery.
     * When set, the miner can look up stealth addresses directly.
     */
    wallet::CWallet* fcmp_wallet{nullptr};
};
} // namespace node

#endif // BITCOIN_NODE_TYPES_H
