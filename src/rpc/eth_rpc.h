// Copyright (c) 2024-2026 The WATTx Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_RPC_ETH_RPC_H
#define BITCOIN_RPC_ETH_RPC_H

#include <consensus/amount.h>
#include <pubkey.h>
#include <rpc/util.h>
#include <uint256.h>
#include <univalue.h>

#include <string>
#include <cstdint>

class CRPCTable;
class ChainstateManager;

// ============================================================================
// Chain Configuration
// ============================================================================

// WATTx Chain ID (2335 decimal = 0x91f hex)
static constexpr uint64_t ETH_CHAIN_ID = 2335;
static constexpr const char* ETH_CHAIN_ID_HEX = "0x91f";

// Gas constants
static constexpr uint64_t ETH_DEFAULT_GAS_PRICE = 40;  // 40 satoshi minimum
static constexpr uint64_t ETH_GAS_PRICE_WEI = 0x9502f9000;  // 40 gwei in wei
static constexpr uint64_t ETH_NON_CONTRACT_GAS = 21000;  // Standard transfer gas
static constexpr uint64_t ETH_MAX_GAS_LIMIT = 40000000;  // Maximum gas limit

// ============================================================================
// Unit Conversion Utilities
// ============================================================================

/**
 * Convert Wei to Satoshi
 * 1 WTX = 10^8 satoshi = 10^18 wei
 * So 1 satoshi = 10^10 wei
 * @param wei Amount in wei (as hex string with 0x prefix)
 * @return Amount in satoshi
 */
CAmount WeiToSatoshi(const std::string& weiHex);

/**
 * Convert Satoshi to Wei
 * @param satoshi Amount in satoshi
 * @return Amount in wei (as hex string with 0x prefix)
 */
std::string SatoshiToWei(CAmount satoshi);

/**
 * Convert Wei to Satoshi (from uint256)
 * @param wei Amount in wei
 * @return Amount in satoshi
 */
CAmount WeiToSatoshi(const uint256& wei);

/**
 * Convert Satoshi to Wei (to uint256)
 * @param satoshi Amount in satoshi
 * @return Amount in wei as uint256
 */
uint256 SatoshiToWeiU256(CAmount satoshi);

// ============================================================================
// Address Conversion Utilities
// ============================================================================

/**
 * Convert WATTx base58 address to Ethereum hex format
 * @param base58 WATTx address (e.g., "qUbxboqjBRp96j3La8D1RYkyqx5uQbJPoW")
 * @param hexOut Output hex address with 0x prefix
 * @return true if conversion successful
 */
bool Base58ToEthAddress(const std::string& base58, std::string& hexOut);

/**
 * Convert Ethereum hex address to WATTx base58 format
 * @param hexAddr Hex address (with or without 0x prefix)
 * @param base58Out Output base58 address
 * @return true if conversion successful
 */
bool EthAddressToBase58(const std::string& hexAddr, std::string& base58Out);

/**
 * Normalize ETH address (ensure 0x prefix, lowercase)
 * @param input Input address
 * @param output Normalized address
 * @return true if valid address
 */
bool NormalizeEthAddress(const std::string& input, std::string& output);

/**
 * Check if string is valid ETH hex address
 * @param addr Address to check (with or without 0x prefix)
 * @return true if valid 40-char hex address
 */
bool IsValidEthAddress(const std::string& addr);

// ============================================================================
// Keccak-256 Based EVM Address Derivation
// ============================================================================

/**
 * Derive Ethereum-compatible 0x address from a public key using Keccak-256.
 * This matches MetaMask/Rabby address derivation.
 * @param pubkey The compressed or uncompressed public key
 * @return The 0x-prefixed Ethereum address, or empty string on error
 */
std::string PubKeyToEvmAddress(const CPubKey& pubkey);

// ============================================================================
// Block Number Parsing
// ============================================================================

/**
 * Parse ETH block number parameter
 * Handles: "latest", "earliest", "pending", hex number
 * @param param Block number parameter
 * @param chainman Chainstate manager for getting current height
 * @return Block height (-1 for error, -2 for pending)
 */
int64_t ParseEthBlockNumber(const UniValue& param, ChainstateManager& chainman);

// ============================================================================
// Hex Utilities
// ============================================================================

/**
 * Convert integer to hex string with 0x prefix
 */
std::string IntToHex(uint64_t value);

/**
 * Convert hex string (with 0x prefix) to integer
 */
uint64_t HexToInt(const std::string& hex);

/**
 * Ensure hex string has 0x prefix
 */
std::string EnsureHexPrefix(const std::string& hex);

/**
 * Remove 0x prefix from hex string if present
 */
std::string StripHexPrefix(const std::string& hex);

/**
 * Pad hex string to specified byte length (without 0x prefix)
 */
std::string PadHex(const std::string& hex, size_t bytes);

// ============================================================================
// Response Formatting
// ============================================================================

/**
 * Format block response in ETH format
 */
UniValue FormatEthBlock(const UniValue& qtumBlock, bool fullTransactions);

/**
 * Format transaction response in ETH format
 */
UniValue FormatEthTransaction(const UniValue& qtumTx);

/**
 * Format transaction receipt in ETH format
 */
UniValue FormatEthReceipt(const UniValue& qtumReceipt);

/**
 * Format log entry in ETH format
 */
UniValue FormatEthLog(const UniValue& qtumLog);

// ============================================================================
// RPC Registration
// ============================================================================

/**
 * Register all Ethereum-compatible RPC commands
 */
void RegisterEthRPCCommands(CRPCTable& t);

#endif // BITCOIN_RPC_ETH_RPC_H
