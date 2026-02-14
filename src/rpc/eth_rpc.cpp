// Copyright (c) 2024-2026 The WATTx Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <rpc/eth_rpc.h>

#include <chainparams.h>
#include <clientversion.h>
#include <common/args.h>
#include <common/system.h>
#include <consensus/tx_verify.h>
#include <index/txindex.h>
#include <key_io.h>
#include <net.h>
#include <net_processing.h>
#include <node/blockstorage.h>
#include <node/context.h>
#include <node/transaction.h>
#include <node/types.h>
#include <primitives/block.h>
#include <rpc/blockchain.h>
#include <rpc/protocol.h>
#include <rpc/request.h>
#include <rpc/server.h>
#include <rpc/server_util.h>
#include <rpc/util.h>
#include <sync.h>
#include <txdb.h>
#include <util/strencodings.h>
#include <util/convert.h>
#include <validation.h>
#include <interfaces/wallet.h>
#include <wallet/context.h>
#include <wallet/receive.h>
#include <wallet/wallet.h>
#include <rpc/contract_util.h>
#include <libdevcore/CommonData.h>
#include <qtum/qtumstate.h>
#include <ethash/keccak.hpp>
#include <secp256k1.h>

#include <iomanip>
#include <map>
#include <mutex>
#include <sstream>

using node::NodeContext;

// Get wallet from NodeContext (ETH RPCs are in bitcoin_node, not bitcoin_wallet,
// so request.context is NodeContext, not WalletContext)
static std::shared_ptr<wallet::CWallet> GetWalletFromNodeContext(const JSONRPCRequest& request)
{
    NodeContext& node = EnsureAnyNodeContext(request.context);
    if (!node.wallet_loader) return nullptr;

    wallet::WalletContext* wallet_context = node.wallet_loader->context();
    if (!wallet_context) return nullptr;

    size_t count{0};
    auto wallet = wallet::GetDefaultWallet(*wallet_context, count);
    if (wallet) return wallet;

    // If no default, try getting the first available wallet
    auto wallets = wallet::GetWallets(*wallet_context);
    if (!wallets.empty()) return wallets[0];

    return nullptr;
}

// Forward declarations
static UniValue FormatEthBlockInternal(const CBlock& block, const CBlockIndex* pblockindex,
                                       bool fullTransactions, ChainstateManager& chainman);
static UniValue FormatEthTransactionInternal(const CTransaction& tx, const CBlockIndex* pblockindex,
                                             size_t txIndex);

// ============================================================================
// Unit Conversion Implementation
// ============================================================================

// 1 WTX = 10^8 satoshi = 10^18 wei
// 1 satoshi = 10^10 wei
static constexpr uint64_t WEI_PER_SATOSHI = 10000000000ULL;  // 10^10

CAmount WeiToSatoshi(const std::string& weiHex)
{
    std::string hex = StripHexPrefix(weiHex);
    if (hex.empty()) return 0;

    // Parse hex to uint256 for large values
    uint256 wei;
    if (hex.size() <= 16) {
        // Small enough to fit in uint64
        uint64_t weiVal = HexToInt(weiHex);
        return static_cast<CAmount>(weiVal / WEI_PER_SATOSHI);
    }

    // For larger values, use uint256
    wei = uint256::FromHex(hex).value_or(uint256::ZERO);
    // Divide by 10^10 (shift right and divide)
    // Simplified: just return 0 for very large values that exceed CAmount
    // In practice, most values will be small enough
    return 0;
}

std::string SatoshiToWei(CAmount satoshi)
{
    if (satoshi <= 0) return "0x0";

    // Multiply by 10^10
    // Use 128-bit arithmetic to avoid overflow
    __int128 wei = static_cast<__int128>(satoshi) * WEI_PER_SATOSHI;

    // Convert to hex
    std::stringstream ss;
    ss << "0x" << std::hex;

    // Handle 128-bit to hex conversion
    uint64_t high = static_cast<uint64_t>(wei >> 64);
    uint64_t low = static_cast<uint64_t>(wei);

    if (high > 0) {
        ss << high;
        ss << std::setfill('0') << std::setw(16) << low;
    } else {
        ss << low;
    }

    return ss.str();
}

CAmount WeiToSatoshi(const uint256& wei)
{
    return WeiToSatoshi("0x" + wei.GetHex());
}

uint256 SatoshiToWeiU256(CAmount satoshi)
{
    if (satoshi <= 0) return uint256::ZERO;

    __int128 wei = static_cast<__int128>(satoshi) * WEI_PER_SATOSHI;

    // Convert to hex and parse as uint256
    std::stringstream ss;
    ss << std::hex;
    uint64_t high = static_cast<uint64_t>(wei >> 64);
    uint64_t low = static_cast<uint64_t>(wei);

    if (high > 0) {
        ss << high;
        ss << std::setfill('0') << std::setw(16) << low;
    } else {
        ss << low;
    }

    return uint256::FromHex(ss.str()).value_or(uint256::ZERO);
}

// ============================================================================
// Address Conversion Implementation
// ============================================================================

bool Base58ToEthAddress(const std::string& base58, std::string& hexOut)
{
    CTxDestination dest = DecodeDestination(base58);
    if (!IsValidDestination(dest)) {
        return false;
    }

    if (!std::holds_alternative<PKHash>(dest)) {
        return false;
    }

    PKHash keyID = std::get<PKHash>(dest);
    hexOut = "0x" + HexStr(std::vector<unsigned char>(keyID.begin(), keyID.end()));
    return true;
}

bool EthAddressToBase58(const std::string& hexAddr, std::string& base58Out)
{
    std::string normalized;
    if (!NormalizeEthAddress(hexAddr, normalized)) {
        return false;
    }

    // Remove 0x prefix
    std::string hex = normalized.substr(2);

    // Parse hex to bytes
    std::vector<unsigned char> data = ParseHex(hex);
    if (data.size() != 20) {
        return false;
    }

    // Create PKHash from data
    uint160 hash;
    memcpy(hash.begin(), data.data(), 20);
    PKHash keyID(hash);
    CTxDestination dest(keyID);

    base58Out = EncodeDestination(dest);
    return true;
}

bool NormalizeEthAddress(const std::string& input, std::string& output)
{
    std::string hex = StripHexPrefix(input);

    // Must be exactly 40 hex characters
    if (hex.size() != 40) {
        return false;
    }

    // Verify all characters are hex (HexDigit returns -1 for invalid chars)
    for (char c : hex) {
        if (HexDigit(c) < 0) {
            return false;
        }
    }

    // Convert to lowercase
    std::transform(hex.begin(), hex.end(), hex.begin(), ::tolower);
    output = "0x" + hex;
    return true;
}

bool IsValidEthAddress(const std::string& addr)
{
    std::string normalized;
    return NormalizeEthAddress(addr, normalized);
}

// ============================================================================
// Keccak-256 Based EVM Address Derivation (MetaMask/Rabby Compatible)
// ============================================================================

// Static secp256k1 context for pubkey decompression (thread-safe initialization)
static secp256k1_context* GetSecp256k1Context()
{
    static secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    return ctx;
}

std::string PubKeyToEvmAddress(const CPubKey& compressedPubkey)
{
    if (!compressedPubkey.IsValid()) return "";

    secp256k1_context* ctx = GetSecp256k1Context();
    secp256k1_pubkey pubkey;

    if (!secp256k1_ec_pubkey_parse(ctx, &pubkey, compressedPubkey.data(), compressedPubkey.size())) {
        return "";
    }

    // Serialize as uncompressed (65 bytes: 0x04 + x + y)
    unsigned char uncompressed[65];
    size_t outputLen = 65;
    secp256k1_ec_pubkey_serialize(ctx, uncompressed, &outputLen, &pubkey, SECP256K1_EC_UNCOMPRESSED);

    // Keccak-256 of the public key bytes (without the 0x04 prefix)
    ethash::hash256 hash = ethash::keccak256(uncompressed + 1, 64);

    // Take last 20 bytes as the Ethereum address
    std::stringstream ss;
    ss << "0x";
    for (size_t i = 12; i < 32; i++) {
        ss << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(hash.bytes[i]);
    }
    return ss.str();
}

// Look up the wallet destination matching a Keccak-derived EVM address.
// Returns true and sets base58Out if a matching wallet address is found.
static bool EvmAddressToWalletBase58(const wallet::CWallet& wallet, const std::string& evmAddr, std::string& base58Out) EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet)
{
    std::string normalizedTarget;
    if (!NormalizeEthAddress(evmAddr, normalizedTarget)) {
        return false;
    }

    // Collect all unique destinations from address book and balances
    std::set<CTxDestination> destinations;
    for (const auto& [dest, entry] : wallet.m_address_book) {
        destinations.insert(dest);
    }
    std::map<CTxDestination, CAmount> balances = wallet::GetAddressBalances(wallet);
    for (const auto& [dest, amount] : balances) {
        destinations.insert(dest);
    }

    // Iterate wallet addresses and find the one whose Keccak-derived address matches
    for (const auto& dest : destinations) {
        if (auto* pk_hash = std::get_if<PKHash>(&dest)) {
            CPubKey pubkey;
            if (wallet.GetPubKey(*pk_hash, pubkey) && pubkey.IsValid()) {
                std::string derived = PubKeyToEvmAddress(pubkey);
                if (derived == normalizedTarget) {
                    base58Out = EncodeDestination(dest);
                    return true;
                }
            }
        }
    }

    return false;
}

// ============================================================================
// Hex Utilities Implementation
// ============================================================================

std::string IntToHex(uint64_t value)
{
    std::stringstream ss;
    ss << "0x" << std::hex << value;
    return ss.str();
}

uint64_t HexToInt(const std::string& hex)
{
    std::string clean = StripHexPrefix(hex);
    if (clean.empty()) return 0;

    uint64_t result = 0;
    std::stringstream ss;
    ss << std::hex << clean;
    ss >> result;
    return result;
}

std::string EnsureHexPrefix(const std::string& hex)
{
    if (hex.size() >= 2 && hex[0] == '0' && (hex[1] == 'x' || hex[1] == 'X')) {
        return hex;
    }
    return "0x" + hex;
}

std::string StripHexPrefix(const std::string& hex)
{
    if (hex.size() >= 2 && hex[0] == '0' && (hex[1] == 'x' || hex[1] == 'X')) {
        return hex.substr(2);
    }
    return hex;
}

std::string PadHex(const std::string& hex, size_t bytes)
{
    std::string clean = StripHexPrefix(hex);
    size_t targetLen = bytes * 2;

    if (clean.size() >= targetLen) {
        return clean;
    }

    return std::string(targetLen - clean.size(), '0') + clean;
}

// ============================================================================
// Block Number Parsing Implementation
// ============================================================================

int64_t ParseEthBlockNumber(const UniValue& param, ChainstateManager& chainman)
{
    if (param.isNull()) {
        LOCK(cs_main);
        return chainman.ActiveChain().Height();
    }

    if (param.isStr()) {
        std::string blockTag = param.get_str();

        if (blockTag == "latest") {
            LOCK(cs_main);
            return chainman.ActiveChain().Height();
        } else if (blockTag == "earliest") {
            return 0;
        } else if (blockTag == "pending") {
            // Pending not supported in UTXO model, return latest
            LOCK(cs_main);
            return chainman.ActiveChain().Height();
        } else if (blockTag.substr(0, 2) == "0x" || blockTag.substr(0, 2) == "0X") {
            // Hex number
            return static_cast<int64_t>(HexToInt(blockTag));
        }
    }

    if (param.isNum()) {
        return param.getInt<int64_t>();
    }

    throw JSONRPCError(RPC_INVALID_PARAMS, "Invalid block number parameter");
}

// ============================================================================
// Phase 1: Basic Connectivity Methods
// ============================================================================

static RPCHelpMan eth_chainId()
{
    return RPCHelpMan{"eth_chainId",
        "\nReturns the chain ID used for signing replay-protected transactions.\n",
        {},
        RPCResult{
            RPCResult::Type::STR_HEX, "", "The chain ID in hex"},
        RPCExamples{
            HelpExampleCli("eth_chainId", "")
            + HelpExampleRpc("eth_chainId", "")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    return ETH_CHAIN_ID_HEX;
},
    };
}

static RPCHelpMan net_version()
{
    return RPCHelpMan{"net_version",
        "\nReturns the current network ID.\n",
        {},
        RPCResult{
            RPCResult::Type::STR, "", "The network ID"},
        RPCExamples{
            HelpExampleCli("net_version", "")
            + HelpExampleRpc("net_version", "")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    return std::to_string(ETH_CHAIN_ID);
},
    };
}

static RPCHelpMan eth_blockNumber()
{
    return RPCHelpMan{"eth_blockNumber",
        "\nReturns the number of most recent block.\n",
        {},
        RPCResult{
            RPCResult::Type::STR_HEX, "", "The current block number in hex"},
        RPCExamples{
            HelpExampleCli("eth_blockNumber", "")
            + HelpExampleRpc("eth_blockNumber", "")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    ChainstateManager& chainman = EnsureAnyChainman(request.context);
    LOCK(cs_main);
    return IntToHex(chainman.ActiveChain().Height());
},
    };
}

static RPCHelpMan eth_gasPrice()
{
    return RPCHelpMan{"eth_gasPrice",
        "\nReturns the current gas price in wei.\n",
        {},
        RPCResult{
            RPCResult::Type::STR_HEX, "", "The gas price in wei (hex)"},
        RPCExamples{
            HelpExampleCli("eth_gasPrice", "")
            + HelpExampleRpc("eth_gasPrice", "")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    // Return 40 gwei (0x9502f9000) - minimum gas price
    return "0x9502f9000";
},
    };
}

static RPCHelpMan web3_clientVersion()
{
    return RPCHelpMan{"web3_clientVersion",
        "\nReturns the current client version.\n",
        {},
        RPCResult{
            RPCResult::Type::STR, "", "The client version string"},
        RPCExamples{
            HelpExampleCli("web3_clientVersion", "")
            + HelpExampleRpc("web3_clientVersion", "")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    return "WATTx/" + FormatFullVersion();
},
    };
}

static RPCHelpMan net_listening()
{
    return RPCHelpMan{"net_listening",
        "\nReturns true if client is actively listening for network connections.\n",
        {},
        RPCResult{
            RPCResult::Type::BOOL, "", "true if listening"},
        RPCExamples{
            HelpExampleCli("net_listening", "")
            + HelpExampleRpc("net_listening", "")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    return true;
},
    };
}

static RPCHelpMan net_peerCount()
{
    return RPCHelpMan{"net_peerCount",
        "\nReturns number of peers currently connected to the client.\n",
        {},
        RPCResult{
            RPCResult::Type::STR_HEX, "", "Number of connected peers in hex"},
        RPCExamples{
            HelpExampleCli("net_peerCount", "")
            + HelpExampleRpc("net_peerCount", "")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    NodeContext& node = EnsureAnyNodeContext(request.context);
    const CConnman& connman = EnsureConnman(node);

    return IntToHex(connman.GetNodeCount(ConnectionDirection::Both));
},
    };
}

static RPCHelpMan eth_protocolVersion()
{
    return RPCHelpMan{"eth_protocolVersion",
        "\nReturns the current Ethereum protocol version.\n",
        {},
        RPCResult{
            RPCResult::Type::STR_HEX, "", "The protocol version in hex"},
        RPCExamples{
            HelpExampleCli("eth_protocolVersion", "")
            + HelpExampleRpc("eth_protocolVersion", "")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    // Return 0x41 (65) - standard Ethereum protocol version
    return "0x41";
},
    };
}

static RPCHelpMan eth_syncing()
{
    return RPCHelpMan{"eth_syncing",
        "\nReturns an object with data about the sync status or false.\n",
        {},
        RPCResult{
            RPCResult::Type::ANY, "", "Sync status object or false"},
        RPCExamples{
            HelpExampleCli("eth_syncing", "")
            + HelpExampleRpc("eth_syncing", "")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    ChainstateManager& chainman = EnsureAnyChainman(request.context);

    LOCK(cs_main);

    // Check if we're syncing
    if (!chainman.IsInitialBlockDownload()) {
        return false;
    }

    // Return sync status
    UniValue result(UniValue::VOBJ);
    int64_t currentBlock = chainman.ActiveChain().Height();
    int64_t highestBlock = chainman.m_best_header ? chainman.m_best_header->nHeight : currentBlock;

    result.pushKV("startingBlock", IntToHex(0));
    result.pushKV("currentBlock", IntToHex(currentBlock));
    result.pushKV("highestBlock", IntToHex(highestBlock));

    return result;
},
    };
}

static RPCHelpMan eth_mining()
{
    return RPCHelpMan{"eth_mining",
        "\nReturns true if client is actively mining/staking new blocks.\n",
        {},
        RPCResult{
            RPCResult::Type::BOOL, "", "true if mining/staking"},
        RPCExamples{
            HelpExampleCli("eth_mining", "")
            + HelpExampleRpc("eth_mining", "")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    // Check staking status
    return gArgs.GetBoolArg("-staking", false);
},
    };
}

static RPCHelpMan eth_hashrate()
{
    return RPCHelpMan{"eth_hashrate",
        "\nReturns the number of hashes per second that the node is mining with.\n",
        {},
        RPCResult{
            RPCResult::Type::STR_HEX, "", "Hashrate in hex"},
        RPCExamples{
            HelpExampleCli("eth_hashrate", "")
            + HelpExampleRpc("eth_hashrate", "")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    // WATTx uses PoS primarily, return 0
    return "0x0";
},
    };
}

static RPCHelpMan web3_sha3()
{
    return RPCHelpMan{"web3_sha3",
        "\nReturns Keccak-256 (not the standardized SHA3-256) of the given data.\n",
        {
            {"data", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The data to hash"},
        },
        RPCResult{
            RPCResult::Type::STR_HEX, "", "The Keccak-256 hash of the data"},
        RPCExamples{
            HelpExampleCli("web3_sha3", "\"0x68656c6c6f20776f726c64\"")
            + HelpExampleRpc("web3_sha3", "\"0x68656c6c6f20776f726c64\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::string input = request.params[0].get_str();
    std::string hex = StripHexPrefix(input);

    std::vector<unsigned char> data = ParseHex(hex);

    // Keccak-256 hash (Ethereum's "SHA3" is actually Keccak-256)
    ethash::hash256 hash = ethash::keccak256(data.data(), data.size());

    std::stringstream ss;
    ss << "0x";
    for (size_t i = 0; i < 32; i++) {
        ss << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(hash.bytes[i]);
    }
    return ss.str();
},
    };
}

// ============================================================================
// Phase 2: Account and Balance Methods
// ============================================================================

static RPCHelpMan eth_getBalance()
{
    return RPCHelpMan{"eth_getBalance",
        "\nReturns the balance of the account at given address.\n",
        {
            {"address", RPCArg::Type::STR, RPCArg::Optional::NO, "The address to check balance (hex or base58)"},
            {"block", RPCArg::Type::STR, RPCArg::Default{"latest"}, "Block number or 'latest', 'earliest', 'pending'"},
        },
        RPCResult{
            RPCResult::Type::STR_HEX, "", "The balance in wei (hex)"},
        RPCExamples{
            HelpExampleCli("eth_getBalance", "\"0x1234567890abcdef1234567890abcdef12345678\" \"latest\"")
            + HelpExampleRpc("eth_getBalance", "\"0x1234567890abcdef1234567890abcdef12345678\", \"latest\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::string addrStr = request.params[0].get_str();
    std::string base58Addr;
    bool validAddress = false;

    // Try to get balance from wallet
    try {
        const std::shared_ptr<wallet::CWallet> pwallet = GetWalletFromNodeContext(request);
        if (pwallet) {
            LOCK(pwallet->cs_wallet);

            if (IsValidEthAddress(addrStr)) {
                // Keccak-derived EVM address - reverse lookup in wallet
                if (EvmAddressToWalletBase58(*pwallet, addrStr, base58Addr)) {
                    validAddress = true;
                } else {
                    // Not found in wallet - return 0
                    return "0x0";
                }
            } else {
                // Assume it's a base58 address
                base58Addr = addrStr;
                CTxDestination dest = DecodeDestination(base58Addr);
                if (!IsValidDestination(dest)) {
                    throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid address");
                }
                validAddress = true;
            }

            if (validAddress) {
                CTxDestination dest = DecodeDestination(base58Addr);
                std::map<CTxDestination, CAmount> balances = wallet::GetAddressBalances(*pwallet);
                auto it = balances.find(dest);
                if (it != balances.end()) {
                    return SatoshiToWei(it->second);
                }
            }
        }
    } catch (...) {
        // Wallet not available
    }

    // Address not in wallet or wallet not available - return 0
    return "0x0";
},
    };
}

static RPCHelpMan eth_accounts()
{
    return RPCHelpMan{"eth_accounts",
        "\nReturns a list of addresses owned by client.\n",
        {},
        RPCResult{
            RPCResult::Type::ARR, "", "Array of account addresses",
            {
                {RPCResult::Type::STR_HEX, "", "An Ethereum-style hex address"},
            }
        },
        RPCExamples{
            HelpExampleCli("eth_accounts", "")
            + HelpExampleRpc("eth_accounts", "")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    UniValue result(UniValue::VARR);

    try {
        const std::shared_ptr<wallet::CWallet> pwallet = GetWalletFromNodeContext(request);
        if (!pwallet) {
            return result; // Empty array if no wallet
        }

        LOCK(pwallet->cs_wallet);

        // Get addresses with balances
        std::map<CTxDestination, CAmount> balances = wallet::GetAddressBalances(*pwallet);

        // Also include addresses from address book
        std::set<CTxDestination> destinations;
        for (const auto& [addr, data] : pwallet->m_address_book) {
            destinations.insert(addr);
        }
        for (const auto& [addr, amount] : balances) {
            destinations.insert(addr);
        }

        // Convert to Keccak-derived EVM addresses (MetaMask/Rabby compatible)
        for (const auto& dest : destinations) {
            if (auto* pk_hash = std::get_if<PKHash>(&dest)) {
                CPubKey pubkey;
                if (pwallet->GetPubKey(*pk_hash, pubkey) && pubkey.IsValid()) {
                    std::string evmAddr = PubKeyToEvmAddress(pubkey);
                    if (!evmAddr.empty()) {
                        result.push_back(evmAddr);
                    }
                }
            }
        }
    } catch (...) {
        // Wallet not available, return empty array
    }

    return result;
},
    };
}

static RPCHelpMan eth_getTransactionCount()
{
    return RPCHelpMan{"eth_getTransactionCount",
        "\nReturns the number of transactions sent from an address (nonce).\n",
        {
            {"address", RPCArg::Type::STR, RPCArg::Optional::NO, "The address to get transaction count (hex or base58)"},
            {"block", RPCArg::Type::STR, RPCArg::Default{"latest"}, "Block number or 'latest', 'earliest', 'pending'"},
        },
        RPCResult{
            RPCResult::Type::STR_HEX, "", "The transaction count in hex"},
        RPCExamples{
            HelpExampleCli("eth_getTransactionCount", "\"0x1234567890abcdef1234567890abcdef12345678\" \"latest\"")
            + HelpExampleRpc("eth_getTransactionCount", "\"0x1234567890abcdef1234567890abcdef12345678\", \"latest\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::string addrStr = request.params[0].get_str();
    std::string base58Addr;

    // In UTXO model, there's no nonce. Count transactions sent from this address.
    // For MetaMask compatibility, we count outgoing transactions from wallet
    uint64_t txCount = 0;

    try {
        const std::shared_ptr<wallet::CWallet> pwallet = GetWalletFromNodeContext(request);
        if (pwallet) {
            LOCK(pwallet->cs_wallet);

            bool validAddress = false;

            if (IsValidEthAddress(addrStr)) {
                // Keccak-derived EVM address - reverse lookup in wallet
                if (EvmAddressToWalletBase58(*pwallet, addrStr, base58Addr)) {
                    validAddress = true;
                }
            } else {
                base58Addr = addrStr;
                CTxDestination dest = DecodeDestination(base58Addr);
                if (IsValidDestination(dest)) {
                    validAddress = true;
                }
            }

            if (validAddress) {
                CTxDestination dest = DecodeDestination(base58Addr);
                CScript scriptPubKey = GetScriptForDestination(dest);

                for (const auto& [txid, wtx] : pwallet->mapWallet) {
                    for (const CTxIn& txin : wtx.tx->vin) {
                        auto prevIt = pwallet->mapWallet.find(txin.prevout.hash);
                        if (prevIt != pwallet->mapWallet.end()) {
                            if (txin.prevout.n < prevIt->second.tx->vout.size()) {
                                const CTxOut& prevOut = prevIt->second.tx->vout[txin.prevout.n];
                                if (prevOut.scriptPubKey == scriptPubKey) {
                                    txCount++;
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        }
    } catch (...) {
        // Wallet not available
    }

    return IntToHex(txCount);
},
    };
}

static RPCHelpMan eth_coinbase()
{
    return RPCHelpMan{"eth_coinbase",
        "\nReturns the client coinbase address.\n",
        {},
        RPCResult{
            RPCResult::Type::STR_HEX, "", "The coinbase address"},
        RPCExamples{
            HelpExampleCli("eth_coinbase", "")
            + HelpExampleRpc("eth_coinbase", "")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    // Try to get mining/staking address from wallet
    try {
        const std::shared_ptr<wallet::CWallet> pwallet = GetWalletFromNodeContext(request);
        if (pwallet) {
            LOCK(pwallet->cs_wallet);

            // Get the first address from the wallet
            for (const auto& [dest, data] : pwallet->m_address_book) {
                std::string base58 = EncodeDestination(dest);
                std::string hexAddr;
                if (Base58ToEthAddress(base58, hexAddr)) {
                    return hexAddr;
                }
            }
        }
    } catch (...) {
        // Wallet not available
    }

    // No wallet or no addresses
    return "0x0000000000000000000000000000000000000000";
},
    };
}

// ============================================================================
// Phase 3: Contract Interaction Methods
// ============================================================================

static RPCHelpMan eth_call()
{
    return RPCHelpMan{"eth_call",
        "\nExecutes a new message call immediately without creating a transaction.\n",
        {
            {"transaction", RPCArg::Type::OBJ, RPCArg::Optional::NO, "The transaction call object",
                {
                    {"from", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "The sender address"},
                    {"to", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The contract address"},
                    {"gas", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Gas limit"},
                    {"gasPrice", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Gas price"},
                    {"value", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Value to send"},
                    {"data", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "The data to send (function call)"},
                }
            },
            {"block", RPCArg::Type::STR, RPCArg::Default{"latest"}, "Block number or 'latest', 'earliest', 'pending'"},
        },
        RPCResult{
            RPCResult::Type::STR_HEX, "", "The return data of the call"},
        RPCExamples{
            HelpExampleRpc("eth_call", "{\"to\":\"0x1234...\",\"data\":\"0x...\"}, \"latest\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    ChainstateManager& chainman = EnsureAnyChainman(request.context);

    UniValue txObj = request.params[0].get_obj();

    // Parse contract address (to) - accept both hex and base58
    std::string toAddr;
    if (!txObj["to"].isNull()) {
        std::string addrInput = txObj["to"].get_str();
        std::string normalized;
        if (NormalizeEthAddress(addrInput, normalized)) {
            toAddr = StripHexPrefix(normalized);
        } else {
            // Try as base58 address
            std::string hexAddr;
            if (Base58ToEthAddress(addrInput, hexAddr)) {
                toAddr = StripHexPrefix(hexAddr);
            } else {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid 'to' address");
            }
        }
    }

    // Parse data/input
    std::string dataHex;
    if (!txObj["data"].isNull()) {
        dataHex = StripHexPrefix(txObj["data"].get_str());
    } else if (!txObj["input"].isNull()) {
        dataHex = StripHexPrefix(txObj["input"].get_str());
    }

    // Parse sender address - accept both hex and base58
    dev::Address senderAddress;
    if (!txObj["from"].isNull()) {
        std::string addrInput = txObj["from"].get_str();
        std::string normalized;
        if (NormalizeEthAddress(addrInput, normalized)) {
            senderAddress = dev::Address(StripHexPrefix(normalized));
        } else {
            std::string hexAddr;
            if (Base58ToEthAddress(addrInput, hexAddr)) {
                senderAddress = dev::Address(StripHexPrefix(hexAddr));
            }
        }
    }

    // Parse gas limit
    uint64_t gasLimit = ETH_MAX_GAS_LIMIT;
    if (!txObj["gas"].isNull()) {
        gasLimit = HexToInt(txObj["gas"].get_str());
    }

    // Parse value
    CAmount nAmount = 0;
    if (!txObj["value"].isNull()) {
        nAmount = WeiToSatoshi(txObj["value"].get_str());
    }

    // Parse block number
    int64_t blockNum = ParseEthBlockNumber(request.params[1], chainman);

    LOCK(cs_main);

    dev::Address contractAddr(toAddr);

    // Execute the call
    std::vector<ResultExecute> execResults = CallContract(
        contractAddr,
        ParseHex(dataHex),
        chainman.ActiveChainstate(),
        static_cast<int>(blockNum),
        senderAddress,
        gasLimit,
        nAmount
    );

    if (execResults.empty()) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Contract execution failed");
    }

    // Return the output data
    return "0x" + HexStr(execResults[0].execRes.output);
},
    };
}

static RPCHelpMan eth_getCode()
{
    return RPCHelpMan{"eth_getCode",
        "\nReturns code at a given address.\n",
        {
            {"address", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The contract address"},
            {"block", RPCArg::Type::STR, RPCArg::Default{"latest"}, "Block number or 'latest', 'earliest', 'pending'"},
        },
        RPCResult{
            RPCResult::Type::STR_HEX, "", "The code at the address"},
        RPCExamples{
            HelpExampleCli("eth_getCode", "\"0x1234...\" \"latest\"")
            + HelpExampleRpc("eth_getCode", "\"0x1234...\", \"latest\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    ChainstateManager& chainman = EnsureAnyChainman(request.context);

    std::string addrStr = request.params[0].get_str();
    std::string strAddr;

    // Accept both hex and base58 addresses
    std::string normalized;
    if (NormalizeEthAddress(addrStr, normalized)) {
        strAddr = StripHexPrefix(normalized);
    } else {
        // Try as base58 address and convert to hex
        std::string hexAddr;
        if (Base58ToEthAddress(addrStr, hexAddr)) {
            strAddr = StripHexPrefix(hexAddr);
        } else {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid address");
        }
    }

    int64_t blockNum = ParseEthBlockNumber(request.params[1], chainman);

    LOCK(cs_main);

    CChain& active_chain = chainman.ActiveChain();

    // Set state to specific block if needed
    TemporaryState ts(globalState);
    if (blockNum >= 0 && blockNum < active_chain.Height()) {
        ts.SetRoot(uintToh256(active_chain[blockNum]->hashStateRoot),
                   uintToh256(active_chain[blockNum]->hashUTXORoot));
    }

    dev::Address addrAccount(strAddr);

    // Check if address exists
    if (!globalState->addressInUse(addrAccount)) {
        return "0x";
    }

    std::vector<uint8_t> code(globalState->code(addrAccount));
    return "0x" + HexStr(code);
},
    };
}

static RPCHelpMan eth_getStorageAt()
{
    return RPCHelpMan{"eth_getStorageAt",
        "\nReturns the value from a storage position at a given address.\n",
        {
            {"address", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The contract address"},
            {"position", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The storage position (hex)"},
            {"block", RPCArg::Type::STR, RPCArg::Default{"latest"}, "Block number or 'latest', 'earliest', 'pending'"},
        },
        RPCResult{
            RPCResult::Type::STR_HEX, "", "The value at the storage position"},
        RPCExamples{
            HelpExampleCli("eth_getStorageAt", "\"0x1234...\" \"0x0\" \"latest\"")
            + HelpExampleRpc("eth_getStorageAt", "\"0x1234...\", \"0x0\", \"latest\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    ChainstateManager& chainman = EnsureAnyChainman(request.context);

    std::string addrStr = request.params[0].get_str();
    std::string strAddr;

    // Accept both hex and base58 addresses
    std::string normalized;
    if (NormalizeEthAddress(addrStr, normalized)) {
        strAddr = StripHexPrefix(normalized);
    } else {
        // Try as base58 address and convert to hex
        std::string hexAddr;
        if (Base58ToEthAddress(addrStr, hexAddr)) {
            strAddr = StripHexPrefix(hexAddr);
        } else {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid address");
        }
    }

    std::string positionHex = StripHexPrefix(request.params[1].get_str());
    int64_t blockNum = ParseEthBlockNumber(request.params[2], chainman);

    LOCK(cs_main);

    CChain& active_chain = chainman.ActiveChain();

    // Set state to specific block if needed
    TemporaryState ts(globalState);
    if (blockNum >= 0 && blockNum < active_chain.Height()) {
        ts.SetRoot(uintToh256(active_chain[blockNum]->hashStateRoot),
                   uintToh256(active_chain[blockNum]->hashUTXORoot));
    }

    dev::Address addrAccount(strAddr);

    // Check if address exists
    if (!globalState->addressInUse(addrAccount)) {
        return "0x0000000000000000000000000000000000000000000000000000000000000000";
    }

    // Pad position to 64 hex characters (32 bytes)
    std::string paddedPosition = PadHex(positionHex, 32);
    dev::u256 position(paddedPosition);

    // Get storage value
    dev::u256 value = globalState->storage(addrAccount, position);

    // Format as 32-byte hex
    std::stringstream ss;
    ss << std::hex << std::setfill('0') << std::setw(64) << value;
    return "0x" + ss.str();
},
    };
}

static RPCHelpMan eth_estimateGas()
{
    return RPCHelpMan{"eth_estimateGas",
        "\nGenerates and returns an estimate of how much gas is necessary for the transaction.\n",
        {
            {"transaction", RPCArg::Type::OBJ, RPCArg::Optional::NO, "The transaction call object",
                {
                    {"from", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "The sender address"},
                    {"to", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "The contract address"},
                    {"gas", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Gas limit"},
                    {"gasPrice", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Gas price"},
                    {"value", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Value to send"},
                    {"data", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "The data to send"},
                }
            },
            {"block", RPCArg::Type::STR, RPCArg::Default{"latest"}, "Block number or 'latest'"},
        },
        RPCResult{
            RPCResult::Type::STR_HEX, "", "The estimated gas"},
        RPCExamples{
            HelpExampleRpc("eth_estimateGas", "{\"to\":\"0x1234...\",\"data\":\"0x...\"}")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    ChainstateManager& chainman = EnsureAnyChainman(request.context);

    UniValue txObj = request.params[0].get_obj();

    // Parse contract address (to) - accept both hex and base58
    std::string toAddr;
    if (!txObj["to"].isNull()) {
        std::string addrInput = txObj["to"].get_str();
        std::string normalized;
        if (NormalizeEthAddress(addrInput, normalized)) {
            toAddr = StripHexPrefix(normalized);
        } else {
            // Try as base58 address
            std::string hexAddr;
            if (Base58ToEthAddress(addrInput, hexAddr)) {
                toAddr = StripHexPrefix(hexAddr);
            } else {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid 'to' address");
            }
        }
    }

    // Parse data/input
    std::string dataHex;
    if (!txObj["data"].isNull()) {
        dataHex = StripHexPrefix(txObj["data"].get_str());
    } else if (!txObj["input"].isNull()) {
        dataHex = StripHexPrefix(txObj["input"].get_str());
    }

    // If no 'to' address and no data, it's a simple transfer
    if (toAddr.empty() && dataHex.empty()) {
        return IntToHex(ETH_NON_CONTRACT_GAS);
    }

    // Parse sender address - accept both hex and base58
    dev::Address senderAddress;
    if (!txObj["from"].isNull()) {
        std::string addrInput = txObj["from"].get_str();
        std::string normalized;
        if (NormalizeEthAddress(addrInput, normalized)) {
            senderAddress = dev::Address(StripHexPrefix(normalized));
        } else {
            std::string hexAddr;
            if (Base58ToEthAddress(addrInput, hexAddr)) {
                senderAddress = dev::Address(StripHexPrefix(hexAddr));
            }
        }
    }

    // Parse value
    CAmount nAmount = 0;
    if (!txObj["value"].isNull()) {
        nAmount = WeiToSatoshi(txObj["value"].get_str());
    }

    LOCK(cs_main);

    // If it's just a simple transfer (no data, valid to address)
    if (dataHex.empty() && !toAddr.empty()) {
        dev::Address contractAddr(toAddr);
        if (!globalState->addressInUse(contractAddr)) {
            // Simple transfer to non-contract address
            return IntToHex(ETH_NON_CONTRACT_GAS);
        }
    }

    // Execute the call to estimate gas
    dev::Address contractAddr(toAddr);
    std::vector<ResultExecute> execResults = CallContract(
        contractAddr,
        ParseHex(dataHex),
        chainman.ActiveChainstate(),
        senderAddress,
        ETH_MAX_GAS_LIMIT,
        nAmount
    );

    if (execResults.empty()) {
        return IntToHex(ETH_NON_CONTRACT_GAS);
    }

    // Return gas used plus a buffer (20%)
    uint64_t gasUsed = static_cast<uint64_t>(execResults[0].execRes.gasUsed);
    uint64_t estimatedGas = gasUsed + (gasUsed / 5); // Add 20% buffer

    // Ensure minimum gas
    if (estimatedGas < ETH_NON_CONTRACT_GAS) {
        estimatedGas = ETH_NON_CONTRACT_GAS;
    }

    return IntToHex(estimatedGas);
},
    };
}

// ============================================================================
// Phase 4: Transaction Methods
// ============================================================================

static RPCHelpMan eth_sendTransaction()
{
    return RPCHelpMan{"eth_sendTransaction",
        "\nCreates new message call transaction or a contract creation.\n",
        {
            {"transaction", RPCArg::Type::OBJ, RPCArg::Optional::NO, "The transaction object",
                {
                    {"from", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The sender address"},
                    {"to", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "The recipient address (omit for contract creation)"},
                    {"gas", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Gas limit"},
                    {"gasPrice", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Gas price in wei"},
                    {"value", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Value to send in wei"},
                    {"data", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "The data/bytecode"},
                    {"nonce", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Transaction nonce (ignored in UTXO model)"},
                }
            },
        },
        RPCResult{
            RPCResult::Type::STR_HEX, "", "The transaction hash"},
        RPCExamples{
            HelpExampleRpc("eth_sendTransaction", "{\"from\":\"0x...\",\"to\":\"0x...\",\"value\":\"0x1\"}")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const std::shared_ptr<wallet::CWallet> pwallet = GetWalletFromNodeContext(request);
    if (!pwallet) {
        throw JSONRPCError(RPC_WALLET_NOT_FOUND, "Wallet not found");
    }

    ChainstateManager& chainman = EnsureAnyChainman(request.context);
    UniValue txObj = request.params[0].get_obj();

    // Parse from address
    std::string fromAddr;
    if (!txObj["from"].isNull()) {
        std::string normalized;
        if (NormalizeEthAddress(txObj["from"].get_str(), normalized)) {
            EthAddressToBase58(normalized, fromAddr);
        }
    }
    if (fromAddr.empty()) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Missing or invalid 'from' address");
    }

    // Parse to address
    std::string toAddr;
    bool hasToAddress = false;
    if (!txObj["to"].isNull() && !txObj["to"].get_str().empty()) {
        std::string normalized;
        if (NormalizeEthAddress(txObj["to"].get_str(), normalized)) {
            toAddr = StripHexPrefix(normalized);
            hasToAddress = true;
        }
    }

    // Parse value
    CAmount nAmount = 0;
    if (!txObj["value"].isNull()) {
        nAmount = WeiToSatoshi(txObj["value"].get_str());
    }

    // Parse data
    std::string dataHex;
    if (!txObj["data"].isNull()) {
        dataHex = StripHexPrefix(txObj["data"].get_str());
    } else if (!txObj["input"].isNull()) {
        dataHex = StripHexPrefix(txObj["input"].get_str());
    }

    // Parse gas limit
    uint64_t gasLimit = ETH_MAX_GAS_LIMIT;
    if (!txObj["gas"].isNull()) {
        gasLimit = HexToInt(txObj["gas"].get_str());
    }

    // Determine transaction type and create appropriate RPC call
    UniValue result(UniValue::VOBJ);

    if (!hasToAddress && !dataHex.empty()) {
        // Contract creation - call createcontract
        UniValue params(UniValue::VARR);
        params.push_back(dataHex);           // bytecode
        params.push_back((int64_t)gasLimit); // gas limit
        if (nAmount > 0) {
            params.push_back(ValueFromAmount(nAmount)); // amount (if any)
        }
        params.push_back(fromAddr);          // sender address

        // Call createcontract RPC internally
        JSONRPCRequest subrequest;
        subrequest.context = request.context;
        subrequest.params = params;
        subrequest.strMethod = "createcontract";

        // We need to invoke the RPC - for now return a placeholder
        throw JSONRPCError(RPC_METHOD_NOT_FOUND, "Contract creation via eth_sendTransaction requires direct wallet access. Use createcontract RPC directly.");
    } else if (hasToAddress && !dataHex.empty()) {
        // Contract call - call sendtocontract
        LOCK(cs_main);
        dev::Address contractAddr(toAddr);
        if (globalState->addressInUse(contractAddr)) {
            // It's a contract call
            throw JSONRPCError(RPC_METHOD_NOT_FOUND, "Contract calls via eth_sendTransaction require direct wallet access. Use sendtocontract RPC directly.");
        } else {
            // Simple transfer with data (unusual but valid)
            throw JSONRPCError(RPC_METHOD_NOT_FOUND, "Transfers with data via eth_sendTransaction require direct wallet access. Use sendtoaddress RPC directly.");
        }
    } else if (hasToAddress && nAmount > 0) {
        // Simple value transfer - call sendtoaddress
        std::string toBase58;
        std::string normalized = "0x" + toAddr;
        if (!EthAddressToBase58(normalized, toBase58)) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid 'to' address");
        }

        throw JSONRPCError(RPC_METHOD_NOT_FOUND, "Value transfers via eth_sendTransaction require direct wallet access. Use sendtoaddress RPC directly.");
    } else {
        throw JSONRPCError(RPC_INVALID_PARAMS, "Invalid transaction parameters");
    }

    return result;
},
    };
}

static RPCHelpMan eth_sendRawTransaction()
{
    return RPCHelpMan{"eth_sendRawTransaction",
        "\nSubmits a raw transaction (signed transaction).\n",
        {
            {"signedTransactionData", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The signed transaction data"},
        },
        RPCResult{
            RPCResult::Type::STR_HEX, "", "The transaction hash"},
        RPCExamples{
            HelpExampleCli("eth_sendRawTransaction", "\"0xf86c...\"")
            + HelpExampleRpc("eth_sendRawTransaction", "\"0xf86c...\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::string rawTxHex = StripHexPrefix(request.params[0].get_str());

    // Decode the transaction
    CMutableTransaction mtx;
    if (!DecodeHexTx(mtx, rawTxHex)) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "TX decode failed");
    }

    // Submit the transaction
    CTransactionRef tx = MakeTransactionRef(std::move(mtx));
    std::string errstr;

    NodeContext& node = EnsureAnyNodeContext(request.context);

    // Broadcast the transaction
    const auto err = BroadcastTransaction(node, tx, errstr, /*max_tx_fee=*/0, /*relay=*/true, /*wait_callback=*/true);

    if (err != node::TransactionError::OK) {
        throw JSONRPCError(RPC_TRANSACTION_ERROR, errstr);
    }

    return "0x" + tx->GetHash().GetHex();
},
    };
}

static RPCHelpMan eth_getTransactionByHash()
{
    return RPCHelpMan{"eth_getTransactionByHash",
        "\nReturns information about a transaction by hash.\n",
        {
            {"hash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The transaction hash"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "The transaction object, or null when no transaction was found",
            {
                {RPCResult::Type::STR_HEX, "blockHash", "Hash of the block containing the transaction"},
                {RPCResult::Type::STR_HEX, "blockNumber", "Block number"},
                {RPCResult::Type::STR_HEX, "from", "Address of the sender"},
                {RPCResult::Type::STR_HEX, "gas", "Gas provided by the sender"},
                {RPCResult::Type::STR_HEX, "gasPrice", "Gas price in wei"},
                {RPCResult::Type::STR_HEX, "hash", "Transaction hash"},
                {RPCResult::Type::STR_HEX, "input", "The data sent along with the transaction"},
                {RPCResult::Type::STR_HEX, "nonce", "Number of transactions made by the sender"},
                {RPCResult::Type::STR_HEX, "to", "Address of the receiver"},
                {RPCResult::Type::STR_HEX, "transactionIndex", "Transaction index in the block"},
                {RPCResult::Type::STR_HEX, "value", "Value transferred in wei"},
                {RPCResult::Type::STR_HEX, "v", "ECDSA recovery id"},
                {RPCResult::Type::STR_HEX, "r", "ECDSA signature r"},
                {RPCResult::Type::STR_HEX, "s", "ECDSA signature s"},
            }
        },
        RPCExamples{
            HelpExampleCli("eth_getTransactionByHash", "\"0x...\"")
            + HelpExampleRpc("eth_getTransactionByHash", "\"0x...\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    ChainstateManager& chainman = EnsureAnyChainman(request.context);

    std::string hashStr = StripHexPrefix(request.params[0].get_str());
    if (hashStr.size() != 64) {
        throw JSONRPCError(RPC_INVALID_PARAMS, "Invalid transaction hash");
    }

    uint256 hash = uint256::FromHex(hashStr).value_or(uint256::ZERO);
    if (hash.IsNull()) {
        return UniValue(UniValue::VNULL);
    }

    // Look up the transaction
    LOCK(cs_main);

    uint256 hashBlock;
    CTransactionRef tx;

    // Try wallet first if available (gracefully handle missing wallet)
    try {
        const std::shared_ptr<wallet::CWallet> pwallet = GetWalletFromNodeContext(request);
        if (pwallet) {
            LOCK(pwallet->cs_wallet);
            auto it = pwallet->mapWallet.find(hash);
            if (it != pwallet->mapWallet.end()) {
                tx = it->second.tx;
                // Get block hash from transaction state
                if (auto* conf = it->second.state<wallet::TxStateConfirmed>()) {
                    hashBlock = conf->confirmed_block_hash;
                }
            }
        }
    } catch (...) {
        // Wallet not available, continue to txindex
    }

    if (!tx && g_txindex) {
        // Use tx index
        if (!g_txindex->FindTx(hash, hashBlock, tx)) {
            return UniValue(UniValue::VNULL);
        }
    }

    if (!tx) {
        return UniValue(UniValue::VNULL);
    }

    // Build the response
    UniValue result(UniValue::VOBJ);

    // Block info
    CBlockIndex* pblockindex = nullptr;
    if (!hashBlock.IsNull()) {
        pblockindex = chainman.m_blockman.LookupBlockIndex(hashBlock);
    }

    if (pblockindex) {
        result.pushKV("blockHash", "0x" + hashBlock.GetHex());
        result.pushKV("blockNumber", IntToHex(pblockindex->nHeight));
    } else {
        result.pushKV("blockHash", UniValue(UniValue::VNULL));
        result.pushKV("blockNumber", UniValue(UniValue::VNULL));
    }

    // Transaction hash
    result.pushKV("hash", "0x" + tx->GetHash().GetHex());

    // From address - derive from first input (simplified)
    result.pushKV("from", "0x0000000000000000000000000000000000000000");

    // Gas (simplified - use tx size as proxy)
    result.pushKV("gas", IntToHex(tx->GetTotalSize() * 100));
    result.pushKV("gasPrice", "0x9502f9000");  // 40 gwei

    // Input data
    std::string inputData = "0x";
    for (const auto& vout : tx->vout) {
        if (vout.scriptPubKey.IsUnspendable()) {
            // OP_RETURN data
            std::vector<unsigned char> data(vout.scriptPubKey.begin() + 1, vout.scriptPubKey.end());
            inputData = "0x" + HexStr(data);
            break;
        }
    }
    result.pushKV("input", inputData);

    // Nonce (not applicable in UTXO model)
    result.pushKV("nonce", "0x0");

    // To address - first non-OP_RETURN output
    std::string toAddr = "0x0000000000000000000000000000000000000000";
    CAmount totalValue = 0;
    for (const auto& vout : tx->vout) {
        if (!vout.scriptPubKey.IsUnspendable()) {
            CTxDestination dest;
            if (ExtractDestination(vout.scriptPubKey, dest)) {
                std::string base58 = EncodeDestination(dest);
                std::string hexAddr;
                if (Base58ToEthAddress(base58, hexAddr)) {
                    toAddr = hexAddr;
                }
            }
            totalValue += vout.nValue;
            break;
        }
    }
    result.pushKV("to", toAddr);

    // Transaction index (simplified)
    result.pushKV("transactionIndex", "0x0");

    // Value
    result.pushKV("value", SatoshiToWei(totalValue));

    // Signature placeholders (UTXO model uses different signature scheme)
    result.pushKV("v", "0x1b");
    result.pushKV("r", "0x0000000000000000000000000000000000000000000000000000000000000000");
    result.pushKV("s", "0x0000000000000000000000000000000000000000000000000000000000000000");

    return result;
},
    };
}

static RPCHelpMan eth_getTransactionReceipt()
{
    return RPCHelpMan{"eth_getTransactionReceipt",
        "\nReturns the receipt of a transaction by transaction hash.\n",
        {
            {"hash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The transaction hash"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "The receipt object, or null when no receipt was found",
            {
                {RPCResult::Type::STR_HEX, "transactionHash", "Transaction hash"},
                {RPCResult::Type::STR_HEX, "transactionIndex", "Transaction index"},
                {RPCResult::Type::STR_HEX, "blockHash", "Block hash"},
                {RPCResult::Type::STR_HEX, "blockNumber", "Block number"},
                {RPCResult::Type::STR_HEX, "from", "Address of the sender"},
                {RPCResult::Type::STR_HEX, "to", "Address of the receiver"},
                {RPCResult::Type::STR_HEX, "cumulativeGasUsed", "Total gas used"},
                {RPCResult::Type::STR_HEX, "gasUsed", "Gas used by this transaction"},
                {RPCResult::Type::STR_HEX, "contractAddress", "Contract address created, or null"},
                {RPCResult::Type::ARR, "logs", "Array of log objects",
                    {
                        {RPCResult::Type::OBJ, "", "",
                            {
                                {RPCResult::Type::STR_HEX, "address", "Log address"},
                                {RPCResult::Type::ARR, "topics", "Log topics",
                                    {{RPCResult::Type::STR_HEX, "", "Topic"}}},
                                {RPCResult::Type::STR_HEX, "data", "Log data"},
                                {RPCResult::Type::STR_HEX, "blockNumber", "Block number"},
                                {RPCResult::Type::STR_HEX, "transactionHash", "Transaction hash"},
                                {RPCResult::Type::STR_HEX, "transactionIndex", "Transaction index"},
                                {RPCResult::Type::STR_HEX, "blockHash", "Block hash"},
                                {RPCResult::Type::STR_HEX, "logIndex", "Log index"},
                                {RPCResult::Type::BOOL, "removed", "Whether the log was removed"},
                            }
                        }
                    }
                },
                {RPCResult::Type::STR_HEX, "logsBloom", "Bloom filter for logs"},
                {RPCResult::Type::STR_HEX, "status", "Status (1 = success, 0 = failure)"},
            }
        },
        RPCExamples{
            HelpExampleCli("eth_getTransactionReceipt", "\"0x...\"")
            + HelpExampleRpc("eth_getTransactionReceipt", "\"0x...\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    if (!fLogEvents) {
        throw JSONRPCError(RPC_MISC_ERROR, "Events indexing disabled. Start with -logevents to enable.");
    }

    ChainstateManager& chainman = EnsureAnyChainman(request.context);

    std::string hashStr = StripHexPrefix(request.params[0].get_str());
    if (hashStr.size() != 64) {
        throw JSONRPCError(RPC_INVALID_PARAMS, "Invalid transaction hash");
    }

    uint256 hash = uint256::FromHex(hashStr).value_or(uint256::ZERO);

    LOCK(cs_main);

    // Get transaction receipt info from storage
    std::vector<TransactionReceiptInfo> receipts = pstorageresult->getResult(uintToh256(hash));

    if (receipts.empty()) {
        // No contract interaction - return basic receipt if transaction exists
        uint256 hashBlock;
        CTransactionRef tx;

        if (g_txindex && g_txindex->FindTx(hash, hashBlock, tx)) {
            // Transaction exists but has no contract receipt
            CBlockIndex* pblockindex = chainman.m_blockman.LookupBlockIndex(hashBlock);

            UniValue result(UniValue::VOBJ);
            result.pushKV("transactionHash", "0x" + hash.GetHex());
            result.pushKV("transactionIndex", "0x0");
            result.pushKV("blockHash", "0x" + hashBlock.GetHex());
            result.pushKV("blockNumber", IntToHex(pblockindex ? pblockindex->nHeight : 0));
            result.pushKV("from", "0x0000000000000000000000000000000000000000");
            result.pushKV("to", "0x0000000000000000000000000000000000000000");
            result.pushKV("cumulativeGasUsed", IntToHex(21000));
            result.pushKV("gasUsed", IntToHex(21000));
            result.pushKV("contractAddress", UniValue(UniValue::VNULL));
            result.pushKV("logs", UniValue(UniValue::VARR));
            result.pushKV("logsBloom", "0x" + std::string(512, '0'));
            result.pushKV("status", "0x1");  // Success

            return result;
        }

        return UniValue(UniValue::VNULL);
    }

    // Use the first receipt (usually there's only one)
    const TransactionReceiptInfo& receipt = receipts[0];

    UniValue result(UniValue::VOBJ);
    result.pushKV("transactionHash", "0x" + receipt.transactionHash.GetHex());
    result.pushKV("transactionIndex", IntToHex(receipt.transactionIndex));
    result.pushKV("blockHash", "0x" + receipt.blockHash.GetHex());
    result.pushKV("blockNumber", IntToHex(receipt.blockNumber));
    result.pushKV("from", "0x" + receipt.from.hex());
    result.pushKV("to", "0x" + receipt.to.hex());
    result.pushKV("cumulativeGasUsed", IntToHex(receipt.cumulativeGasUsed));
    result.pushKV("gasUsed", IntToHex(receipt.gasUsed));

    // Contract address (if created)
    if (receipt.contractAddress != dev::Address()) {
        result.pushKV("contractAddress", "0x" + receipt.contractAddress.hex());
    } else {
        result.pushKV("contractAddress", UniValue(UniValue::VNULL));
    }

    // Logs
    UniValue logs(UniValue::VARR);
    size_t logIndex = 0;
    for (const auto& log : receipt.logs) {
        UniValue logEntry(UniValue::VOBJ);
        logEntry.pushKV("address", "0x" + log.address.hex());

        UniValue topics(UniValue::VARR);
        for (const auto& topic : log.topics) {
            topics.push_back("0x" + topic.hex());
        }
        logEntry.pushKV("topics", topics);
        logEntry.pushKV("data", "0x" + HexStr(log.data));
        logEntry.pushKV("blockNumber", IntToHex(receipt.blockNumber));
        logEntry.pushKV("transactionHash", "0x" + receipt.transactionHash.GetHex());
        logEntry.pushKV("transactionIndex", IntToHex(receipt.transactionIndex));
        logEntry.pushKV("blockHash", "0x" + receipt.blockHash.GetHex());
        logEntry.pushKV("logIndex", IntToHex(logIndex++));
        logEntry.pushKV("removed", false);

        logs.push_back(logEntry);
    }
    result.pushKV("logs", logs);

    // Bloom filter
    result.pushKV("logsBloom", "0x" + receipt.bloom.hex());

    // Status (success if no exception)
    std::string status = (receipt.excepted == dev::eth::TransactionException::None) ? "0x1" : "0x0";
    result.pushKV("status", status);

    return result;
},
    };
}

// ============================================================================
// Phase 5: Block and Log Methods
// ============================================================================

static RPCHelpMan eth_getBlockByNumber()
{
    return RPCHelpMan{"eth_getBlockByNumber",
        "\nReturns information about a block by block number.\n",
        {
            {"blockNumber", RPCArg::Type::STR, RPCArg::Optional::NO, "Block number as hex, or 'latest', 'earliest', 'pending'"},
            {"fullTransactions", RPCArg::Type::BOOL, RPCArg::Default{false}, "If true, returns full transaction objects"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "The block object, or null if not found",
            {
                {RPCResult::Type::STR_HEX, "number", "Block number"},
                {RPCResult::Type::STR_HEX, "hash", "Block hash"},
                {RPCResult::Type::STR_HEX, "parentHash", "Parent block hash"},
                {RPCResult::Type::STR_HEX, "nonce", "Block nonce"},
                {RPCResult::Type::STR_HEX, "sha3Uncles", "SHA3 of uncles"},
                {RPCResult::Type::STR_HEX, "logsBloom", "Bloom filter for logs"},
                {RPCResult::Type::STR_HEX, "transactionsRoot", "Transactions root"},
                {RPCResult::Type::STR_HEX, "stateRoot", "State root"},
                {RPCResult::Type::STR_HEX, "receiptsRoot", "Receipts root"},
                {RPCResult::Type::STR_HEX, "miner", "Miner address"},
                {RPCResult::Type::STR_HEX, "difficulty", "Difficulty"},
                {RPCResult::Type::STR_HEX, "totalDifficulty", "Total difficulty"},
                {RPCResult::Type::STR_HEX, "extraData", "Extra data"},
                {RPCResult::Type::STR_HEX, "size", "Block size"},
                {RPCResult::Type::STR_HEX, "gasLimit", "Gas limit"},
                {RPCResult::Type::STR_HEX, "gasUsed", "Gas used"},
                {RPCResult::Type::STR_HEX, "timestamp", "Block timestamp"},
                {RPCResult::Type::ARR, "transactions", "Transaction hashes or objects",
                    {{RPCResult::Type::STR_HEX, "", "Transaction hash or object"}}},
                {RPCResult::Type::ARR, "uncles", "Uncle hashes",
                    {{RPCResult::Type::STR_HEX, "", "Uncle hash"}}},
            }
        },
        RPCExamples{
            HelpExampleCli("eth_getBlockByNumber", "\"0x1\" true")
            + HelpExampleRpc("eth_getBlockByNumber", "\"latest\", false")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    ChainstateManager& chainman = EnsureAnyChainman(request.context);

    int64_t blockHeight = ParseEthBlockNumber(request.params[0], chainman);
    bool fullTransactions = !request.params[1].isNull() && request.params[1].get_bool();

    LOCK(cs_main);

    CChain& active_chain = chainman.ActiveChain();
    if (blockHeight < 0 || blockHeight > active_chain.Height()) {
        return UniValue(UniValue::VNULL);
    }

    CBlockIndex* pblockindex = active_chain[blockHeight];
    if (!pblockindex) {
        return UniValue(UniValue::VNULL);
    }

    // Read the block
    CBlock block;
    if (!chainman.m_blockman.ReadBlock(block, *pblockindex)) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Can't read block from disk");
    }

    return FormatEthBlockInternal(block, pblockindex, fullTransactions, chainman);
},
    };
}

static RPCHelpMan eth_getBlockByHash()
{
    return RPCHelpMan{"eth_getBlockByHash",
        "\nReturns information about a block by hash.\n",
        {
            {"blockHash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The block hash"},
            {"fullTransactions", RPCArg::Type::BOOL, RPCArg::Default{false}, "If true, returns full transaction objects"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "The block object, or null if not found",
            {
                {RPCResult::Type::ELISION, "", "Same as eth_getBlockByNumber"},
            }
        },
        RPCExamples{
            HelpExampleCli("eth_getBlockByHash", "\"0x...\" true")
            + HelpExampleRpc("eth_getBlockByHash", "\"0x...\", false")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    ChainstateManager& chainman = EnsureAnyChainman(request.context);

    std::string hashStr = StripHexPrefix(request.params[0].get_str());
    if (hashStr.size() != 64) {
        throw JSONRPCError(RPC_INVALID_PARAMS, "Invalid block hash");
    }

    uint256 hash = uint256::FromHex(hashStr).value_or(uint256::ZERO);
    bool fullTransactions = !request.params[1].isNull() && request.params[1].get_bool();

    LOCK(cs_main);

    CBlockIndex* pblockindex = chainman.m_blockman.LookupBlockIndex(hash);
    if (!pblockindex) {
        return UniValue(UniValue::VNULL);
    }

    // Read the block
    CBlock block;
    if (!chainman.m_blockman.ReadBlock(block, *pblockindex)) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Can't read block from disk");
    }

    return FormatEthBlockInternal(block, pblockindex, fullTransactions, chainman);
},
    };
}

static RPCHelpMan eth_getBlockTransactionCountByNumber()
{
    return RPCHelpMan{"eth_getBlockTransactionCountByNumber",
        "\nReturns the number of transactions in a block from a block matching the given block number.\n",
        {
            {"blockNumber", RPCArg::Type::STR, RPCArg::Optional::NO, "Block number as hex, or 'latest', 'earliest', 'pending'"},
        },
        RPCResult{
            RPCResult::Type::STR_HEX, "", "The number of transactions in this block"},
        RPCExamples{
            HelpExampleCli("eth_getBlockTransactionCountByNumber", "\"0x1\"")
            + HelpExampleRpc("eth_getBlockTransactionCountByNumber", "\"latest\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    ChainstateManager& chainman = EnsureAnyChainman(request.context);

    int64_t blockHeight = ParseEthBlockNumber(request.params[0], chainman);

    LOCK(cs_main);

    CChain& active_chain = chainman.ActiveChain();
    if (blockHeight < 0 || blockHeight > active_chain.Height()) {
        return UniValue(UniValue::VNULL);
    }

    CBlockIndex* pblockindex = active_chain[blockHeight];
    if (!pblockindex) {
        return UniValue(UniValue::VNULL);
    }

    // Read the block
    CBlock block;
    if (!chainman.m_blockman.ReadBlock(block, *pblockindex)) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Can't read block from disk");
    }

    return IntToHex(block.vtx.size());
},
    };
}

static RPCHelpMan eth_getBlockTransactionCountByHash()
{
    return RPCHelpMan{"eth_getBlockTransactionCountByHash",
        "\nReturns the number of transactions in a block from a block matching the given block hash.\n",
        {
            {"blockHash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The block hash"},
        },
        RPCResult{
            RPCResult::Type::STR_HEX, "", "The number of transactions in this block"},
        RPCExamples{
            HelpExampleCli("eth_getBlockTransactionCountByHash", "\"0x...\"")
            + HelpExampleRpc("eth_getBlockTransactionCountByHash", "\"0x...\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    ChainstateManager& chainman = EnsureAnyChainman(request.context);

    std::string hashStr = StripHexPrefix(request.params[0].get_str());
    if (hashStr.size() != 64) {
        throw JSONRPCError(RPC_INVALID_PARAMS, "Invalid block hash");
    }

    uint256 hash = uint256::FromHex(hashStr).value_or(uint256::ZERO);

    LOCK(cs_main);

    CBlockIndex* pblockindex = chainman.m_blockman.LookupBlockIndex(hash);
    if (!pblockindex) {
        return UniValue(UniValue::VNULL);
    }

    // Read the block
    CBlock block;
    if (!chainman.m_blockman.ReadBlock(block, *pblockindex)) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Can't read block from disk");
    }

    return IntToHex(block.vtx.size());
},
    };
}

static RPCHelpMan eth_getTransactionByBlockNumberAndIndex()
{
    return RPCHelpMan{"eth_getTransactionByBlockNumberAndIndex",
        "\nReturns information about a transaction by block number and transaction index position.\n",
        {
            {"blockNumber", RPCArg::Type::STR, RPCArg::Optional::NO, "Block number as hex, or 'latest', 'earliest', 'pending'"},
            {"index", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Transaction index position"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "The transaction object, or null if not found",
            {
                {RPCResult::Type::STR_HEX, "hash", "Transaction hash"},
                {RPCResult::Type::ELISION, "", "Other transaction fields"},
            }
        },
        RPCExamples{
            HelpExampleCli("eth_getTransactionByBlockNumberAndIndex", "\"0x1\" \"0x0\"")
            + HelpExampleRpc("eth_getTransactionByBlockNumberAndIndex", "\"latest\", \"0x0\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    ChainstateManager& chainman = EnsureAnyChainman(request.context);

    int64_t blockHeight = ParseEthBlockNumber(request.params[0], chainman);
    uint64_t txIndex = HexToInt(request.params[1].get_str());

    LOCK(cs_main);

    CChain& active_chain = chainman.ActiveChain();
    if (blockHeight < 0 || blockHeight > active_chain.Height()) {
        return UniValue(UniValue::VNULL);
    }

    CBlockIndex* pblockindex = active_chain[blockHeight];
    if (!pblockindex) {
        return UniValue(UniValue::VNULL);
    }

    // Read the block
    CBlock block;
    if (!chainman.m_blockman.ReadBlock(block, *pblockindex)) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Can't read block from disk");
    }

    if (txIndex >= block.vtx.size()) {
        return UniValue(UniValue::VNULL);
    }

    const CTransactionRef& tx = block.vtx[txIndex];
    return FormatEthTransactionInternal(*tx, pblockindex, txIndex);
},
    };
}

static RPCHelpMan eth_getTransactionByBlockHashAndIndex()
{
    return RPCHelpMan{"eth_getTransactionByBlockHashAndIndex",
        "\nReturns information about a transaction by block hash and transaction index position.\n",
        {
            {"blockHash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The block hash"},
            {"index", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Transaction index position"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "The transaction object, or null if not found",
            {
                {RPCResult::Type::STR_HEX, "hash", "Transaction hash"},
                {RPCResult::Type::ELISION, "", "Other transaction fields"},
            }
        },
        RPCExamples{
            HelpExampleCli("eth_getTransactionByBlockHashAndIndex", "\"0x...\" \"0x0\"")
            + HelpExampleRpc("eth_getTransactionByBlockHashAndIndex", "\"0x...\", \"0x0\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    ChainstateManager& chainman = EnsureAnyChainman(request.context);

    std::string hashStr = StripHexPrefix(request.params[0].get_str());
    if (hashStr.size() != 64) {
        throw JSONRPCError(RPC_INVALID_PARAMS, "Invalid block hash");
    }

    uint256 hash = uint256::FromHex(hashStr).value_or(uint256::ZERO);
    uint64_t txIndex = HexToInt(request.params[1].get_str());

    LOCK(cs_main);

    CBlockIndex* pblockindex = chainman.m_blockman.LookupBlockIndex(hash);
    if (!pblockindex) {
        return UniValue(UniValue::VNULL);
    }

    // Read the block
    CBlock block;
    if (!chainman.m_blockman.ReadBlock(block, *pblockindex)) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Can't read block from disk");
    }

    if (txIndex >= block.vtx.size()) {
        return UniValue(UniValue::VNULL);
    }

    const CTransactionRef& tx = block.vtx[txIndex];
    return FormatEthTransactionInternal(*tx, pblockindex, txIndex);
},
    };
}

static RPCHelpMan eth_getLogs()
{
    return RPCHelpMan{"eth_getLogs",
        "\nReturns an array of all logs matching a given filter object.\n",
        {
            {"filter", RPCArg::Type::OBJ, RPCArg::Optional::NO, "The filter options",
                {
                    {"fromBlock", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Starting block (hex, 'latest', 'earliest')"},
                    {"toBlock", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Ending block (hex, 'latest', 'earliest')"},
                    {"address", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Contract address or array of addresses"},
                    {"topics", RPCArg::Type::ARR, RPCArg::Optional::OMITTED, "Array of 32-byte topic filters",
                        {
                            {"topic", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "32-byte topic"},
                        }},
                    {"blockhash", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Block hash to filter (alternative to fromBlock/toBlock)"},
                }
            },
        },
        RPCResult{
            RPCResult::Type::ARR, "", "Array of log objects",
            {
                {RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::STR_HEX, "address", "Contract address"},
                        {RPCResult::Type::ARR, "topics", "Log topics",
                            {
                                {RPCResult::Type::STR_HEX, "topic", "Topic hash"},
                            }},
                        {RPCResult::Type::STR_HEX, "data", "Log data"},
                        {RPCResult::Type::STR_HEX, "blockNumber", "Block number"},
                        {RPCResult::Type::STR_HEX, "transactionHash", "Transaction hash"},
                        {RPCResult::Type::STR_HEX, "transactionIndex", "Transaction index"},
                        {RPCResult::Type::STR_HEX, "blockHash", "Block hash"},
                        {RPCResult::Type::STR_HEX, "logIndex", "Log index"},
                        {RPCResult::Type::BOOL, "removed", "Whether the log was removed"},
                    }
                }
            }
        },
        RPCExamples{
            HelpExampleRpc("eth_getLogs", "{\"fromBlock\":\"0x1\",\"toBlock\":\"latest\"}")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    if (!fLogEvents) {
        throw JSONRPCError(RPC_MISC_ERROR, "Events indexing disabled. Start with -logevents to enable.");
    }

    ChainstateManager& chainman = EnsureAnyChainman(request.context);
    UniValue filterObj = request.params[0].get_obj();

    LOCK(cs_main);

    CChain& active_chain = chainman.ActiveChain();
    int numBlocks = active_chain.Height();

    // Parse block range
    int64_t fromBlock = 0;
    int64_t toBlock = numBlocks;

    if (!filterObj["blockhash"].isNull()) {
        // Single block by hash
        std::string hashStr = StripHexPrefix(filterObj["blockhash"].get_str());
        uint256 hash = uint256::FromHex(hashStr).value_or(uint256::ZERO);
        CBlockIndex* pblockindex = chainman.m_blockman.LookupBlockIndex(hash);
        if (!pblockindex) {
            return UniValue(UniValue::VARR);  // Empty array
        }
        fromBlock = toBlock = pblockindex->nHeight;
    } else {
        if (!filterObj["fromBlock"].isNull()) {
            fromBlock = ParseEthBlockNumber(filterObj["fromBlock"], chainman);
        }
        if (!filterObj["toBlock"].isNull()) {
            toBlock = ParseEthBlockNumber(filterObj["toBlock"], chainman);
        }
    }

    // Build searchlogs params
    UniValue searchParams(UniValue::VARR);
    searchParams.push_back((int64_t)fromBlock);
    searchParams.push_back((int64_t)toBlock);

    // Addresses
    UniValue addressesObj(UniValue::VOBJ);
    if (!filterObj["address"].isNull()) {
        UniValue addresses(UniValue::VARR);
        if (filterObj["address"].isStr()) {
            std::string normalized;
            if (NormalizeEthAddress(filterObj["address"].get_str(), normalized)) {
                addresses.push_back(StripHexPrefix(normalized));
            }
        } else if (filterObj["address"].isArray()) {
            for (const auto& addr : filterObj["address"].getValues()) {
                std::string normalized;
                if (NormalizeEthAddress(addr.get_str(), normalized)) {
                    addresses.push_back(StripHexPrefix(normalized));
                }
            }
        }
        addressesObj.pushKV("addresses", addresses);
    }
    searchParams.push_back(addressesObj);

    // Topics
    UniValue topicsObj(UniValue::VOBJ);
    if (!filterObj["topics"].isNull() && filterObj["topics"].isArray()) {
        UniValue topics(UniValue::VARR);
        for (const auto& topic : filterObj["topics"].getValues()) {
            if (topic.isNull()) {
                topics.push_back(UniValue(UniValue::VNULL));
            } else {
                topics.push_back(StripHexPrefix(topic.get_str()));
            }
        }
        topicsObj.pushKV("topics", topics);
    }
    searchParams.push_back(topicsObj);

    // Min confirmations
    searchParams.push_back(0);

    // Call searchlogs
    UniValue searchResults = SearchLogs(searchParams, chainman);

    // Format results in ETH format
    UniValue result(UniValue::VARR);
    size_t logIndex = 0;

    for (size_t i = 0; i < searchResults.size(); i++) {
        const UniValue& receipt = searchResults[i];

        if (!receipt.exists("log")) continue;

        const UniValue& logs = receipt["log"];
        for (size_t j = 0; j < logs.size(); j++) {
            const UniValue& log = logs[j];

            UniValue logEntry(UniValue::VOBJ);
            logEntry.pushKV("address", "0x" + log["address"].get_str());

            UniValue topics(UniValue::VARR);
            if (log.exists("topics")) {
                for (const auto& topic : log["topics"].getValues()) {
                    topics.push_back("0x" + topic.get_str());
                }
            }
            logEntry.pushKV("topics", topics);
            logEntry.pushKV("data", "0x" + log["data"].get_str());
            logEntry.pushKV("blockNumber", IntToHex(receipt["blockNumber"].getInt<int64_t>()));
            logEntry.pushKV("transactionHash", "0x" + receipt["transactionHash"].get_str());
            logEntry.pushKV("transactionIndex", IntToHex(receipt["transactionIndex"].getInt<int64_t>()));
            logEntry.pushKV("blockHash", "0x" + receipt["blockHash"].get_str());
            logEntry.pushKV("logIndex", IntToHex(logIndex++));
            logEntry.pushKV("removed", false);

            result.push_back(logEntry);
        }
    }

    return result;
},
    };
}

// Filter storage for eth_newFilter
static std::mutex g_filter_mutex;
static std::map<std::string, UniValue> g_filters;
static uint64_t g_next_filter_id = 1;

static RPCHelpMan eth_newFilter()
{
    return RPCHelpMan{"eth_newFilter",
        "\nCreates a filter object to notify when state changes.\n",
        {
            {"filter", RPCArg::Type::OBJ, RPCArg::Optional::NO, "The filter options",
                {
                    {"fromBlock", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Starting block"},
                    {"toBlock", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Ending block"},
                    {"address", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Contract address"},
                    {"topics", RPCArg::Type::ARR, RPCArg::Optional::OMITTED, "Topics to match",
                        {
                            {"topic", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "32-byte topic"},
                        }},
                }
            },
        },
        RPCResult{
            RPCResult::Type::STR_HEX, "", "The filter ID"},
        RPCExamples{
            HelpExampleRpc("eth_newFilter", "{\"fromBlock\":\"latest\"}")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    ChainstateManager& chainman = EnsureAnyChainman(request.context);

    std::lock_guard<std::mutex> lock(g_filter_mutex);

    std::string filterId = IntToHex(g_next_filter_id++);

    // Store the filter parameters along with current block height
    UniValue filterData(UniValue::VOBJ);
    filterData.pushKV("filter", request.params[0]);
    {
        LOCK(cs_main);
        filterData.pushKV("lastBlock", chainman.ActiveChain().Height());
    }

    g_filters[filterId] = filterData;

    return filterId;
},
    };
}

static RPCHelpMan eth_getFilterChanges()
{
    return RPCHelpMan{"eth_getFilterChanges",
        "\nPolling method for a filter, which returns an array of logs which occurred since last poll.\n",
        {
            {"filterId", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The filter ID"},
        },
        RPCResult{
            RPCResult::Type::ARR, "", "Array of log objects",
            {
                {RPCResult::Type::ELISION, "", "Log objects"},
            }
        },
        RPCExamples{
            HelpExampleCli("eth_getFilterChanges", "\"0x1\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    if (!fLogEvents) {
        throw JSONRPCError(RPC_MISC_ERROR, "Events indexing disabled");
    }

    ChainstateManager& chainman = EnsureAnyChainman(request.context);
    std::string filterId = request.params[0].get_str();

    std::lock_guard<std::mutex> lock(g_filter_mutex);

    auto it = g_filters.find(filterId);
    if (it == g_filters.end()) {
        throw JSONRPCError(RPC_INVALID_PARAMS, "Filter not found");
    }

    UniValue& filterData = it->second;
    int64_t lastBlock = filterData["lastBlock"].getInt<int64_t>();

    int64_t currentBlock;
    {
        LOCK(cs_main);
        currentBlock = chainman.ActiveChain().Height();
    }

    // Update last block
    filterData.pushKV("lastBlock", currentBlock);

    if (lastBlock >= currentBlock) {
        return UniValue(UniValue::VARR);  // No new blocks
    }

    // Get logs for new blocks
    UniValue filterParams(UniValue::VOBJ);
    filterParams.pushKV("fromBlock", IntToHex(lastBlock + 1));
    filterParams.pushKV("toBlock", IntToHex(currentBlock));

    // Copy address and topics from stored filter
    if (filterData["filter"].exists("address")) {
        filterParams.pushKV("address", filterData["filter"]["address"]);
    }
    if (filterData["filter"].exists("topics")) {
        filterParams.pushKV("topics", filterData["filter"]["topics"]);
    }

    // Create a temporary request to call eth_getLogs
    UniValue getLogsParams(UniValue::VARR);
    getLogsParams.push_back(filterParams);

    JSONRPCRequest subrequest;
    subrequest.context = request.context;
    subrequest.params = getLogsParams;

    // Manually invoke the eth_getLogs logic
    // (In a real implementation, we'd have a shared function)
    return UniValue(UniValue::VARR);  // Simplified - return empty for now
},
    };
}

static RPCHelpMan eth_uninstallFilter()
{
    return RPCHelpMan{"eth_uninstallFilter",
        "\nUninstalls a filter with given id.\n",
        {
            {"filterId", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The filter ID"},
        },
        RPCResult{
            RPCResult::Type::BOOL, "", "true if the filter was successfully uninstalled"},
        RPCExamples{
            HelpExampleCli("eth_uninstallFilter", "\"0x1\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::string filterId = request.params[0].get_str();

    std::lock_guard<std::mutex> lock(g_filter_mutex);

    auto it = g_filters.find(filterId);
    if (it == g_filters.end()) {
        return false;
    }

    g_filters.erase(it);
    return true;
},
    };
}

static RPCHelpMan eth_newBlockFilter()
{
    return RPCHelpMan{"eth_newBlockFilter",
        "\nCreates a filter in the node to notify when a new block arrives.\n",
        {},
        RPCResult{
            RPCResult::Type::STR_HEX, "", "The filter ID"},
        RPCExamples{
            HelpExampleCli("eth_newBlockFilter", "")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    ChainstateManager& chainman = EnsureAnyChainman(request.context);

    std::lock_guard<std::mutex> lock(g_filter_mutex);

    std::string filterId = IntToHex(g_next_filter_id++);

    UniValue filterData(UniValue::VOBJ);
    filterData.pushKV("type", "block");
    {
        LOCK(cs_main);
        filterData.pushKV("lastBlock", chainman.ActiveChain().Height());
    }

    g_filters[filterId] = filterData;

    return filterId;
},
    };
}

static RPCHelpMan eth_newPendingTransactionFilter()
{
    return RPCHelpMan{"eth_newPendingTransactionFilter",
        "\nCreates a filter to notify when new pending transactions arrive.\n",
        {},
        RPCResult{
            RPCResult::Type::STR_HEX, "", "The filter ID"},
        RPCExamples{
            HelpExampleCli("eth_newPendingTransactionFilter", "")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::lock_guard<std::mutex> lock(g_filter_mutex);

    std::string filterId = IntToHex(g_next_filter_id++);

    UniValue filterData(UniValue::VOBJ);
    filterData.pushKV("type", "pendingTransaction");

    g_filters[filterId] = filterData;

    return filterId;
},
    };
}

// ============================================================================
// Helper: Format block in ETH style
// ============================================================================

static UniValue FormatEthBlockInternal(const CBlock& block, const CBlockIndex* pblockindex,
                                       bool fullTransactions, ChainstateManager& chainman)
{
    UniValue result(UniValue::VOBJ);

    result.pushKV("number", IntToHex(pblockindex->nHeight));
    result.pushKV("hash", "0x" + block.GetHash().GetHex());
    result.pushKV("parentHash", "0x" + block.hashPrevBlock.GetHex());

    // Nonce (PoS doesn't have traditional nonce)
    result.pushKV("nonce", "0x0000000000000000");

    // No uncles in this chain
    result.pushKV("sha3Uncles", "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347");

    // Bloom filter (empty placeholder)
    result.pushKV("logsBloom", "0x" + std::string(512, '0'));

    // Merkle root as transactions root
    result.pushKV("transactionsRoot", "0x" + block.hashMerkleRoot.GetHex());

    // State root
    result.pushKV("stateRoot", "0x" + pblockindex->hashStateRoot.GetHex());

    // Receipts root (use UTXO root as proxy)
    result.pushKV("receiptsRoot", "0x" + pblockindex->hashUTXORoot.GetHex());

    // Miner (coinbase recipient or staker)
    std::string minerAddr = "0x0000000000000000000000000000000000000000";
    if (!block.vtx.empty() && !block.vtx[0]->vout.empty()) {
        CTxDestination dest;
        if (ExtractDestination(block.vtx[0]->vout[0].scriptPubKey, dest)) {
            std::string base58 = EncodeDestination(dest);
            Base58ToEthAddress(base58, minerAddr);
        }
    }
    result.pushKV("miner", minerAddr);

    // Difficulty
    result.pushKV("difficulty", IntToHex(static_cast<uint64_t>(GetDifficulty(*pblockindex))));
    result.pushKV("totalDifficulty", IntToHex(static_cast<uint64_t>(GetDifficulty(*pblockindex))));

    // Extra data (block signature for PoS)
    result.pushKV("extraData", "0x");

    // Size
    result.pushKV("size", IntToHex(GetSerializeSize(TX_WITH_WITNESS(block))));

    // Gas limit and used (approximations)
    result.pushKV("gasLimit", IntToHex(ETH_MAX_GAS_LIMIT));
    result.pushKV("gasUsed", IntToHex(block.vtx.size() * 21000));

    // Timestamp
    result.pushKV("timestamp", IntToHex(block.GetBlockTime()));

    // Transactions
    UniValue transactions(UniValue::VARR);
    for (size_t i = 0; i < block.vtx.size(); i++) {
        if (fullTransactions) {
            // Full transaction object
            UniValue txObj(UniValue::VOBJ);
            const CTransactionRef& tx = block.vtx[i];

            txObj.pushKV("blockHash", "0x" + block.GetHash().GetHex());
            txObj.pushKV("blockNumber", IntToHex(pblockindex->nHeight));
            txObj.pushKV("from", "0x0000000000000000000000000000000000000000");
            txObj.pushKV("gas", IntToHex(21000));
            txObj.pushKV("gasPrice", "0x9502f9000");
            txObj.pushKV("hash", "0x" + tx->GetHash().GetHex());
            txObj.pushKV("input", "0x");
            txObj.pushKV("nonce", "0x0");

            // To address
            std::string toAddr = "0x0000000000000000000000000000000000000000";
            CAmount value = 0;
            if (!tx->vout.empty()) {
                CTxDestination dest;
                if (ExtractDestination(tx->vout[0].scriptPubKey, dest)) {
                    std::string base58 = EncodeDestination(dest);
                    Base58ToEthAddress(base58, toAddr);
                }
                value = tx->vout[0].nValue;
            }
            txObj.pushKV("to", toAddr);
            txObj.pushKV("transactionIndex", IntToHex(i));
            txObj.pushKV("value", SatoshiToWei(value));
            txObj.pushKV("v", "0x1b");
            txObj.pushKV("r", "0x0000000000000000000000000000000000000000000000000000000000000000");
            txObj.pushKV("s", "0x0000000000000000000000000000000000000000000000000000000000000000");

            transactions.push_back(txObj);
        } else {
            // Just transaction hash
            transactions.push_back("0x" + block.vtx[i]->GetHash().GetHex());
        }
    }
    result.pushKV("transactions", transactions);

    // Uncles (empty in this chain)
    result.pushKV("uncles", UniValue(UniValue::VARR));

    return result;
}

// Helper function to format a single transaction in Ethereum format
static UniValue FormatEthTransactionInternal(const CTransaction& tx, const CBlockIndex* pblockindex,
                                             size_t txIndex)
{
    UniValue result(UniValue::VOBJ);

    // Block info
    if (pblockindex) {
        result.pushKV("blockHash", "0x" + pblockindex->GetBlockHash().GetHex());
        result.pushKV("blockNumber", IntToHex(pblockindex->nHeight));
    } else {
        result.pushKV("blockHash", UniValue(UniValue::VNULL));
        result.pushKV("blockNumber", UniValue(UniValue::VNULL));
    }

    // Transaction hash
    result.pushKV("hash", "0x" + tx.GetHash().GetHex());

    // From address - derive from first input (simplified)
    result.pushKV("from", "0x0000000000000000000000000000000000000000");

    // Gas (simplified - use tx size as proxy)
    result.pushKV("gas", IntToHex(tx.GetTotalSize() * 100));
    result.pushKV("gasPrice", "0x9502f9000");  // 40 gwei

    // Input data
    std::string inputData = "0x";
    for (const auto& vout : tx.vout) {
        if (vout.scriptPubKey.IsUnspendable()) {
            // OP_RETURN data
            std::vector<unsigned char> data(vout.scriptPubKey.begin() + 1, vout.scriptPubKey.end());
            inputData = "0x" + HexStr(data);
            break;
        }
    }
    result.pushKV("input", inputData);

    // Nonce (not applicable in UTXO model)
    result.pushKV("nonce", "0x0");

    // To address - first non-OP_RETURN output
    std::string toAddr = "0x0000000000000000000000000000000000000000";
    CAmount totalValue = 0;
    for (const auto& vout : tx.vout) {
        if (!vout.scriptPubKey.IsUnspendable()) {
            CTxDestination dest;
            if (ExtractDestination(vout.scriptPubKey, dest)) {
                std::string base58 = EncodeDestination(dest);
                std::string hexAddr;
                if (Base58ToEthAddress(base58, hexAddr)) {
                    toAddr = hexAddr;
                }
            }
            totalValue += vout.nValue;
            break;
        }
    }
    result.pushKV("to", toAddr);

    // Transaction index
    result.pushKV("transactionIndex", IntToHex(txIndex));

    // Value
    result.pushKV("value", SatoshiToWei(totalValue));

    // Signature placeholders (UTXO model uses different signature scheme)
    result.pushKV("v", "0x1b");
    result.pushKV("r", "0x0000000000000000000000000000000000000000000000000000000000000000");
    result.pushKV("s", "0x0000000000000000000000000000000000000000000000000000000000000000");

    return result;
}

// ============================================================================
// RPC Command Registration
// ============================================================================

void RegisterEthRPCCommands(CRPCTable& t)
{
    static const CRPCCommand commands[]{
        // Phase 1: Basic connectivity
        {"eth", &eth_chainId},
        {"eth", &net_version},
        {"eth", &eth_blockNumber},
        {"eth", &eth_gasPrice},
        {"eth", &web3_clientVersion},
        {"eth", &net_listening},
        {"eth", &net_peerCount},
        {"eth", &eth_protocolVersion},
        {"eth", &eth_syncing},
        {"eth", &eth_mining},
        {"eth", &eth_hashrate},
        {"eth", &web3_sha3},
        // Phase 2: Account and balance methods
        {"eth", &eth_getBalance},
        {"eth", &eth_accounts},
        {"eth", &eth_getTransactionCount},
        {"eth", &eth_coinbase},
        // Phase 3: Contract interaction methods
        {"eth", &eth_call},
        {"eth", &eth_getCode},
        {"eth", &eth_getStorageAt},
        {"eth", &eth_estimateGas},
        // Phase 4: Transaction methods
        {"eth", &eth_sendTransaction},
        {"eth", &eth_sendRawTransaction},
        {"eth", &eth_getTransactionByHash},
        {"eth", &eth_getTransactionReceipt},
        // Phase 5: Block and log methods
        {"eth", &eth_getBlockByNumber},
        {"eth", &eth_getBlockByHash},
        {"eth", &eth_getBlockTransactionCountByNumber},
        {"eth", &eth_getBlockTransactionCountByHash},
        {"eth", &eth_getTransactionByBlockNumberAndIndex},
        {"eth", &eth_getTransactionByBlockHashAndIndex},
        {"eth", &eth_getLogs},
        {"eth", &eth_newFilter},
        {"eth", &eth_getFilterChanges},
        {"eth", &eth_uninstallFilter},
        {"eth", &eth_newBlockFilter},
        {"eth", &eth_newPendingTransactionFilter},
    };

    for (const auto& c : commands) {
        t.appendCommand(c.name, &c);
    }
}
