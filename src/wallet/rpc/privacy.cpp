// Copyright (c) 2024-2026 The WATTx Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <rpc/server.h>
#include <rpc/server_util.h>
#include <rpc/util.h>
#include <core_io.h>
#include <wallet/rpc/util.h>
#include <wallet/wallet.h>
#include <wallet/receive.h>
#include <wallet/spend.h>
#include <wallet/coincontrol.h>
#include <wallet/stealth_wallet.h>
#include <wallet/privacy_wallet.h>
#include <wallet/fcmp_wallet.h>
#include <privacy/privacy.h>
#include <privacy/curvetree/curve_tree.h>
#include <key_io.h>
#include <util/strencodings.h>
#include <util/moneystr.h>

#include <univalue.h>

// Helper to get wallet's FCMP manager (initialized during wallet creation)
static wallet::CFcmpWalletManager* GetFcmpManager(const std::shared_ptr<const wallet::CWallet>& pwallet) {
    return const_cast<wallet::CWallet*>(pwallet.get())->GetFcmpWalletManager();
}

namespace wallet {

static RPCHelpMan getnewstealthaddress()
{
    return RPCHelpMan{"getnewstealthaddress",
        "\nGenerates a new stealth address for receiving private payments.\n",
        {
            {"label", RPCArg::Type::STR, RPCArg::Default{""}, "A label for the stealth address."},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR, "address", "The new stealth address"},
                {RPCResult::Type::STR, "scan_pubkey", "The scan public key (hex)"},
                {RPCResult::Type::STR, "spend_pubkey", "The spend public key (hex)"},
                {RPCResult::Type::STR, "label", "The label for the stealth address"},
            }
        },
        RPCExamples{
            HelpExampleCli("getnewstealthaddress", "\"\"")
            + HelpExampleCli("getnewstealthaddress", "\"my label\"")
            + HelpExampleRpc("getnewstealthaddress", "\"my label\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            const std::shared_ptr<const CWallet> pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;

            LOCK(pwallet->cs_wallet);

            std::string label;
            if (!request.params[0].isNull()) {
                label = request.params[0].get_str();
            }

            // Use the wallet's internal stealth address manager
            auto* stealthMgr = const_cast<CWallet*>(pwallet.get())->GetStealthAddressManager();
            if (!stealthMgr) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Stealth address manager not initialized");
            }

            CStealthAddressData addressData;
            if (!stealthMgr->GenerateStealthAddress(label, addressData)) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Failed to generate stealth address");
            }

            UniValue result(UniValue::VOBJ);
            result.pushKV("address", addressData.address.ToString());
            result.pushKV("scan_pubkey", HexStr(addressData.address.scanPubKey));
            result.pushKV("spend_pubkey", HexStr(addressData.address.spendPubKey));
            result.pushKV("label", addressData.label);

            return result;
        },
    };
}

static RPCHelpMan liststealthaddresses()
{
    return RPCHelpMan{"liststealthaddresses",
        "\nLists all stealth addresses in the wallet.\n",
        {},
        RPCResult{
            RPCResult::Type::ARR, "", "",
            {
                {RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::STR, "address", "The stealth address"},
                        {RPCResult::Type::STR, "label", "The label"},
                        {RPCResult::Type::NUM_TIME, "created", "Creation timestamp"},
                    }
                },
            }
        },
        RPCExamples{
            HelpExampleCli("liststealthaddresses", "")
            + HelpExampleRpc("liststealthaddresses", "")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            const std::shared_ptr<const CWallet> pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;

            LOCK(pwallet->cs_wallet);

            // Use the wallet's internal stealth address manager
            auto* stealthMgr = const_cast<CWallet*>(pwallet.get())->GetStealthAddressManager();
            if (!stealthMgr) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Stealth address manager not initialized");
            }

            UniValue result(UniValue::VARR);
            for (const auto& addr : stealthMgr->GetStealthAddresses()) {
                UniValue obj(UniValue::VOBJ);
                obj.pushKV("address", addr.address.ToString());
                obj.pushKV("label", addr.label);
                obj.pushKV("created", addr.nCreateTime);
                result.push_back(obj);
            }

            return result;
        },
    };
}

static RPCHelpMan getprivacybalance()
{
    return RPCHelpMan{"getprivacybalance",
        "\nReturns the wallet's privacy balance.\n",
        {},
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_AMOUNT, "balance", "Total privacy balance"},
                {RPCResult::Type::STR_AMOUNT, "spendable", "Spendable privacy balance"},
                {RPCResult::Type::STR_AMOUNT, "stealth_balance", "Stealth address balance"},
                {RPCResult::Type::NUM, "stealth_outputs", "Number of stealth outputs"},
            }
        },
        RPCExamples{
            HelpExampleCli("getprivacybalance", "")
            + HelpExampleRpc("getprivacybalance", "")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            const std::shared_ptr<const CWallet> pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;

            LOCK(pwallet->cs_wallet);

            // Get managers
            static std::map<std::string, std::unique_ptr<CStealthAddressManager>> s_stealthManagers;
            static std::map<std::string, std::unique_ptr<CPrivacyWalletManager>> s_privacyManagers;

            const std::string walletName = pwallet->GetName();
            if (s_stealthManagers.find(walletName) == s_stealthManagers.end()) {
                s_stealthManagers[walletName] = std::make_unique<CStealthAddressManager>(
                    const_cast<CWallet*>(pwallet.get()));
            }
            if (s_privacyManagers.find(walletName) == s_privacyManagers.end()) {
                s_privacyManagers[walletName] = std::make_unique<CPrivacyWalletManager>(
                    const_cast<CWallet*>(pwallet.get()));
            }

            CAmount stealthBalance = s_stealthManagers[walletName]->GetStealthBalance();
            CAmount privacyBalance = s_privacyManagers[walletName]->GetPrivacyBalance();
            CAmount spendable = s_privacyManagers[walletName]->GetSpendablePrivacyBalance();
            size_t outputs = s_stealthManagers[walletName]->GetUnspentStealthOutputs().size();

            UniValue result(UniValue::VOBJ);
            result.pushKV("balance", ValueFromAmount(privacyBalance));
            result.pushKV("spendable", ValueFromAmount(spendable));
            result.pushKV("stealth_balance", ValueFromAmount(stealthBalance));
            result.pushKV("stealth_outputs", static_cast<uint64_t>(outputs));

            return result;
        },
    };
}

static RPCHelpMan decodestealthaddress()
{
    return RPCHelpMan{"decodestealthaddress",
        "\nDecodes a stealth address to show its components.\n",
        {
            {"address", RPCArg::Type::STR, RPCArg::Optional::NO, "The stealth address to decode."},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::BOOL, "valid", "Whether the address is valid"},
                {RPCResult::Type::STR, "scan_pubkey", /*optional=*/true, "The scan public key (hex)"},
                {RPCResult::Type::STR, "spend_pubkey", /*optional=*/true, "The spend public key (hex)"},
                {RPCResult::Type::STR, "label", /*optional=*/true, "The label for the stealth address"},
                {RPCResult::Type::STR, "error", /*optional=*/true, "Error message if address is invalid"},
            }
        },
        RPCExamples{
            HelpExampleCli("decodestealthaddress", "\"sx1...\"")
            + HelpExampleRpc("decodestealthaddress", "\"sx1...\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            std::string addrStr = request.params[0].get_str();

            auto addr = privacy::CStealthAddress::FromString(addrStr);

            UniValue result(UniValue::VOBJ);
            if (addr) {
                result.pushKV("valid", true);
                result.pushKV("scan_pubkey", HexStr(addr->scanPubKey));
                result.pushKV("spend_pubkey", HexStr(addr->spendPubKey));
                result.pushKV("label", addr->label);
            } else {
                result.pushKV("valid", false);
                result.pushKV("error", "Invalid stealth address format");
            }

            return result;
        },
    };
}

static RPCHelpMan getprivacyinfo()
{
    return RPCHelpMan{"getprivacyinfo",
        "\nReturns information about privacy features.\n",
        {},
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::BOOL, "enabled", "Whether privacy features are enabled"},
                {RPCResult::Type::NUM, "min_ring_size", "Minimum ring size"},
                {RPCResult::Type::NUM, "default_ring_size", "Default ring size"},
                {RPCResult::Type::NUM, "decoy_outputs", "Total indexed decoy outputs"},
                {RPCResult::Type::NUM, "index_height", "Decoy index height"},
            }
        },
        RPCExamples{
            HelpExampleCli("getprivacyinfo", "")
            + HelpExampleRpc("getprivacyinfo", "")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            UniValue result(UniValue::VOBJ);

            // Check if privacy provider is available
            auto provider = privacy::GetDecoyProvider();
            bool enabled = provider != nullptr;

            result.pushKV("enabled", enabled);
            result.pushKV("min_ring_size", static_cast<uint64_t>(privacy::GetMinRingSize(0)));
            result.pushKV("default_ring_size", static_cast<uint64_t>(privacy::GetDefaultRingSize(0)));

            if (provider) {
                result.pushKV("decoy_outputs", provider->GetOutputCount());
                result.pushKV("index_height", provider->GetHeight());
            } else {
                result.pushKV("decoy_outputs", 0);
                result.pushKV("index_height", 0);
            }

            return result;
        },
    };
}

// ============================================================================
// FCMP (Full-Chain Membership Proofs) RPC Commands
// ============================================================================

static RPCHelpMan getfcmpbalance()
{
    return RPCHelpMan{"getfcmpbalance",
        "\nReturns the wallet's FCMP (Full-Chain Membership Proofs) balance.\n"
        "FCMP provides full anonymity by proving membership in the entire output set.\n",
        {
            {"minconf", RPCArg::Type::NUM, RPCArg::Default{10}, "Minimum confirmations for spendable balance."},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_AMOUNT, "total", "Total FCMP balance"},
                {RPCResult::Type::STR_AMOUNT, "spendable", "Spendable FCMP balance (confirmed)"},
                {RPCResult::Type::STR_AMOUNT, "pending", "Pending FCMP balance (unconfirmed)"},
                {RPCResult::Type::NUM, "outputs", "Number of unspent FCMP outputs"},
            }
        },
        RPCExamples{
            HelpExampleCli("getfcmpbalance", "")
            + HelpExampleCli("getfcmpbalance", "6")
            + HelpExampleRpc("getfcmpbalance", "10")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            const std::shared_ptr<const CWallet> pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;

            int minConf = 10;
            if (!request.params[0].isNull()) {
                minConf = request.params[0].getInt<int>();
            }

            LOCK(pwallet->cs_wallet);

            auto* fcmpManager = GetFcmpManager(pwallet);

            CAmount total = fcmpManager->GetFcmpBalance();
            CAmount spendable = fcmpManager->GetSpendableFcmpBalance(minConf);
            CAmount pending = fcmpManager->GetPendingFcmpBalance();
            auto outputs = fcmpManager->GetFcmpOutputs(false);

            UniValue result(UniValue::VOBJ);
            result.pushKV("total", ValueFromAmount(total));
            result.pushKV("spendable", ValueFromAmount(spendable));
            result.pushKV("pending", ValueFromAmount(pending));
            result.pushKV("outputs", static_cast<uint64_t>(outputs.size()));

            return result;
        },
    };
}

static RPCHelpMan listfcmpoutputs()
{
    return RPCHelpMan{"listfcmpoutputs",
        "\nLists all FCMP outputs owned by the wallet.\n",
        {
            {"include_spent", RPCArg::Type::BOOL, RPCArg::Default{false}, "Include spent outputs."},
            {"minconf", RPCArg::Type::NUM, RPCArg::Default{0}, "Minimum confirmations."},
        },
        RPCResult{
            RPCResult::Type::ARR, "", "",
            {
                {RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::STR_HEX, "txid", "Transaction ID"},
                        {RPCResult::Type::NUM, "vout", "Output index"},
                        {RPCResult::Type::STR_AMOUNT, "amount", "Output amount"},
                        {RPCResult::Type::NUM, "confirmations", "Number of confirmations"},
                        {RPCResult::Type::NUM, "leaf_index", "Position in curve tree"},
                        {RPCResult::Type::BOOL, "spendable", "Whether this output is spendable"},
                        {RPCResult::Type::BOOL, "spent", "Whether this output has been spent"},
                    }
                },
            }
        },
        RPCExamples{
            HelpExampleCli("listfcmpoutputs", "")
            + HelpExampleCli("listfcmpoutputs", "true")
            + HelpExampleRpc("listfcmpoutputs", "false, 10")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            const std::shared_ptr<const CWallet> pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;

            bool includeSpent = false;
            int minConf = 0;

            if (!request.params[0].isNull()) {
                includeSpent = request.params[0].get_bool();
            }
            if (!request.params[1].isNull()) {
                minConf = request.params[1].getInt<int>();
            }

            LOCK(pwallet->cs_wallet);

            auto* fcmpManager = GetFcmpManager(pwallet);
            int currentHeight = fcmpManager->GetCurrentHeight();

            auto outputs = fcmpManager->GetFcmpOutputs(includeSpent);

            UniValue result(UniValue::VARR);
            for (const auto& output : outputs) {
                int confirmations = output.blockHeight >= 0 ?
                    currentHeight - output.blockHeight + 1 : 0;

                if (confirmations < minConf) continue;

                UniValue obj(UniValue::VOBJ);
                obj.pushKV("txid", output.outpoint.hash.GetHex());
                obj.pushKV("vout", static_cast<uint64_t>(output.outpoint.n));
                obj.pushKV("amount", ValueFromAmount(output.amount));
                obj.pushKV("confirmations", confirmations);
                obj.pushKV("leaf_index", output.treeLeafIndex);
                obj.pushKV("spendable", output.IsSpendable(currentHeight, 10));
                obj.pushKV("spent", output.spent);

                result.push_back(obj);
            }

            return result;
        },
    };
}

static RPCHelpMan sendfcmp()
{
    return RPCHelpMan{"sendfcmp",
        "\nSend an FCMP (Full-Chain Membership Proofs) private transaction.\n"
        "FCMP provides maximum privacy by proving output membership in the entire chain.\n",
        {
            {"address", RPCArg::Type::STR, RPCArg::Optional::NO, "The stealth address to send to."},
            {"amount", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "The amount to send."},
            {"minconf", RPCArg::Type::NUM, RPCArg::Default{10}, "Minimum confirmations for inputs."},
            {"subtractfeefromamount", RPCArg::Type::BOOL, RPCArg::Default{false}, "Subtract fee from amount."},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "txid", "The transaction ID"},
                {RPCResult::Type::STR_AMOUNT, "fee", "The fee paid"},
                {RPCResult::Type::NUM, "inputs", "Number of inputs used"},
                {RPCResult::Type::NUM, "outputs", "Number of outputs created"},
            }
        },
        RPCExamples{
            HelpExampleCli("sendfcmp", "\"sx1...\" 1.0")
            + HelpExampleCli("sendfcmp", "\"sx1...\" 1.0 10 true")
            + HelpExampleRpc("sendfcmp", "\"sx1...\", 1.0")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            const std::shared_ptr<const CWallet> pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;

            // Parse stealth address
            std::string addrStr = request.params[0].get_str();
            auto stealthAddr = privacy::CStealthAddress::FromString(addrStr);
            if (!stealthAddr) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid stealth address");
            }

            // Parse amount
            CAmount amount = AmountFromValue(request.params[1]);
            if (amount <= 0) {
                throw JSONRPCError(RPC_TYPE_ERROR, "Invalid amount");
            }

            // Parse optional params
            int minConf = 10;
            bool subtractFee = false;

            if (!request.params[2].isNull()) {
                minConf = request.params[2].getInt<int>();
            }
            if (!request.params[3].isNull()) {
                subtractFee = request.params[3].get_bool();
            }

            LOCK(pwallet->cs_wallet);

            auto* fcmpManager = GetFcmpManager(pwallet);

            // Check balance
            CAmount spendable = fcmpManager->GetSpendableFcmpBalance(minConf);
            if (spendable < amount) {
                throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS,
                    strprintf("Insufficient FCMP funds. Available: %s, Requested: %s",
                              FormatMoney(spendable), FormatMoney(amount)));
            }

            // Build recipient
            CFcmpRecipient recipient;
            recipient.stealthAddress = *stealthAddr;
            recipient.amount = amount;

            // Build params
            CFcmpTransactionParams params;
            params.minConfirmations = minConf;
            params.subtractFeeFromAmount = subtractFee;

            // Create transaction
            auto result = fcmpManager->CreateFcmpTransaction({recipient}, params);

            if (!result.success) {
                throw JSONRPCError(RPC_WALLET_ERROR,
                    strprintf("Failed to create FCMP transaction: %s", result.error));
            }

            // Broadcast transaction
            mapValue_t mapValue;
            mapValue["comment"] = "FCMP private transaction";
            const_cast<CWallet*>(pwallet.get())->CommitTransaction(result.standardTx, std::move(mapValue), {});

            // Mark spent inputs by matching key images to our outputs
            uint256 spendingTxHash = result.standardTx->GetHash();
            auto allOutputs = fcmpManager->GetFcmpOutputs(false);
            for (const auto& ki : result.keyImages) {
                uint256 kiHash = ki.GetHash();
                for (const auto& out : allOutputs) {
                    if (out.keyImageHash == kiHash) {
                        fcmpManager->MarkFcmpOutputSpent(out.outpoint, spendingTxHash);
                        break;
                    }
                }
            }

            // Register change output in wallet for balance tracking
            if (result.changeOutputInfo) {
                auto changeInfo = *result.changeOutputInfo;
                changeInfo.outpoint = COutPoint(Txid::FromUint256(spendingTxHash), result.privacyTx.privacyOutputs.size() - 1);
                fcmpManager->AddFcmpOutput(changeInfo);
            }

            UniValue ret(UniValue::VOBJ);
            ret.pushKV("txid", result.standardTx->GetHash().GetHex());
            ret.pushKV("fee", ValueFromAmount(result.fee));
            ret.pushKV("inputs", static_cast<uint64_t>(result.privacyTx.fcmpInputs.size()));
            ret.pushKV("outputs", static_cast<uint64_t>(result.privacyTx.privacyOutputs.size()));

            return ret;
        },
    };
}

static RPCHelpMan getfcmpinfo()
{
    return RPCHelpMan{"getfcmpinfo",
        "\nReturns information about FCMP (Full-Chain Membership Proofs) status.\n",
        {},
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::BOOL, "enabled", "Whether FCMP is enabled"},
                {RPCResult::Type::NUM, "tree_size", "Number of outputs in the curve tree"},
                {RPCResult::Type::NUM, "tree_height", "Current tree height"},
                {RPCResult::Type::STR_HEX, "tree_root", "Current tree root hash"},
                {RPCResult::Type::NUM, "proof_size_estimate", "Estimated proof size (bytes)"},
            }
        },
        RPCExamples{
            HelpExampleCli("getfcmpinfo", "")
            + HelpExampleRpc("getfcmpinfo", "")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            const std::shared_ptr<const CWallet> pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;

            LOCK(pwallet->cs_wallet);

            auto* fcmpManager = GetFcmpManager(pwallet);
            auto curveTree = fcmpManager->GetCurveTree();

            UniValue result(UniValue::VOBJ);

            bool enabled = curveTree != nullptr;
            result.pushKV("enabled", enabled);

            if (enabled) {
                result.pushKV("tree_size", curveTree->GetOutputCount());
                result.pushKV("tree_height", static_cast<uint64_t>(curveTree->GetDepth()));

                auto root = curveTree->GetRoot();
                result.pushKV("tree_root", HexStr(root.data));

                // Estimate proof size for typical transaction
                size_t proofSize = 1024 + curveTree->GetDepth() * 64;
                result.pushKV("proof_size_estimate", static_cast<uint64_t>(proofSize));
            } else {
                result.pushKV("tree_size", 0);
                result.pushKV("tree_height", 0);
                result.pushKV("tree_root", "");
                result.pushKV("proof_size_estimate", 0);
            }

            return result;
        },
    };
}

static RPCHelpMan shieldfcmp()
{
    return RPCHelpMan{"shieldfcmp",
        "\nShield transparent coins to FCMP (Full-Chain Membership Proofs) outputs.\n"
        "Converts regular WATTx to private FCMP outputs that can be spent anonymously.\n",
        {
            {"amount", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "The amount to shield."},
            {"address", RPCArg::Type::STR, RPCArg::Default{""}, "Optional stealth address (generates new if empty)."},
            {"minconf", RPCArg::Type::NUM, RPCArg::Default{1}, "Minimum confirmations for inputs."},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "txid", "The transaction ID"},
                {RPCResult::Type::STR_AMOUNT, "amount", "Amount shielded"},
                {RPCResult::Type::STR_AMOUNT, "fee", "Fee paid"},
                {RPCResult::Type::STR, "stealth_address", "The receiving stealth address"},
                {RPCResult::Type::NUM, "leaf_index", "Curve tree leaf index for the new output"},
            }
        },
        RPCExamples{
            HelpExampleCli("shieldfcmp", "10.0")
            + HelpExampleCli("shieldfcmp", "10.0 \"sx1...\"")
            + HelpExampleRpc("shieldfcmp", "10.0")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            const std::shared_ptr<const CWallet> pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;

            // Parse amount
            CAmount amount = AmountFromValue(request.params[0]);
            if (amount <= 0) {
                throw JSONRPCError(RPC_TYPE_ERROR, "Invalid amount");
            }

            // Parse optional stealth address
            std::optional<privacy::CStealthAddress> stealthAddr;
            if (!request.params[1].isNull() && !request.params[1].get_str().empty()) {
                stealthAddr = privacy::CStealthAddress::FromString(request.params[1].get_str());
                if (!stealthAddr) {
                    throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid stealth address");
                }
            }

            int minConf = 1;
            if (!request.params[2].isNull()) {
                minConf = request.params[2].getInt<int>();
            }

            LOCK(pwallet->cs_wallet);

            // Check transparent balance
            const auto bal = GetBalance(*pwallet);
            CAmount available = bal.m_mine_trusted;
            if (available < amount) {
                throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS,
                    strprintf("Insufficient transparent funds. Available: %s, Requested: %s",
                              FormatMoney(available), FormatMoney(amount)));
            }

            auto* fcmpManager = GetFcmpManager(pwallet);

            // Generate new stealth address if not provided
            std::string stealthAddrStr;
            if (!stealthAddr) {
                // Use the wallet's own stealth address manager
                auto* stealthMgr = const_cast<CWallet*>(pwallet.get())->GetStealthAddressManager();
                if (!stealthMgr) {
                    throw JSONRPCError(RPC_WALLET_ERROR, "Stealth address manager not available");
                }

                CStealthAddressData addressData;
                if (!stealthMgr->GenerateStealthAddress("fcmp_shield", addressData)) {
                    throw JSONRPCError(RPC_WALLET_ERROR, "Failed to generate stealth address");
                }
                stealthAddr = addressData.address;
                stealthAddrStr = addressData.address.ToString();
            } else {
                stealthAddrStr = request.params[1].get_str();
            }

            // Create the shielding transaction
            // This creates a tx that:
            // 1. Spends transparent inputs
            // 2. Creates an OP_RETURN output with FCMP output data (O, I, C)
            // 3. The FCMP output gets added to curve tree on block confirmation

            auto shieldResult = fcmpManager->CreateShieldTransaction(*stealthAddr, amount, minConf);

            if (!shieldResult.success) {
                throw JSONRPCError(RPC_WALLET_ERROR,
                    strprintf("Failed to create shield transaction: %s", shieldResult.error));
            }

            // Get the OP_RETURN script from the template transaction
            CScript opReturnScript;
            for (const auto& txout : shieldResult.standardTx->vout) {
                if (txout.scriptPubKey.size() > 0 && txout.scriptPubKey[0] == OP_RETURN) {
                    opReturnScript = txout.scriptPubKey;
                    break;
                }
            }

            if (opReturnScript.empty()) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Failed to create FCMP OP_RETURN script");
            }

            // Create recipient for the OP_RETURN output (0 value)
            CRecipient opReturnRecipient{CNoDestination{opReturnScript}, 0, false};

            // Create recipient for the shielded value
            // The shielded amount is sent to a one-time address derived from the stealth address
            // In FCMP, this creates a UTXO that can only be spent with a valid membership proof
            auto destResult = const_cast<CWallet*>(pwallet.get())->GetNewDestination(OutputType::BECH32, "fcmp_shield");
            if (!destResult) {
                throw JSONRPCError(RPC_WALLET_ERROR,
                    strprintf("Failed to generate shield destination: %s", util::ErrorString(destResult).original));
            }
            CTxDestination shieldDest = *destResult;

            // The shielded amount goes to a wallet-controlled address
            // The OP_RETURN commitment proves ownership of the shielded value
            // When spending, the FCMP proof demonstrates membership without revealing which output
            CRecipient shieldRecipient{shieldDest, amount, false};

            // Build recipients list
            std::vector<CRecipient> recipients;
            recipients.push_back(shieldRecipient);  // Shielded value output first
            recipients.push_back(opReturnRecipient); // FCMP commitment output

            // Create the transaction
            CCoinControl coinControl;
            coinControl.m_min_depth = minConf;

            auto txResult = CreateTransaction(*const_cast<CWallet*>(pwallet.get()), recipients, std::nullopt, coinControl, true);

            if (!txResult) {
                throw JSONRPCError(RPC_WALLET_ERROR,
                    strprintf("Failed to create transaction: %s", util::ErrorString(txResult).original));
            }

            // Commit the transaction
            mapValue_t mapValue;
            mapValue["comment"] = "FCMP shield transaction";

            const_cast<CWallet*>(pwallet.get())->CommitTransaction(txResult->tx, std::move(mapValue), {});

            // Register the FCMP output in the wallet so balance tracking works
            if (shieldResult.hasPrivKey) {
                // Find the OP_RETURN output index in the committed TX
                int opReturnVout = -1;
                for (size_t vi = 0; vi < txResult->tx->vout.size(); vi++) {
                    if (txResult->tx->vout[vi].scriptPubKey.size() > 0 &&
                        txResult->tx->vout[vi].scriptPubKey[0] == OP_RETURN) {
                        opReturnVout = vi;
                        break;
                    }
                }

                CFcmpOutputInfo outputInfo;
                outputInfo.outpoint = COutPoint(txResult->tx->GetHash(), opReturnVout >= 0 ? opReturnVout : 0);
                outputInfo.amount = amount;
                outputInfo.privKey = shieldResult.privKey;
                outputInfo.blinding = shieldResult.blinding;
                outputInfo.outputTuple = shieldResult.outputTuple;
                outputInfo.treeLeafIndex = shieldResult.leafIndex;
                outputInfo.keyImageHash = shieldResult.keyImageHash;
                outputInfo.blockHeight = -1; // Will be updated when confirmed
                outputInfo.spent = false;
                outputInfo.nTime = GetTime();

                fcmpManager->AddFcmpOutput(outputInfo);
            }

            UniValue ret(UniValue::VOBJ);
            ret.pushKV("txid", txResult->tx->GetHash().GetHex());
            ret.pushKV("amount", ValueFromAmount(amount));
            ret.pushKV("fee", ValueFromAmount(txResult->fee));
            ret.pushKV("stealth_address", stealthAddrStr);
            ret.pushKV("leaf_index", static_cast<uint64_t>(shieldResult.leafIndex));

            return ret;
        },
    };
}

static RPCHelpMan importfcmpoutput()
{
    return RPCHelpMan{"importfcmpoutput",
        "\nImport an FCMP output for recovery or watch-only purposes.\n",
        {
            {"txid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The transaction ID."},
            {"vout", RPCArg::Type::NUM, RPCArg::Optional::NO, "The output index."},
            {"amount", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "The output amount."},
            {"privkey", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The Ed25519 private key (32 bytes hex)."},
            {"blinding", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The blinding factor (32 bytes hex)."},
            {"leaf_index", RPCArg::Type::NUM, RPCArg::Optional::NO, "The leaf index in the curve tree."},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::BOOL, "success", "Whether the import succeeded"},
                {RPCResult::Type::STR_HEX, "key_image", "The computed key image"},
            }
        },
        RPCExamples{
            HelpExampleCli("importfcmpoutput", "\"txid\" 0 1.0 \"privkey\" \"blinding\" 12345")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            const std::shared_ptr<const CWallet> pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;

            // Parse parameters
            Txid txid = Txid::FromUint256(ParseHashV(request.params[0], "txid"));
            uint32_t vout = request.params[1].getInt<uint32_t>();
            CAmount amount = AmountFromValue(request.params[2]);

            std::vector<uint8_t> privKeyBytes = ParseHex(request.params[3].get_str());
            std::vector<uint8_t> blindingBytes = ParseHex(request.params[4].get_str());
            uint64_t leafIndex = request.params[5].getInt<uint64_t>();

            if (privKeyBytes.size() != 32) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Private key must be 32 bytes");
            }
            if (blindingBytes.size() != 32) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Blinding factor must be 32 bytes");
            }

            LOCK(pwallet->cs_wallet);

            auto* fcmpManager = GetFcmpManager(pwallet);

            // Build output info
            CFcmpOutputInfo output;
            output.outpoint = COutPoint(txid, vout);
            output.amount = amount;
            std::memcpy(output.privKey.data.data(), privKeyBytes.data(), 32);
            std::memcpy(output.blinding.data.data(), blindingBytes.data(), 32);
            output.treeLeafIndex = leafIndex;
            output.blockHeight = -1; // Unknown
            output.spent = false;
            output.nTime = GetTime();

            // Compute output tuple from private key
            auto G = ed25519::Point::BasePoint();
            output.outputTuple.O = output.privKey * G;

            // Compute key image base
            std::vector<uint8_t> toHash(output.outputTuple.O.data.begin(),
                                        output.outputTuple.O.data.end());
            output.outputTuple.I = ed25519::Point::HashToPoint(toHash);

            // Compute commitment
            auto commitment = ed25519::PedersenCommitment::CommitAmount(
                static_cast<uint64_t>(amount),
                output.blinding
            );
            output.outputTuple.C = commitment.GetPoint();

            // Generate key image hash
            auto keyImage = fcmpManager->GenerateKeyImage(output.privKey, output.outputTuple.O);
            output.keyImageHash = keyImage.GetHash();

            // Add to wallet
            bool success = fcmpManager->AddFcmpOutput(output);

            UniValue result(UniValue::VOBJ);
            result.pushKV("success", success);
            result.pushKV("key_image", HexStr(keyImage.data));

            return result;
        },
    };
}

Span<const CRPCCommand> GetPrivacyRPCCommands()
{
    static const CRPCCommand commands[]{
        // Stealth address commands
        {"privacy", &getnewstealthaddress},
        {"privacy", &liststealthaddresses},
        {"privacy", &getprivacybalance},
        {"privacy", &decodestealthaddress},
        {"privacy", &getprivacyinfo},
        // FCMP commands
        {"privacy", &getfcmpbalance},
        {"privacy", &listfcmpoutputs},
        {"privacy", &shieldfcmp},
        {"privacy", &sendfcmp},
        {"privacy", &getfcmpinfo},
        {"privacy", &importfcmpoutput},
    };
    return commands;
}

} // namespace wallet
