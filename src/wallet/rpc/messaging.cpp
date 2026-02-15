// Copyright (c) 2024-2026 The WATTx Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <addresstype.h>
#include <key_io.h>
#include <rpc/server.h>
#include <rpc/util.h>
#include <span.h>
#include <wallet/messaging.h>
#include <wallet/rpc/messaging.h>
#include <wallet/rpc/util.h>
#include <wallet/wallet.h>

#include <univalue.h>

// Windows winuser.h defines SendMessage as a macro
#ifdef SendMessage
#undef SendMessage
#endif

namespace wallet {

RPCHelpMan sendmessage()
{
    return RPCHelpMan{"sendmessage",
        "\nSend an encrypted message to another WATTx address on-chain.\n"
        "The message is encrypted using ECDH so only the recipient can read it.\n"
        "Requires the recipient to have previously sent you a transaction (so their public key is known).\n",
        {
            {"address", RPCArg::Type::STR, RPCArg::Optional::NO, "The recipient's WATTx address"},
            {"message", RPCArg::Type::STR, RPCArg::Optional::NO, "The message to send"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "txid", "The transaction ID containing the message"},
            }
        },
        RPCExamples{
            HelpExampleCli("sendmessage", "\"WZzugKM8P9L3Ds2PjqoZUBVvESqtA5RCUr\" \"Hello, how are you?\"")
            + HelpExampleRpc("sendmessage", "\"WZzugKM8P9L3Ds2PjqoZUBVvESqtA5RCUr\", \"Hello, how are you?\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return UniValue::VNULL;

    // Make sure the wallet is unlocked
    EnsureWalletIsUnlocked(*pwallet);

    std::string address = request.params[0].get_str();
    std::string message = request.params[1].get_str();

    if (message.empty()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Message cannot be empty");
    }

    if (message.size() > 1000) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Message too long (max 1000 characters)");
    }

    uint256 txid;
    std::string error = SendMessage(*pwallet, address, message, txid);

    if (!error.empty()) {
        throw JSONRPCError(RPC_WALLET_ERROR, error);
    }

    UniValue result(UniValue::VOBJ);
    result.pushKV("txid", txid.GetHex());
    return result;
},
    };
}

RPCHelpMan listmessages()
{
    return RPCHelpMan{"listmessages",
        "\nList all encrypted messages in the wallet.\n",
        {
            {"count", RPCArg::Type::NUM, RPCArg::Default{100}, "Maximum number of messages to return"},
            {"skip", RPCArg::Type::NUM, RPCArg::Default{0}, "Number of messages to skip"},
        },
        RPCResult{
            RPCResult::Type::ARR, "", "",
            {
                {RPCResult::Type::OBJ, "", "",
                {
                    {RPCResult::Type::STR_HEX, "txid", "Transaction ID"},
                    {RPCResult::Type::NUM, "timestamp", "Unix timestamp"},
                    {RPCResult::Type::NUM, "blockheight", "Block height (-1 if unconfirmed)"},
                    {RPCResult::Type::STR, "from", "Sender address"},
                    {RPCResult::Type::STR, "to", "Recipient address"},
                    {RPCResult::Type::STR, "message", "Decrypted message (or '[Encrypted]' if cannot decrypt)"},
                    {RPCResult::Type::BOOL, "outgoing", "True if we sent this message"},
                    {RPCResult::Type::BOOL, "read", "True if message has been read"},
                }},
            }
        },
        RPCExamples{
            HelpExampleCli("listmessages", "")
            + HelpExampleCli("listmessages", "10 0")
            + HelpExampleRpc("listmessages", "10, 0")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const std::shared_ptr<const CWallet> pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return UniValue::VNULL;

    int count = 100;
    int skip = 0;

    if (!request.params[0].isNull()) {
        count = request.params[0].getInt<int>();
    }
    if (!request.params[1].isNull()) {
        skip = request.params[1].getInt<int>();
    }

    std::vector<OnChainMessage> messages;
    if (!GetMessages(*pwallet, messages, true)) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Failed to get messages");
    }

    UniValue result(UniValue::VARR);

    int skipped = 0;
    int added = 0;
    for (const auto& msg : messages) {
        if (skipped < skip) {
            skipped++;
            continue;
        }
        if (added >= count) {
            break;
        }

        UniValue msgObj(UniValue::VOBJ);
        msgObj.pushKV("txid", msg.txid.GetHex());
        msgObj.pushKV("timestamp", msg.timestamp);
        msgObj.pushKV("blockheight", msg.blockHeight);
        msgObj.pushKV("from", msg.senderAddress);
        msgObj.pushKV("to", msg.recipientAddress);
        msgObj.pushKV("message", msg.decryptedText.empty() ? "[Encrypted]" : msg.decryptedText);
        msgObj.pushKV("outgoing", msg.isOutgoing);
        msgObj.pushKV("read", msg.isRead);

        result.push_back(msgObj);
        added++;
    }

    return result;
},
    };
}

RPCHelpMan getconversation()
{
    return RPCHelpMan{"getconversation",
        "\nGet all messages in a conversation with a specific address.\n",
        {
            {"address", RPCArg::Type::STR, RPCArg::Optional::NO, "The peer's WATTx address"},
        },
        RPCResult{
            RPCResult::Type::ARR, "", "",
            {
                {RPCResult::Type::OBJ, "", "",
                {
                    {RPCResult::Type::STR_HEX, "txid", "Transaction ID"},
                    {RPCResult::Type::NUM, "timestamp", "Unix timestamp"},
                    {RPCResult::Type::STR, "message", "Decrypted message"},
                    {RPCResult::Type::BOOL, "outgoing", "True if we sent this message"},
                }},
            }
        },
        RPCExamples{
            HelpExampleCli("getconversation", "\"WZzugKM8P9L3Ds2PjqoZUBVvESqtA5RCUr\"")
            + HelpExampleRpc("getconversation", "\"WZzugKM8P9L3Ds2PjqoZUBVvESqtA5RCUr\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const std::shared_ptr<const CWallet> pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return UniValue::VNULL;

    std::string peerAddress = request.params[0].get_str();

    std::vector<OnChainMessage> messages;
    if (!GetConversation(*pwallet, peerAddress, messages)) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Failed to get conversation");
    }

    UniValue result(UniValue::VARR);
    for (const auto& msg : messages) {
        UniValue msgObj(UniValue::VOBJ);
        msgObj.pushKV("txid", msg.txid.GetHex());
        msgObj.pushKV("timestamp", msg.timestamp);
        msgObj.pushKV("message", msg.decryptedText.empty() ? "[Encrypted]" : msg.decryptedText);
        msgObj.pushKV("outgoing", msg.isOutgoing);
        result.push_back(msgObj);
    }

    return result;
},
    };
}

RPCHelpMan listconversations()
{
    return RPCHelpMan{"listconversations",
        "\nList all message conversations.\n",
        {},
        RPCResult{
            RPCResult::Type::ARR, "", "",
            {
                {RPCResult::Type::OBJ, "", "",
                {
                    {RPCResult::Type::STR, "address", "Peer's address"},
                    {RPCResult::Type::STR, "label", "Address label (if in address book)"},
                    {RPCResult::Type::NUM, "lastmessage", "Timestamp of last message"},
                    {RPCResult::Type::NUM, "unread", "Number of unread messages"},
                    {RPCResult::Type::STR, "preview", "Preview of last message"},
                }},
            }
        },
        RPCExamples{
            HelpExampleCli("listconversations", "")
            + HelpExampleRpc("listconversations", "")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const std::shared_ptr<const CWallet> pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return UniValue::VNULL;

    std::vector<Conversation> conversations;
    if (!GetConversations(*pwallet, conversations)) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Failed to get conversations");
    }

    UniValue result(UniValue::VARR);
    for (const auto& conv : conversations) {
        UniValue convObj(UniValue::VOBJ);
        convObj.pushKV("address", conv.peerAddress);
        convObj.pushKV("label", conv.peerLabel);
        convObj.pushKV("lastmessage", conv.lastMessageTime);
        convObj.pushKV("unread", conv.unreadCount);
        convObj.pushKV("preview", conv.lastMessagePreview);
        result.push_back(convObj);
    }

    return result;
},
    };
}

RPCHelpMan getmessagingpubkey()
{
    return RPCHelpMan{"getmessagingpubkey",
        "\nGet your public key for receiving encrypted messages.\n"
        "Share this with people who want to send you messages.\n",
        {
            {"address", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Specific address to get pubkey for (default: first available)"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR, "address", "Your WATTx address"},
                {RPCResult::Type::STR_HEX, "pubkey", "Your public key (hex)"},
            }
        },
        RPCExamples{
            HelpExampleCli("getmessagingpubkey", "")
            + HelpExampleRpc("getmessagingpubkey", "")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const std::shared_ptr<const CWallet> pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return UniValue::VNULL;

    LOCK(pwallet->cs_wallet);

    CTxDestination dest;
    CPubKey pubKey;

    if (!request.params[0].isNull()) {
        // Get specific address
        dest = DecodeDestination(request.params[0].get_str());
        if (!IsValidDestination(dest)) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid address");
        }
    } else {
        // Get first address from address book
        bool found = false;
        for (const auto& [addr, data] : pwallet->m_address_book) {
            if (pwallet->IsMine(addr)) {
                dest = addr;
                found = true;
                break;
            }
        }
        if (!found) {
            throw JSONRPCError(RPC_WALLET_ERROR, "No addresses available in wallet");
        }
    }

    // Get the public key for this destination
    // Try to find the key through the scriptPubKeyManagers
    CScript script = GetScriptForDestination(dest);
    std::unique_ptr<SigningProvider> provider = pwallet->GetSolvingProvider(script);
    if (!provider) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Could not get signing provider for address");
    }

    // Extract KeyID from destination
    CKeyID keyId;
    if (std::holds_alternative<PKHash>(dest)) {
        keyId = CKeyID(uint160(std::get<PKHash>(dest)));
    } else if (std::holds_alternative<WitnessV0KeyHash>(dest)) {
        keyId = CKeyID(uint160(std::get<WitnessV0KeyHash>(dest)));
    } else {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Address type not supported for messaging");
    }

    if (!provider->GetPubKey(keyId, pubKey)) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Could not get public key for address");
    }

    UniValue result(UniValue::VOBJ);
    result.pushKV("address", EncodeDestination(dest));
    result.pushKV("pubkey", HexStr(pubKey));

    return result;
},
    };
}

RPCHelpMan importmessagingpubkey()
{
    return RPCHelpMan{"importmessagingpubkey",
        "\nImport a contact's public key for sending them encrypted messages.\n",
        {
            {"address", RPCArg::Type::STR, RPCArg::Optional::NO, "The contact's WATTx address"},
            {"pubkey", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The contact's public key (hex)"},
            {"label", RPCArg::Type::STR, RPCArg::Default{""}, "Label for this contact"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::BOOL, "success", "True if import successful"},
            }
        },
        RPCExamples{
            HelpExampleCli("importmessagingpubkey", "\"WZzug...\" \"03abc...\" \"Alice\"")
            + HelpExampleRpc("importmessagingpubkey", "\"WZzug...\", \"03abc...\", \"Alice\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return UniValue::VNULL;

    LOCK(pwallet->cs_wallet);

    std::string address = request.params[0].get_str();
    std::string pubkeyHex = request.params[1].get_str();
    std::string label = request.params[2].isNull() ? "" : request.params[2].get_str();

    // Validate address
    CTxDestination dest = DecodeDestination(address);
    if (!IsValidDestination(dest)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid address");
    }

    // Validate and parse public key
    std::vector<unsigned char> pubkeyData = ParseHex(pubkeyHex);
    CPubKey pubkey(pubkeyData);
    if (!pubkey.IsValid()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid public key");
    }

    // Verify pubkey matches address
    if (std::holds_alternative<PKHash>(dest)) {
        PKHash expectedHash = std::get<PKHash>(dest);
        if (PKHash(pubkey) != expectedHash) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Public key does not match address");
        }
    }

    // Add to address book with label
    pwallet->SetAddressBook(dest, label, AddressPurpose::SEND);

    // TODO: Store pubkey in a messaging contacts table for future use

    UniValue result(UniValue::VOBJ);
    result.pushKV("success", true);
    return result;
},
    };
}

Span<const CRPCCommand> GetMessagingRPCCommands()
{
    static const CRPCCommand commands[]{
        {"messaging", &sendmessage},
        {"messaging", &listmessages},
        {"messaging", &getconversation},
        {"messaging", &listconversations},
        {"messaging", &getmessagingpubkey},
        {"messaging", &importmessagingpubkey},
    };
    return commands;
}

} // namespace wallet
