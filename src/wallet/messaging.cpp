// Copyright (c) 2024-2026 The WATTx Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/messaging.h>

// Windows winuser.h defines SendMessage as a macro
#ifdef SendMessage
#undef SendMessage
#endif

#include <crypto/sha256.h>
#include <hash.h>
#include <key_io.h>
#include <primitives/transaction.h>
#include <random.h>
#include <script/script.h>
#include <script/signingprovider.h>
#include <script/solver.h>
#include <secp256k1.h>
#include <secp256k1_ecdh.h>
#include <util/strencodings.h>
#include <util/string.h>
#include <wallet/coincontrol.h>
#include <wallet/scriptpubkeyman.h>
#include <wallet/spend.h>
#include <wallet/wallet.h>

#include <openssl/evp.h>

// Windows winuser.h defines SendMessage as a macro - must undef AFTER all includes
#ifdef SendMessage
#undef SendMessage
#endif

namespace wallet {

// ============================================================================
// Helper Functions for Descriptor Wallet Key Access
// ============================================================================

// Helper to get private key from wallet (works with both legacy and descriptor wallets)
static bool GetKeyFromWallet(const CWallet& wallet, const CKeyID& keyId, CKey& key) {
    // First try the wallet's GetKey method (works for some wallet types)
    std::optional<CKey> optKey = wallet.GetKey(keyId);
    if (optKey) {
        key = *optKey;
        return true;
    }

    // For descriptor wallets, try getting the key via signing provider
    // First need to get the pubkey
    CPubKey pubkey;
    PKHash pkhash(keyId);
    if (!wallet.GetPubKey(pkhash, pubkey)) {
        // Try without converting through PKHash
        WitnessV0KeyHash wpkh(keyId);
        CScript witnessScript = GetScriptForDestination(wpkh);
        std::unique_ptr<SigningProvider> provider = wallet.GetSolvingProvider(witnessScript);
        if (provider && provider->GetPubKey(keyId, pubkey)) {
            // Got it via witness
        } else {
            return false;
        }
    }

    // Iterate through script pub key managers and try to get private key
    CScript script = GetScriptForDestination(PKHash(keyId));
    std::set<ScriptPubKeyMan*> spk_mans = wallet.GetScriptPubKeyMans(script);
    for (auto* spk_man : spk_mans) {
        DescriptorScriptPubKeyMan* desc_spk = dynamic_cast<DescriptorScriptPubKeyMan*>(spk_man);
        if (desc_spk) {
            // Use the public GetSigningProvider(pubkey) which includes private keys
            std::unique_ptr<FlatSigningProvider> keys = desc_spk->GetSigningProvider(pubkey);
            if (keys && keys->GetKey(keyId, key)) {
                return true;
            }
        }
    }

    // Also try legacy wallet
    LegacyScriptPubKeyMan* legacy_spk = wallet.GetLegacyScriptPubKeyMan();
    if (legacy_spk && legacy_spk->GetKey(keyId, key)) {
        return true;
    }

    return false;
}

// ============================================================================
// Helper to extract sender's public key from transaction inputs
// ============================================================================

// Extract public key from a scriptSig or witness (used to find sender's pubkey for decryption)
static bool ExtractPubKeyFromInput(const CTxIn& txin, CPubKey& pubkey) {
    // Try scriptSig first (P2PKH)
    if (!txin.scriptSig.empty()) {
        // P2PKH scriptSig format: <sig> <pubkey>
        // The pubkey is typically the last push in the scriptSig
        std::vector<std::vector<unsigned char>> stack;
        if (EvalScript(stack, txin.scriptSig, SCRIPT_VERIFY_NONE, BaseSignatureChecker(), SigVersion::BASE)) {
            // Look for a valid pubkey in the stack (33 or 65 bytes)
            for (auto it = stack.rbegin(); it != stack.rend(); ++it) {
                if (it->size() == 33 || it->size() == 65) {
                    CPubKey testPubKey(*it);
                    if (testPubKey.IsValid()) {
                        pubkey = testPubKey;
                        return true;
                    }
                }
            }
        }
    }

    // Try witness (P2WPKH)
    if (!txin.scriptWitness.IsNull() && txin.scriptWitness.stack.size() >= 2) {
        // P2WPKH witness format: <sig> <pubkey>
        const auto& witnessStack = txin.scriptWitness.stack;
        for (auto it = witnessStack.rbegin(); it != witnessStack.rend(); ++it) {
            if (it->size() == 33 || it->size() == 65) {
                CPubKey testPubKey(*it);
                if (testPubKey.IsValid()) {
                    pubkey = testPubKey;
                    return true;
                }
            }
        }
    }

    return false;
}

// Try to decrypt a message using wallet keys
static bool TryDecryptMessage(const CWallet& wallet,
                               const std::vector<unsigned char>& encryptedData,
                               const CPubKey& otherPartyPubKey,
                               const uint160& ourAddressHash,
                               std::string& decryptedText) {
    // Get our private key for this address
    CKeyID ourKeyId(ourAddressHash);
    CKey ourKey;

    if (!GetKeyFromWallet(wallet, ourKeyId, ourKey)) {
        return false;
    }

    // Derive shared secret using ECDH
    std::vector<unsigned char> sharedSecret;
    if (!DeriveSharedSecret(ourKey, otherPartyPubKey, sharedSecret)) {
        return false;
    }

    // Decrypt the message
    if (!DecryptMessage(encryptedData, sharedSecret, decryptedText)) {
        return false;
    }

    return true;
}

// ============================================================================
// Encryption Implementation
// ============================================================================

bool DeriveSharedSecret(const CKey& myPrivKey, const CPubKey& theirPubKey,
                        std::vector<unsigned char>& sharedSecret)
{
    if (!myPrivKey.IsValid() || !theirPubKey.IsValid()) {
        return false;
    }

    sharedSecret.resize(32);

    // Create a secp256k1 context for ECDH
    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    if (!ctx) {
        return false;
    }

    // Parse their public key
    secp256k1_pubkey pubkey;
    if (!secp256k1_ec_pubkey_parse(ctx, &pubkey, theirPubKey.data(), theirPubKey.size())) {
        secp256k1_context_destroy(ctx);
        return false;
    }

    // Perform ECDH
    unsigned char rawSecret[32];
    if (!secp256k1_ecdh(ctx, rawSecret, &pubkey,
                        reinterpret_cast<const unsigned char*>(myPrivKey.data()),
                        nullptr, nullptr)) {
        secp256k1_context_destroy(ctx);
        return false;
    }

    secp256k1_context_destroy(ctx);

    // Hash the raw ECDH output to get final shared secret
    CSHA256 hasher;
    hasher.Write(rawSecret, 32);
    hasher.Finalize(sharedSecret.data());

    // Clear sensitive data
    memory_cleanse(rawSecret, 32);

    return true;
}

bool EncryptMessage(const std::string& plaintext,
                    const std::vector<unsigned char>& sharedSecret,
                    std::vector<unsigned char>& ciphertext)
{
    if (sharedSecret.size() != 32 || plaintext.empty()) {
        return false;
    }

    // Generate random 12-byte nonce
    unsigned char nonce[12];
    GetStrongRandBytes(nonce);

    // Prepare output buffer: nonce(12) + ciphertext + tag(16)
    ciphertext.resize(12 + plaintext.size() + 16);

    // Copy nonce to output
    memcpy(ciphertext.data(), nonce, 12);

    // AES-256-GCM encryption using OpenSSL
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;

    int len;
    int ciphertextLen;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, sharedSecret.data(), nonce) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    if (EVP_EncryptUpdate(ctx, ciphertext.data() + 12, &len,
                          reinterpret_cast<const unsigned char*>(plaintext.data()),
                          plaintext.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    ciphertextLen = len;

    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + 12 + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    ciphertextLen += len;

    // Get the authentication tag
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, ciphertext.data() + 12 + ciphertextLen) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    EVP_CIPHER_CTX_free(ctx);

    // Resize to actual size
    ciphertext.resize(12 + ciphertextLen + 16);

    return true;
}

bool DecryptMessage(const std::vector<unsigned char>& ciphertext,
                    const std::vector<unsigned char>& sharedSecret,
                    std::string& plaintext)
{
    if (sharedSecret.size() != 32 || ciphertext.size() < ENCRYPTION_OVERHEAD) {
        return false;
    }

    // Extract nonce (first 12 bytes)
    const unsigned char* nonce = ciphertext.data();

    // Extract tag (last 16 bytes)
    const unsigned char* tag = ciphertext.data() + ciphertext.size() - 16;

    // Encrypted data is in the middle
    size_t encryptedLen = ciphertext.size() - 12 - 16;
    const unsigned char* encrypted = ciphertext.data() + 12;

    // Prepare output buffer
    std::vector<unsigned char> decrypted(encryptedLen);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;

    int len;
    int plaintextLen;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, sharedSecret.data(), nonce) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    if (EVP_DecryptUpdate(ctx, decrypted.data(), &len, encrypted, encryptedLen) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    plaintextLen = len;

    // Set expected tag
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, const_cast<unsigned char*>(tag)) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    // Verify tag and finalize
    if (EVP_DecryptFinal_ex(ctx, decrypted.data() + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;  // Authentication failed
    }
    plaintextLen += len;

    EVP_CIPHER_CTX_free(ctx);

    plaintext.assign(reinterpret_cast<char*>(decrypted.data()), plaintextLen);
    return true;
}

// ============================================================================
// Message Script Functions
// ============================================================================

bool CreateMessageScripts(const std::string& message,
                          const CKey& senderKey,
                          const CPubKey& recipientPubKey,
                          const uint160& recipientHash,
                          std::vector<CScript>& scripts)
{
    scripts.clear();

    // Derive shared secret
    std::vector<unsigned char> sharedSecret;
    if (!DeriveSharedSecret(senderKey, recipientPubKey, sharedSecret)) {
        return false;
    }

    // Encrypt the message
    std::vector<unsigned char> encrypted;
    if (!EncryptMessage(message, sharedSecret, encrypted)) {
        return false;
    }

    // Calculate how many OP_RETURNs we need
    // Header: version(1) + type(1) + recipient(20) + chunk_info(2) = 24 bytes
    // Leaving ~56 bytes per chunk for payload
    const size_t CHUNK_HEADER_SIZE = 24;
    const size_t MAX_CHUNK_PAYLOAD = MAX_OP_RETURN_SIZE - CHUNK_HEADER_SIZE;

    size_t totalChunks = (encrypted.size() + MAX_CHUNK_PAYLOAD - 1) / MAX_CHUNK_PAYLOAD;
    if (totalChunks > 255) {
        return false;  // Message too long
    }

    for (size_t i = 0; i < totalChunks; i++) {
        size_t offset = i * MAX_CHUNK_PAYLOAD;
        size_t chunkSize = std::min(MAX_CHUNK_PAYLOAD, encrypted.size() - offset);

        // Build OP_RETURN data
        std::vector<unsigned char> data;
        data.reserve(CHUNK_HEADER_SIZE + chunkSize);

        // Version
        data.push_back(MSG_VERSION);
        // Type
        data.push_back(MSG_TYPE_TEXT);
        // Recipient hash (20 bytes)
        data.insert(data.end(), recipientHash.begin(), recipientHash.end());
        // Chunk index
        data.push_back(static_cast<uint8_t>(i));
        // Total chunks
        data.push_back(static_cast<uint8_t>(totalChunks));
        // Encrypted payload
        data.insert(data.end(), encrypted.begin() + offset, encrypted.begin() + offset + chunkSize);

        // Create OP_RETURN script
        CScript script;
        script << OP_RETURN << data;
        scripts.push_back(script);
    }

    return true;
}

bool ParseMessageScript(const CScript& script,
                        uint8_t& version,
                        uint8_t& msgType,
                        uint160& recipientHash,
                        std::vector<unsigned char>& payload)
{
    // Check if it's an OP_RETURN
    if (script.size() < 2 || script[0] != OP_RETURN) {
        return false;
    }

    // Extract the data
    std::vector<unsigned char> data;
    CScript::const_iterator it = script.begin() + 1;

    opcodetype opcode;
    if (!script.GetOp(it, opcode, data)) {
        return false;
    }

    // Minimum size: version(1) + type(1) + recipient(20) + chunk_info(2) = 24
    if (data.size() < 24) {
        return false;
    }

    // Parse header
    version = data[0];
    if (version != MSG_VERSION) {
        return false;  // Unknown version
    }

    msgType = data[1];

    // Extract recipient hash
    memcpy(recipientHash.begin(), data.data() + 2, 20);

    // Extract chunk info (bytes 22-23)
    // uint8_t chunkIndex = data[22];
    // uint8_t totalChunks = data[23];

    // Extract payload (everything after header)
    payload.assign(data.begin() + 24, data.end());

    return true;
}

// ============================================================================
// Wallet Message Functions
// ============================================================================

std::string SendMessage(CWallet& wallet,
                        const std::string& recipientAddress,
                        const std::string& message,
                        uint256& txid)
{
    LOCK(wallet.cs_wallet);

    // Decode recipient address
    CTxDestination dest = DecodeDestination(recipientAddress);
    if (!IsValidDestination(dest)) {
        return "Invalid recipient address";
    }

    // Get recipient's public key hash
    if (!std::holds_alternative<PKHash>(dest)) {
        return "Recipient must be a standard P2PKH address";
    }
    PKHash recipientKeyHash = std::get<PKHash>(dest);
    uint160 recipientHash(recipientKeyHash);

    // We need the recipient's public key for ECDH
    // For now, require the recipient to have sent us a transaction (so we have their pubkey)
    // Or use a key exchange protocol

    // Try to find recipient's public key from previous transactions
    CPubKey recipientPubKey;
    bool foundPubKey = false;

    // Search through wallet transactions for the recipient's public key
    for (const auto& [wtxid, wtx] : wallet.mapWallet) {
        for (const CTxIn& txin : wtx.tx->vin) {
            // Check if this input is from the recipient
            if (txin.scriptSig.size() > 0) {
                // Try to extract public key from scriptSig
                std::vector<std::vector<unsigned char>> solutions;
                // P2PKH scriptSig: <sig> <pubkey>
                CScript::const_iterator it = txin.scriptSig.begin();
                opcodetype opcode;
                std::vector<unsigned char> data;

                // Skip signature
                if (txin.scriptSig.GetOp(it, opcode, data)) {
                    // Get public key
                    if (txin.scriptSig.GetOp(it, opcode, data)) {
                        if (data.size() == 33 || data.size() == 65) {
                            CPubKey testPubKey(data);
                            if (testPubKey.IsValid()) {
                                // Check if this pubkey hashes to recipient
                                if (PKHash(testPubKey) == recipientKeyHash) {
                                    recipientPubKey = testPubKey;
                                    foundPubKey = true;
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        }
        if (foundPubKey) break;
    }

    if (!foundPubKey) {
        return "Cannot find recipient's public key. They must send you a transaction first, or publish their public key.";
    }

    // Get a key from our wallet to use as sender
    CKey senderKey;
    CPubKey senderPubKey;

    // Find a key we control - use first valid P2PKH or P2WPKH address from address book
    CTxDestination senderDest;
    bool foundSender = false;
    for (const auto& [addr, data] : wallet.m_address_book) {
        // Skip if not ours
        if (!wallet.IsMine(addr)) continue;

        // Skip if not a valid destination
        if (!IsValidDestination(addr)) continue;

        // Only use P2PKH (PKHash) or P2WPKH (WitnessV0KeyHash) addresses for messaging
        if (std::holds_alternative<PKHash>(addr) || std::holds_alternative<WitnessV0KeyHash>(addr)) {
            senderDest = addr;
            foundSender = true;
            break;
        }
    }

    if (!foundSender) {
        return "No addresses available in wallet";
    }

    // Get the key for this address - support P2PKH and P2WPKH
    CKeyID senderKeyId;
    if (std::holds_alternative<PKHash>(senderDest)) {
        senderKeyId = ToKeyID(std::get<PKHash>(senderDest));
    } else if (std::holds_alternative<WitnessV0KeyHash>(senderDest)) {
        senderKeyId = ToKeyID(std::get<WitnessV0KeyHash>(senderDest));
    } else {
        return strprintf("Sender address type not supported for messaging: %s", EncodeDestination(senderDest));
    }

    // Get key using helper that works with both legacy and descriptor wallets
    if (!GetKeyFromWallet(wallet, senderKeyId, senderKey)) {
        return strprintf("Could not get private key for address %s - wallet may need to be unlocked", EncodeDestination(senderDest));
    }
    senderPubKey = senderKey.GetPubKey();

    // Create message scripts
    std::vector<CScript> msgScripts;
    if (!CreateMessageScripts(message, senderKey, recipientPubKey, recipientHash, msgScripts)) {
        return "Failed to create message scripts";
    }

    // Create transaction with OP_RETURN outputs
    // First, create a recipient for a small payment to the recipient (so they see it)
    std::vector<CRecipient> recipients;
    CAmount dustAmount = 100000; // 0.001 WTX - above dust threshold

    recipients.push_back({dest, dustAmount, false});

    // Create the base transaction
    CCoinControl coinControl;
    auto res = CreateTransaction(wallet, recipients, std::nullopt, coinControl, true);
    if (!res) {
        return strprintf("Failed to create transaction: %s", util::ErrorString(res).original);
    }

    // Get the mutable transaction to add OP_RETURN outputs
    CMutableTransaction mtx(*res->tx);

    // Add OP_RETURN outputs with the encrypted message (0 value for OP_RETURN)
    for (const CScript& script : msgScripts) {
        mtx.vout.push_back(CTxOut(0, script));
    }

    // Re-sign the transaction since we modified it
    // Need to sign each input
    std::map<COutPoint, Coin> coins;
    for (const CTxIn& input : mtx.vin) {
        auto it = wallet.mapWallet.find(input.prevout.hash);
        if (it != wallet.mapWallet.end() && input.prevout.n < it->second.tx->vout.size()) {
            // Coin(CTxOut, height, isCoinBase, isCoinStake)
            coins[input.prevout] = Coin(it->second.tx->vout[input.prevout.n], 1, false, false);
        }
    }

    // Sign with the wallet
    std::map<int, bilingual_str> input_errors;
    bool signed_ok = wallet.SignTransaction(mtx, coins, SIGHASH_ALL, input_errors);
    if (!signed_ok) {
        std::string err_str;
        for (const auto& [idx, err] : input_errors) {
            err_str += strprintf("Input %d: %s; ", idx, err.original);
        }
        return strprintf("Failed to sign message transaction: %s", err_str);
    }

    // Create the final transaction
    CTransactionRef tx = MakeTransactionRef(std::move(mtx));

    // Commit the transaction
    wallet.CommitTransaction(tx, {}, {});

    txid = tx->GetHash();
    return "";  // Success
}

int ScanTransactionForMessages(const CWallet& wallet,
                               const CTransaction& tx,
                               int blockHeight,
                               int64_t blockTime,
                               std::vector<OnChainMessage>& messages)
{
    int found = 0;

    // Get our addresses
    std::set<uint160> ourAddressHashes;
    for (const auto& [dest, data] : wallet.m_address_book) {
        if (std::holds_alternative<PKHash>(dest)) {
            ourAddressHashes.insert(uint160(std::get<PKHash>(dest)));
        }
    }

    // Also add addresses from our keys
    auto spk_man = wallet.GetLegacyScriptPubKeyMan();
    if (spk_man) {
        std::set<CKeyID> keyIds = spk_man->GetKeys();
        for (const CKeyID& keyId : keyIds) {
            ourAddressHashes.insert(uint160(keyId));
        }
    }

    // Check each output for OP_RETURN messages
    for (const CTxOut& txout : tx.vout) {
        uint8_t version, msgType;
        uint160 recipientHash;
        std::vector<unsigned char> payload;

        if (ParseMessageScript(txout.scriptPubKey, version, msgType, recipientHash, payload)) {
            // Check if this message is for one of our addresses
            bool isForUs = ourAddressHashes.count(recipientHash) > 0;

            // Also check if we sent it (check inputs)
            bool isFromUs = false;
            std::string senderAddress;

            for (const CTxIn& txin : tx.vin) {
                auto it = wallet.mapWallet.find(txin.prevout.hash);
                if (it != wallet.mapWallet.end()) {
                    if (txin.prevout.n < it->second.tx->vout.size()) {
                        const CTxOut& prevOut = it->second.tx->vout[txin.prevout.n];
                        if (wallet.IsMine(prevOut)) {
                            isFromUs = true;
                            CTxDestination senderDest;
                            if (ExtractDestination(prevOut.scriptPubKey, senderDest)) {
                                senderAddress = EncodeDestination(senderDest);
                            }
                            break;
                        }
                    }
                }
            }

            if (isForUs || isFromUs) {
                OnChainMessage msg;
                msg.txid = tx.GetHash();
                msg.timestamp = blockTime;
                msg.blockHeight = blockHeight;
                msg.senderAddress = senderAddress;
                msg.recipientAddress = EncodeDestination(PKHash(recipientHash));
                msg.encryptedData = payload;
                msg.isOutgoing = isFromUs && !isForUs;
                msg.isRead = isFromUs;  // Messages we sent are automatically "read"
                msg.msgType = msgType;

                // TODO: Extract chunk info and reassemble multi-part messages
                msg.chunkIndex = 0;
                msg.totalChunks = 1;

                // Try to decrypt the message
                // We need the other party's public key to derive the shared secret
                CPubKey otherPartyPubKey;
                bool canDecrypt = false;

                // First, always try to get sender's pubkey from this transaction's inputs
                // This works for received messages AND self-messages
                CPubKey senderPubKey;
                for (const CTxIn& txin : tx.vin) {
                    if (ExtractPubKeyFromInput(txin, senderPubKey)) {
                        break;
                    }
                }

                if (isForUs) {
                    // Message is TO us (or to ourselves) - use sender's pubkey from inputs
                    if (senderPubKey.IsValid()) {
                        otherPartyPubKey = senderPubKey;
                        canDecrypt = true;
                    }

                    if (canDecrypt) {
                        // Decrypt using our key (recipient) and sender's pubkey
                        std::string decrypted;
                        if (TryDecryptMessage(wallet, payload, otherPartyPubKey, recipientHash, decrypted)) {
                            msg.decryptedText = decrypted;
                        }
                    }
                } else if (isFromUs && !isForUs) {
                    // Message is FROM us - we need recipient's pubkey
                    // Look in blockchain for a transaction where they spent (exposing their pubkey)
                    // For now, search our wallet transactions for their pubkey
                    for (const auto& [wtxid, wtx] : wallet.mapWallet) {
                        for (const CTxIn& txin : wtx.tx->vin) {
                            // Check if this input was from the recipient address
                            auto prevIt = wallet.mapWallet.find(txin.prevout.hash);
                            if (prevIt != wallet.mapWallet.end() &&
                                txin.prevout.n < prevIt->second.tx->vout.size()) {
                                const CTxOut& prevOut = prevIt->second.tx->vout[txin.prevout.n];
                                CTxDestination prevDest;
                                if (ExtractDestination(prevOut.scriptPubKey, prevDest)) {
                                    if (std::holds_alternative<PKHash>(prevDest)) {
                                        PKHash prevHash = std::get<PKHash>(prevDest);
                                        if (uint160(prevHash) == recipientHash) {
                                            // Found! Extract pubkey from the input
                                            if (ExtractPubKeyFromInput(txin, otherPartyPubKey)) {
                                                canDecrypt = true;
                                                break;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        if (canDecrypt) break;
                    }

                    if (canDecrypt) {
                        // Get our sending key from the inputs of THIS transaction
                        CKeyID senderKeyId;
                        for (const CTxIn& txin : tx.vin) {
                            auto it = wallet.mapWallet.find(txin.prevout.hash);
                            if (it != wallet.mapWallet.end() &&
                                txin.prevout.n < it->second.tx->vout.size()) {
                                const CTxOut& prevOut = it->second.tx->vout[txin.prevout.n];
                                if (wallet.IsMine(prevOut)) {
                                    CTxDestination senderDest;
                                    if (ExtractDestination(prevOut.scriptPubKey, senderDest)) {
                                        if (std::holds_alternative<PKHash>(senderDest)) {
                                            senderKeyId = CKeyID(uint160(std::get<PKHash>(senderDest)));
                                            break;
                                        }
                                    }
                                }
                            }
                        }

                        if (!senderKeyId.IsNull()) {
                            std::string decrypted;
                            if (TryDecryptMessage(wallet, payload, otherPartyPubKey, uint160(senderKeyId), decrypted)) {
                                msg.decryptedText = decrypted;
                            }
                        }
                    }
                }

                messages.push_back(msg);
                found++;
            }
        }
    }

    return found;
}

bool GetMessages(const CWallet& wallet,
                 std::vector<OnChainMessage>& messages,
                 bool includeOutgoing)
{
    LOCK(wallet.cs_wallet);
    messages.clear();

    // Scan all wallet transactions
    for (const auto& [txid, wtx] : wallet.mapWallet) {
        int blockHeight = -1;
        int64_t blockTime = wtx.GetTxTime();

        if (wtx.isConfirmed()) {
            blockHeight = wallet.GetTxDepthInMainChain(wtx);
        }

        std::vector<OnChainMessage> txMessages;
        ScanTransactionForMessages(wallet, *wtx.tx, blockHeight, blockTime, txMessages);

        for (auto& msg : txMessages) {
            if (includeOutgoing || !msg.isOutgoing) {
                messages.push_back(std::move(msg));
            }
        }
    }

    // Sort by timestamp (newest first)
    std::sort(messages.begin(), messages.end(),
              [](const OnChainMessage& a, const OnChainMessage& b) {
                  return a.timestamp > b.timestamp;
              });

    return true;
}

bool GetConversation(const CWallet& wallet,
                     const std::string& peerAddress,
                     std::vector<OnChainMessage>& messages)
{
    std::vector<OnChainMessage> allMessages;
    if (!GetMessages(wallet, allMessages, true)) {
        return false;
    }

    messages.clear();
    for (auto& msg : allMessages) {
        if (msg.senderAddress == peerAddress || msg.recipientAddress == peerAddress) {
            messages.push_back(std::move(msg));
        }
    }

    // Sort by timestamp (oldest first for conversation view)
    std::sort(messages.begin(), messages.end(),
              [](const OnChainMessage& a, const OnChainMessage& b) {
                  return a.timestamp < b.timestamp;
              });

    return true;
}

bool GetConversations(const CWallet& wallet,
                      std::vector<Conversation>& conversations)
{
    std::vector<OnChainMessage> allMessages;
    if (!GetMessages(wallet, allMessages, true)) {
        return false;
    }

    std::map<std::string, Conversation> convMap;

    for (const auto& msg : allMessages) {
        std::string peerAddr = msg.isOutgoing ? msg.recipientAddress : msg.senderAddress;

        auto it = convMap.find(peerAddr);
        if (it == convMap.end()) {
            Conversation conv;
            conv.peerAddress = peerAddr;
            conv.lastMessageTime = msg.timestamp;
            conv.unreadCount = (!msg.isRead && !msg.isOutgoing) ? 1 : 0;
            conv.lastMessagePreview = msg.decryptedText.empty() ? "[Encrypted]" :
                                      msg.decryptedText.substr(0, 50);
            convMap[peerAddr] = conv;
        } else {
            if (msg.timestamp > it->second.lastMessageTime) {
                it->second.lastMessageTime = msg.timestamp;
                it->second.lastMessagePreview = msg.decryptedText.empty() ? "[Encrypted]" :
                                                msg.decryptedText.substr(0, 50);
            }
            if (!msg.isRead && !msg.isOutgoing) {
                it->second.unreadCount++;
            }
        }
    }

    conversations.clear();
    for (auto& [addr, conv] : convMap) {
        // Try to get label from address book
        CTxDestination dest = DecodeDestination(addr);
        if (IsValidDestination(dest)) {
            const auto* entry = wallet.FindAddressBookEntry(dest);
            if (entry) {
                conv.peerLabel = entry->GetLabel();
            }
        }
        conversations.push_back(std::move(conv));
    }

    // Sort by last message time (newest first)
    std::sort(conversations.begin(), conversations.end(),
              [](const Conversation& a, const Conversation& b) {
                  return a.lastMessageTime > b.lastMessageTime;
              });

    return true;
}

bool MarkMessageRead(CWallet& wallet, const uint256& txid)
{
    // TODO: Store read status in wallet database
    // For now, this is a no-op
    return true;
}

} // namespace wallet
