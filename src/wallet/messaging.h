// Copyright (c) 2024-2026 The WATTx Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_WALLET_MESSAGING_H
#define BITCOIN_WALLET_MESSAGING_H

#include <key.h>
#include <primitives/transaction.h>
#include <pubkey.h>
#include <uint256.h>
#include <script/script.h>

#include <string>
#include <vector>

// Windows winuser.h defines SendMessage as a macro
#ifdef SendMessage
#undef SendMessage
#endif
#include <cstdint>

namespace wallet {

class CWallet;

// Message protocol version
static constexpr uint8_t MSG_VERSION = 0x01;

// Message type identifiers
static constexpr uint8_t MSG_TYPE_TEXT = 0x01;
static constexpr uint8_t MSG_TYPE_FILE = 0x02;  // Future use

// OP_RETURN max size (standard)
static constexpr size_t MAX_OP_RETURN_SIZE = 80;

// Message header size: version(1) + type(1) + recipient(20) = 22 bytes
static constexpr size_t MSG_HEADER_SIZE = 22;

// Max message payload per OP_RETURN
static constexpr size_t MAX_MSG_PAYLOAD = MAX_OP_RETURN_SIZE - MSG_HEADER_SIZE;

// Encryption overhead (nonce + tag for AES-GCM)
static constexpr size_t ENCRYPTION_OVERHEAD = 28;  // 12 byte nonce + 16 byte tag

/**
 * Encrypted message stored on-chain
 */
struct OnChainMessage {
    uint256 txid;                    // Transaction containing the message
    int64_t timestamp;               // Block timestamp (or mempool time)
    int blockHeight;                 // Block height (-1 if unconfirmed)
    std::string senderAddress;       // Sender's address (from tx inputs)
    std::string recipientAddress;    // Recipient's address
    std::vector<unsigned char> encryptedData;  // Encrypted message content
    std::string decryptedText;       // Decrypted message (if we can decrypt)
    bool isOutgoing;                 // True if we sent this message
    bool isRead;                     // True if message has been read
    uint8_t msgType;                 // Message type (text, file, etc.)
    uint32_t chunkIndex;             // For multi-part messages
    uint32_t totalChunks;            // Total chunks in message
};

/**
 * Conversation thread between two addresses
 */
struct Conversation {
    std::string peerAddress;         // The other party's address
    std::string peerLabel;           // Label from address book (if any)
    int64_t lastMessageTime;         // Timestamp of last message
    int unreadCount;                 // Number of unread messages
    std::string lastMessagePreview;  // Preview of last message
};

// ============================================================================
// Encryption Functions
// ============================================================================

/**
 * Derive a shared secret using ECDH
 * @param myPrivKey Our private key
 * @param theirPubKey Their public key
 * @param sharedSecret Output: 32-byte shared secret
 * @return true if successful
 */
bool DeriveSharedSecret(const CKey& myPrivKey, const CPubKey& theirPubKey,
                        std::vector<unsigned char>& sharedSecret);

/**
 * Encrypt a message using AES-256-GCM with ECDH-derived key
 * @param plaintext The message to encrypt
 * @param sharedSecret 32-byte shared secret from ECDH
 * @param ciphertext Output: encrypted data (nonce + ciphertext + tag)
 * @return true if successful
 */
bool EncryptMessage(const std::string& plaintext,
                    const std::vector<unsigned char>& sharedSecret,
                    std::vector<unsigned char>& ciphertext);

/**
 * Decrypt a message using AES-256-GCM
 * @param ciphertext Encrypted data (nonce + ciphertext + tag)
 * @param sharedSecret 32-byte shared secret from ECDH
 * @param plaintext Output: decrypted message
 * @return true if successful
 */
bool DecryptMessage(const std::vector<unsigned char>& ciphertext,
                    const std::vector<unsigned char>& sharedSecret,
                    std::string& plaintext);

// ============================================================================
// Message Creation Functions
// ============================================================================

/**
 * Create OP_RETURN script(s) for an encrypted message
 * @param message The plaintext message
 * @param senderKey Sender's private key
 * @param recipientPubKey Recipient's public key
 * @param recipientHash Recipient's address hash (20 bytes)
 * @param scripts Output: OP_RETURN scripts (may be multiple for long messages)
 * @return true if successful
 */
bool CreateMessageScripts(const std::string& message,
                          const CKey& senderKey,
                          const CPubKey& recipientPubKey,
                          const uint160& recipientHash,
                          std::vector<CScript>& scripts);

/**
 * Parse an OP_RETURN script to extract message data
 * @param script The OP_RETURN script
 * @param version Output: protocol version
 * @param msgType Output: message type
 * @param recipientHash Output: recipient address hash
 * @param payload Output: encrypted payload
 * @return true if this is a valid WATTx message
 */
bool ParseMessageScript(const CScript& script,
                        uint8_t& version,
                        uint8_t& msgType,
                        uint160& recipientHash,
                        std::vector<unsigned char>& payload);

// ============================================================================
// Wallet Message Functions
// ============================================================================

/**
 * Send an encrypted message to an address
 * @param wallet The wallet to send from
 * @param recipientAddress Recipient's WATTx address
 * @param message The plaintext message
 * @param txid Output: transaction ID
 * @return empty string on success, error message on failure
 */
std::string SendMessage(CWallet& wallet,
                        const std::string& recipientAddress,
                        const std::string& message,
                        uint256& txid);

/**
 * Get all messages for this wallet
 * @param wallet The wallet
 * @param messages Output: list of messages
 * @param includeOutgoing Include messages we sent
 * @return true if successful
 */
bool GetMessages(const CWallet& wallet,
                 std::vector<OnChainMessage>& messages,
                 bool includeOutgoing = true);

/**
 * Get messages in a conversation with a specific address
 * @param wallet The wallet
 * @param peerAddress The other party's address
 * @param messages Output: list of messages
 * @return true if successful
 */
bool GetConversation(const CWallet& wallet,
                     const std::string& peerAddress,
                     std::vector<OnChainMessage>& messages);

/**
 * Get list of conversations
 * @param wallet The wallet
 * @param conversations Output: list of conversations
 * @return true if successful
 */
bool GetConversations(const CWallet& wallet,
                      std::vector<Conversation>& conversations);

/**
 * Mark a message as read
 * @param wallet The wallet
 * @param txid Transaction ID of the message
 * @return true if successful
 */
bool MarkMessageRead(CWallet& wallet, const uint256& txid);

/**
 * Scan a transaction for messages to/from our addresses
 * @param wallet The wallet
 * @param tx The transaction to scan
 * @param blockHeight Block height (-1 if mempool)
 * @param blockTime Block timestamp
 * @param messages Output: any messages found
 * @return Number of messages found
 */
int ScanTransactionForMessages(const CWallet& wallet,
                               const CTransaction& tx,
                               int blockHeight,
                               int64_t blockTime,
                               std::vector<OnChainMessage>& messages);

} // namespace wallet

#endif // BITCOIN_WALLET_MESSAGING_H
