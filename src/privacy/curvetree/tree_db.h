// Copyright (c) 2024-2026 The WATTx Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef WATTX_PRIVACY_CURVETREE_DB_H
#define WATTX_PRIVACY_CURVETREE_DB_H

#include <privacy/curvetree/curve_tree.h>

#include <leveldb/db.h>
#include <leveldb/write_batch.h>

#include <filesystem>
#include <memory>
#include <mutex>

namespace curvetree {

/**
 * LevelDB-backed storage for curve tree.
 * Provides persistent storage with efficient batch operations.
 *
 * Key format:
 * - Nodes:    'N' + layer (4 bytes) + index (8 bytes)
 * - Outputs:  'O' + index (8 bytes)
 * - Metadata: 'M' + key string
 */
class LevelDBTreeStorage : public ITreeStorage {
public:
    // Open or create database at path
    explicit LevelDBTreeStorage(const std::filesystem::path& db_path);

    ~LevelDBTreeStorage() override;

    // Prevent copying
    LevelDBTreeStorage(const LevelDBTreeStorage&) = delete;
    LevelDBTreeStorage& operator=(const LevelDBTreeStorage&) = delete;

    // ITreeStorage interface
    bool StoreNode(const TreeIndex& index, const TreeNode& node) override;
    std::optional<TreeNode> GetNode(const TreeIndex& index) override;
    bool DeleteNode(const TreeIndex& index) override;

    bool StoreOutput(uint64_t index, const OutputTuple& output) override;
    std::optional<OutputTuple> GetOutput(uint64_t index) override;
    bool DeleteOutput(uint64_t index) override;

    bool StoreMetadata(const std::string& key, const std::vector<uint8_t>& value) override;
    std::optional<std::vector<uint8_t>> GetMetadata(const std::string& key) override;

    void BeginBatch() override;
    bool CommitBatch() override;
    void AbortBatch() override;

    uint64_t GetOutputCount() override;

    // Additional methods
    bool IsOpen() const { return m_db != nullptr; }

    // Compact the database
    void Compact();

    // Get database statistics
    std::string GetStats() const;

    // Flush to disk
    bool Sync();

private:
    // Key construction helpers
    static std::string MakeNodeKey(const TreeIndex& index);
    static std::string MakeOutputKey(uint64_t index);
    static std::string MakeMetadataKey(const std::string& key);

    // Serialization helpers
    static std::string SerializeNode(const TreeNode& node);
    static std::optional<TreeNode> DeserializeNode(const std::string& data);

    std::unique_ptr<leveldb::DB> m_db;
    std::unique_ptr<leveldb::WriteBatch> m_batch;
    bool m_in_batch;
    mutable std::mutex m_mutex;

    // Cache output count for efficiency
    mutable uint64_t m_cached_output_count;
    mutable bool m_output_count_dirty;
};

/**
 * Factory for creating tree storage instances.
 * Supports both in-memory (testing) and LevelDB (production) backends.
 */
class TreeStorageFactory {
public:
    enum class StorageType {
        Memory,
        LevelDB
    };

    static std::shared_ptr<ITreeStorage> Create(StorageType type,
                                                const std::filesystem::path& path = "");

    // Create default storage for the node's data directory
    static std::shared_ptr<ITreeStorage> CreateDefault(const std::filesystem::path& data_dir);
};

} // namespace curvetree

#endif // WATTX_PRIVACY_CURVETREE_DB_H
