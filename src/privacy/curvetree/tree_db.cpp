// Copyright (c) 2024-2026 The WATTx Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <privacy/curvetree/tree_db.h>

#include <leveldb/cache.h>
#include <leveldb/filter_policy.h>

#include <cstring>
#include <stdexcept>

namespace curvetree {

// Key prefixes
constexpr char PREFIX_NODE = 'N';
constexpr char PREFIX_OUTPUT = 'O';
constexpr char PREFIX_METADATA = 'M';

// ============================================================================
// LevelDBTreeStorage Implementation
// ============================================================================

LevelDBTreeStorage::LevelDBTreeStorage(const std::filesystem::path& db_path)
    : m_in_batch(false)
    , m_cached_output_count(0)
    , m_output_count_dirty(true)
{
    leveldb::Options options;
    options.create_if_missing = true;
    options.max_open_files = 64;
    options.block_cache = leveldb::NewLRUCache(8 * 1024 * 1024); // 8MB cache
    options.filter_policy = leveldb::NewBloomFilterPolicy(10);
    options.write_buffer_size = 4 * 1024 * 1024; // 4MB write buffer

    leveldb::DB* db_ptr = nullptr;
    leveldb::Status status = leveldb::DB::Open(options, db_path.string(), &db_ptr);

    if (!status.ok()) {
        throw std::runtime_error("Failed to open curve tree database: " + status.ToString());
    }

    m_db.reset(db_ptr);
}

LevelDBTreeStorage::~LevelDBTreeStorage() {
    if (m_in_batch) {
        AbortBatch();
    }
    // DB is automatically closed by unique_ptr destructor
}

std::string LevelDBTreeStorage::MakeNodeKey(const TreeIndex& index) {
    std::string key;
    key.reserve(13);
    key.push_back(PREFIX_NODE);

    // Layer (4 bytes, big-endian for sorted iteration)
    key.push_back((index.layer >> 24) & 0xFF);
    key.push_back((index.layer >> 16) & 0xFF);
    key.push_back((index.layer >> 8) & 0xFF);
    key.push_back(index.layer & 0xFF);

    // Index (8 bytes, big-endian)
    for (int i = 7; i >= 0; --i) {
        key.push_back((index.index >> (i * 8)) & 0xFF);
    }

    return key;
}

std::string LevelDBTreeStorage::MakeOutputKey(uint64_t index) {
    std::string key;
    key.reserve(9);
    key.push_back(PREFIX_OUTPUT);

    // Index (8 bytes, big-endian)
    for (int i = 7; i >= 0; --i) {
        key.push_back((index >> (i * 8)) & 0xFF);
    }

    return key;
}

std::string LevelDBTreeStorage::MakeMetadataKey(const std::string& key) {
    return std::string(1, PREFIX_METADATA) + key;
}

std::string LevelDBTreeStorage::SerializeNode(const TreeNode& node) {
    std::string data;
    data.reserve(40); // 32 bytes hash + 8 bytes count

    // Hash
    data.append(reinterpret_cast<const char*>(node.hash.data.data()), 32);

    // Child count (8 bytes, little-endian)
    for (int i = 0; i < 8; ++i) {
        data.push_back((node.child_count >> (i * 8)) & 0xFF);
    }

    return data;
}

std::optional<TreeNode> LevelDBTreeStorage::DeserializeNode(const std::string& data) {
    if (data.size() != 40) {
        return std::nullopt;
    }

    TreeNode node;

    // Hash
    std::memcpy(node.hash.data.data(), data.data(), 32);

    // Child count
    node.child_count = 0;
    for (int i = 0; i < 8; ++i) {
        node.child_count |= static_cast<uint64_t>(static_cast<uint8_t>(data[32 + i])) << (i * 8);
    }

    return node;
}

bool LevelDBTreeStorage::StoreNode(const TreeIndex& index, const TreeNode& node) {
    std::lock_guard<std::mutex> lock(m_mutex);

    std::string key = MakeNodeKey(index);
    std::string value = SerializeNode(node);

    if (m_in_batch) {
        m_batch->Put(key, value);
        return true;
    }

    leveldb::Status status = m_db->Put(leveldb::WriteOptions(), key, value);
    return status.ok();
}

std::optional<TreeNode> LevelDBTreeStorage::GetNode(const TreeIndex& index) {
    std::lock_guard<std::mutex> lock(m_mutex);

    std::string key = MakeNodeKey(index);
    std::string value;

    leveldb::Status status = m_db->Get(leveldb::ReadOptions(), key, &value);
    if (!status.ok()) {
        return std::nullopt;
    }

    return DeserializeNode(value);
}

bool LevelDBTreeStorage::DeleteNode(const TreeIndex& index) {
    std::lock_guard<std::mutex> lock(m_mutex);

    std::string key = MakeNodeKey(index);

    if (m_in_batch) {
        m_batch->Delete(key);
        return true;
    }

    leveldb::Status status = m_db->Delete(leveldb::WriteOptions(), key);
    return status.ok();
}

bool LevelDBTreeStorage::StoreOutput(uint64_t index, const OutputTuple& output) {
    std::lock_guard<std::mutex> lock(m_mutex);

    std::string key = MakeOutputKey(index);
    auto data = output.Serialize();
    std::string value(data.begin(), data.end());

    m_output_count_dirty = true;

    if (m_in_batch) {
        m_batch->Put(key, value);
        return true;
    }

    leveldb::Status status = m_db->Put(leveldb::WriteOptions(), key, value);
    return status.ok();
}

bool LevelDBTreeStorage::DeleteOutput(uint64_t index) {
    std::lock_guard<std::mutex> lock(m_mutex);

    std::string key = MakeOutputKey(index);
    m_output_count_dirty = true;

    if (m_in_batch) {
        m_batch->Delete(key);
        return true;
    }

    leveldb::Status status = m_db->Delete(leveldb::WriteOptions(), key);
    return status.ok();
}

std::optional<OutputTuple> LevelDBTreeStorage::GetOutput(uint64_t index) {
    std::lock_guard<std::mutex> lock(m_mutex);

    std::string key = MakeOutputKey(index);
    std::string value;

    leveldb::Status status = m_db->Get(leveldb::ReadOptions(), key, &value);
    if (!status.ok()) {
        return std::nullopt;
    }

    std::vector<uint8_t> data(value.begin(), value.end());
    return OutputTuple::Deserialize(data);
}

bool LevelDBTreeStorage::StoreMetadata(const std::string& key, const std::vector<uint8_t>& value) {
    std::lock_guard<std::mutex> lock(m_mutex);

    std::string db_key = MakeMetadataKey(key);
    std::string db_value(value.begin(), value.end());

    if (m_in_batch) {
        m_batch->Put(db_key, db_value);
        return true;
    }

    leveldb::Status status = m_db->Put(leveldb::WriteOptions(), db_key, db_value);
    return status.ok();
}

std::optional<std::vector<uint8_t>> LevelDBTreeStorage::GetMetadata(const std::string& key) {
    std::lock_guard<std::mutex> lock(m_mutex);

    std::string db_key = MakeMetadataKey(key);
    std::string value;

    leveldb::Status status = m_db->Get(leveldb::ReadOptions(), db_key, &value);
    if (!status.ok()) {
        return std::nullopt;
    }

    return std::vector<uint8_t>(value.begin(), value.end());
}

void LevelDBTreeStorage::BeginBatch() {
    std::lock_guard<std::mutex> lock(m_mutex);

    if (m_in_batch) {
        return; // Already in batch
    }

    m_batch = std::make_unique<leveldb::WriteBatch>();
    m_in_batch = true;
}

bool LevelDBTreeStorage::CommitBatch() {
    std::lock_guard<std::mutex> lock(m_mutex);

    if (!m_in_batch) {
        return false;
    }

    leveldb::WriteOptions options;
    options.sync = false; // Async for performance, call Sync() for durability

    leveldb::Status status = m_db->Write(options, m_batch.get());

    m_batch.reset();
    m_in_batch = false;

    return status.ok();
}

void LevelDBTreeStorage::AbortBatch() {
    std::lock_guard<std::mutex> lock(m_mutex);

    m_batch.reset();
    m_in_batch = false;
}

uint64_t LevelDBTreeStorage::GetOutputCount() {
    std::lock_guard<std::mutex> lock(m_mutex);

    if (!m_output_count_dirty) {
        return m_cached_output_count;
    }

    // Count outputs by iterating with prefix
    std::string prefix(1, PREFIX_OUTPUT);
    uint64_t count = 0;

    std::unique_ptr<leveldb::Iterator> it(m_db->NewIterator(leveldb::ReadOptions()));
    for (it->Seek(prefix); it->Valid(); it->Next()) {
        leveldb::Slice key = it->key();
        // Check if key starts with prefix
        if (key.size() < prefix.size() ||
            std::memcmp(key.data(), prefix.data(), prefix.size()) != 0) {
            break;
        }
        count++;
    }

    m_cached_output_count = count;
    m_output_count_dirty = false;

    return count;
}

void LevelDBTreeStorage::Compact() {
    if (m_db) {
        m_db->CompactRange(nullptr, nullptr);
    }
}

std::string LevelDBTreeStorage::GetStats() const {
    std::string stats;
    if (m_db) {
        std::string value;
        if (m_db->GetProperty("leveldb.stats", &value)) {
            stats = value;
        }
        if (m_db->GetProperty("leveldb.sstables", &value)) {
            stats += "\n" + value;
        }
    }
    return stats;
}

bool LevelDBTreeStorage::Sync() {
    if (!m_db) {
        return false;
    }

    // Write an empty batch with sync flag
    leveldb::WriteBatch empty_batch;
    leveldb::WriteOptions options;
    options.sync = true;

    return m_db->Write(options, &empty_batch).ok();
}

// ============================================================================
// TreeStorageFactory Implementation
// ============================================================================

std::shared_ptr<ITreeStorage> TreeStorageFactory::Create(StorageType type,
                                                         const std::filesystem::path& path) {
    switch (type) {
        case StorageType::Memory:
            return std::make_shared<MemoryTreeStorage>();

        case StorageType::LevelDB:
            if (path.empty()) {
                throw std::runtime_error("LevelDB storage requires a path");
            }
            return std::make_shared<LevelDBTreeStorage>(path);

        default:
            throw std::runtime_error("Unknown storage type");
    }
}

std::shared_ptr<ITreeStorage> TreeStorageFactory::CreateDefault(const std::filesystem::path& data_dir) {
    std::filesystem::path db_path = data_dir / "curvetree";
    std::filesystem::create_directories(db_path);
    return Create(StorageType::LevelDB, db_path);
}

} // namespace curvetree
