// Copyright (c) 2024-2026 The WATTx Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef WATTX_PRIVACY_CURVETREE_H
#define WATTX_PRIVACY_CURVETREE_H

#include <privacy/ed25519/ed25519_types.h>
#include <privacy/ed25519/pedersen.h>

#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <vector>
#include <functional>

namespace curvetree {

using ed25519::Scalar;
using ed25519::Point;
using ed25519::PedersenHash;

/**
 * Configuration constants for the curve tree.
 * These match FCMP++ specifications for Ed25519.
 */
struct TreeConfig {
    // Elements per output tuple: O.x, O.y, I.x, I.y, C.x, C.y
    static constexpr size_t ELEMENTS_PER_OUTPUT = 6;

    // Branch width for leaf layer (outputs per leaf commitment)
    static constexpr size_t LEAF_BRANCH_WIDTH = 38;

    // Total leaf elements = 6 * 38 = 228
    static constexpr size_t LEAF_LAYER_WIDTH = ELEMENTS_PER_OUTPUT * LEAF_BRANCH_WIDTH;

    // Branch width for internal layers
    static constexpr size_t INTERNAL_BRANCH_WIDTH = 38;

    // Maximum tree depth (log2 of max outputs)
    static constexpr size_t MAX_DEPTH = 32;

    // Minimum outputs before tree is considered valid
    static constexpr size_t MIN_OUTPUTS = 1;
};

/**
 * Output tuple stored in curve tree leaves.
 * Represents a privacy output with:
 * - O: One-time public key (stealth address)
 * - I: Key image (for double-spend prevention)
 * - C: Pedersen commitment to amount
 */
struct OutputTuple {
    Point O;  // One-time public key
    Point I;  // Key image
    Point C;  // Amount commitment

    OutputTuple() = default;
    OutputTuple(const Point& o, const Point& i, const Point& c) : O(o), I(i), C(c) {}

    // Validate that all points are valid and non-identity
    bool IsValid() const;

    // Convert to field elements for tree hashing
    // Returns 6 scalars: [O.x, O.y, I.x, I.y, C.x, C.y]
    std::vector<Scalar> ToFieldElements() const;

    // Serialization
    std::vector<uint8_t> Serialize() const;
    static std::optional<OutputTuple> Deserialize(const std::vector<uint8_t>& data);

    bool operator==(const OutputTuple& other) const;
    bool operator!=(const OutputTuple& other) const { return !(*this == other); }
};

/**
 * Index identifying a position in the curve tree.
 * Used for both outputs (leaves) and internal nodes.
 */
struct TreeIndex {
    uint32_t layer;   // 0 = leaf layer
    uint64_t index;   // Position within layer

    TreeIndex() : layer(0), index(0) {}
    TreeIndex(uint32_t l, uint64_t i) : layer(l), index(i) {}

    bool operator==(const TreeIndex& other) const {
        return layer == other.layer && index == other.index;
    }
    bool operator<(const TreeIndex& other) const {
        return layer < other.layer || (layer == other.layer && index < other.index);
    }

    // Get parent index
    TreeIndex Parent() const {
        return TreeIndex(layer + 1, index / TreeConfig::INTERNAL_BRANCH_WIDTH);
    }

    // Get index within parent's children
    size_t ChildOffset() const {
        return index % TreeConfig::INTERNAL_BRANCH_WIDTH;
    }
};

/**
 * A branch (path) from a leaf to the root.
 * Used for membership proofs.
 */
struct TreeBranch {
    uint64_t leaf_index;                    // Index of the leaf output
    std::vector<std::vector<Scalar>> layers; // Sibling elements at each layer

    TreeBranch() : leaf_index(0) {}

    // Number of layers in the branch (tree depth)
    size_t Depth() const { return layers.size(); }

    // Serialization
    std::vector<uint8_t> Serialize() const;
    static std::optional<TreeBranch> Deserialize(const std::vector<uint8_t>& data);
};

/**
 * Tree node representing either a leaf commitment or internal hash.
 */
struct TreeNode {
    Point hash;           // The Pedersen hash/commitment
    uint64_t child_count; // Number of children (for partial nodes)

    TreeNode() : child_count(0) {}
    explicit TreeNode(const Point& h, uint64_t count = 0) : hash(h), child_count(count) {}

    bool operator==(const TreeNode& other) const {
        return hash == other.hash && child_count == other.child_count;
    }
};

/**
 * Interface for curve tree storage backend.
 * Implementations can use LevelDB, memory, or other storage.
 */
class ITreeStorage {
public:
    virtual ~ITreeStorage() = default;

    // Store/retrieve tree nodes by index
    virtual bool StoreNode(const TreeIndex& index, const TreeNode& node) = 0;
    virtual std::optional<TreeNode> GetNode(const TreeIndex& index) = 0;
    virtual bool DeleteNode(const TreeIndex& index) = 0;

    // Store/retrieve/delete output tuples by leaf index
    virtual bool StoreOutput(uint64_t index, const OutputTuple& output) = 0;
    virtual std::optional<OutputTuple> GetOutput(uint64_t index) = 0;
    virtual bool DeleteOutput(uint64_t index) = 0;

    // Store/retrieve tree metadata
    virtual bool StoreMetadata(const std::string& key, const std::vector<uint8_t>& value) = 0;
    virtual std::optional<std::vector<uint8_t>> GetMetadata(const std::string& key) = 0;

    // Batch operations for efficiency
    virtual void BeginBatch() = 0;
    virtual bool CommitBatch() = 0;
    virtual void AbortBatch() = 0;

    // Get count of outputs
    virtual uint64_t GetOutputCount() = 0;
};

/**
 * In-memory tree storage for testing and small trees.
 */
class MemoryTreeStorage : public ITreeStorage {
public:
    bool StoreNode(const TreeIndex& index, const TreeNode& node) override;
    std::optional<TreeNode> GetNode(const TreeIndex& index) override;
    bool DeleteNode(const TreeIndex& index) override;

    bool StoreOutput(uint64_t index, const OutputTuple& output) override;
    std::optional<OutputTuple> GetOutput(uint64_t index) override;
    bool DeleteOutput(uint64_t index) override;

    bool StoreMetadata(const std::string& key, const std::vector<uint8_t>& value) override;
    std::optional<std::vector<uint8_t>> GetMetadata(const std::string& key) override;

    void BeginBatch() override {}
    bool CommitBatch() override { return true; }
    void AbortBatch() override {}

    uint64_t GetOutputCount() override { return m_outputs.size(); }

private:
    std::map<TreeIndex, TreeNode> m_nodes;
    std::map<uint64_t, OutputTuple> m_outputs;
    std::map<std::string, std::vector<uint8_t>> m_metadata;
};

/**
 * The Curve Tree: an authenticated data structure for privacy outputs.
 *
 * Structure:
 * - Leaf layer: Pedersen commitments to output tuples
 * - Internal layers: Pedersen hashes of child commitments
 * - Root: Single point representing entire tree state
 *
 * Properties:
 * - Membership proofs are O(log n) in size
 * - Updates are O(log n) time
 * - Tree state is binding (cannot forge proofs)
 */
class CurveTree {
public:
    // Create tree with specified storage backend
    explicit CurveTree(std::shared_ptr<ITreeStorage> storage);

    // Create tree with in-memory storage
    CurveTree();

    ~CurveTree() = default;

    // ========== Tree State ==========

    // Get the current tree root
    Point GetRoot() const;

    // Get number of outputs in tree
    uint64_t GetOutputCount() const;

    // Get tree depth (number of layers including leaves)
    uint32_t GetDepth() const;

    // Check if tree is empty
    bool IsEmpty() const { return GetOutputCount() == 0; }

    // ========== Output Management ==========

    // Add a new output to the tree
    // Returns the leaf index of the added output
    uint64_t AddOutput(const OutputTuple& output);

    // Add multiple outputs (more efficient than individual adds)
    std::vector<uint64_t> AddOutputs(const std::vector<OutputTuple>& outputs);

    // Get output by leaf index
    std::optional<OutputTuple> GetOutput(uint64_t index) const;

    // Check if an output exists at the given index
    bool HasOutput(uint64_t index) const;

    // Remove the last N outputs from the tree (for reorg handling)
    // Returns true on success
    bool RemoveLastN(uint64_t count);

    // ========== Branch/Proof Operations ==========

    // Extract a branch (Merkle path) for the given leaf index
    std::optional<TreeBranch> GetBranch(uint64_t leaf_index) const;

    // Verify that a branch is valid for the given output and root
    static bool VerifyBranch(const OutputTuple& output, const TreeBranch& branch,
                             const Point& expected_root);

    // ========== Tree Maintenance ==========

    // Rebuild the entire tree from stored outputs
    // Use after loading from storage or to fix corrupted tree
    bool Rebuild();

    // Verify tree integrity (all hashes are correct)
    bool VerifyIntegrity() const;

    // Get the Pedersen hasher used by this tree
    const PedersenHash& GetHasher() const { return m_hasher; }

    // ========== Persistence ==========

    // Save tree metadata to storage
    bool Save();

    // Load tree metadata from storage
    bool Load();

private:
    // Compute leaf commitment from output tuple
    Point ComputeLeafCommitment(const std::vector<Scalar>& elements) const;

    // Compute leaf node (commitment for a group of outputs)
    Point ComputeLeafNode(uint64_t leaf_index) const;

    // Compute internal node hash from children
    Point ComputeNodeHash(const std::vector<Point>& children) const;

    // Update tree from leaf index up to root
    void UpdatePath(uint64_t leaf_index);

    // Get children of a node
    std::vector<Point> GetChildren(const TreeIndex& parent) const;

    // Calculate required depth for given output count
    static uint32_t CalculateDepth(uint64_t output_count);

    // Storage backend
    std::shared_ptr<ITreeStorage> m_storage;

    // Pedersen hasher for tree operations
    PedersenHash m_hasher;

    // Cached tree state
    mutable Point m_cached_root;
    mutable bool m_root_dirty;
    uint64_t m_output_count;
    uint32_t m_depth;
};

/**
 * Builder for constructing curve trees from UTXO sets.
 * Provides batch construction with progress callbacks.
 */
class CurveTreeBuilder {
public:
    using ProgressCallback = std::function<void(uint64_t processed, uint64_t total)>;

    explicit CurveTreeBuilder(std::shared_ptr<ITreeStorage> storage);

    // Set progress callback
    void SetProgressCallback(ProgressCallback callback) { m_progress_cb = callback; }

    // Add outputs in batch
    void AddOutputs(const std::vector<OutputTuple>& outputs);

    // Finalize tree construction
    std::unique_ptr<CurveTree> Finalize();

    // Get current output count
    uint64_t GetOutputCount() const { return m_outputs.size(); }

private:
    std::shared_ptr<ITreeStorage> m_storage;
    std::vector<OutputTuple> m_outputs;
    ProgressCallback m_progress_cb;
};

} // namespace curvetree

#endif // WATTX_PRIVACY_CURVETREE_H
