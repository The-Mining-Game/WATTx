# CLAUDE.md - Session Notes for WATTx Development

## Project Overview
- **Project:** WATTx Core - Hybrid PoW/PoS blockchain (QTUM-based)
- **Current Version:** 0.1.7-dev
- **Build System:** CMake 3.22+, C++20, vcpkg dependencies

## Current Work: Altcoinchain FUSAKA Upgrade

### Location
- **Altcoinchain codebase:** `/home/nuts/Documents/go-altcoinchain_FUSAKA/`
- **Chain ID:** 2330
- **Genesis file:** `altcoinchain-genesis.json`

### FUSAKA EIPs Status (Target: December 2025)

| EIP | Description | Status |
|-----|-------------|--------|
| EIP-7825 | Transaction Gas Upper Limit (16,777,216) | COMPLETE |
| EIP-7935 | Default Block Gas Limit (150,000,000) | COMPLETE |
| EIP-7594 | PeerDAS (Peer Data Availability Sampling) | 80% COMPLETE |

### EIP-7594 (PeerDAS) Implementation Status
- [x] Core data structures (DataSample, SampleCommitment)
- [x] Merkle proof generation and verification
- [x] Erasure coding (XOR-based Reed-Solomon compatible)
- [x] P2P protocol messages (SampleRequest, SampleResponse, SampleAnnounce, SamplePush)
- [x] Sample caching with TTL
- [x] Block validation integration hooks (DAValidator)
- [ ] Network layer integration (eth/protocols/peerdas)
- [ ] Block header extension for DA commitments

### Key Files (go-altcoinchain_FUSAKA)
- `consensus/peerdas/peerdas.go` - Core PeerDAS implementation
- `consensus/peerdas/erasure.go` - Reed-Solomon erasure coding
- `consensus/peerdas/protocol.go` - P2P message types and handlers
- `consensus/peerdas/validator.go` - Block validation integration
- `consensus/peerdas/peerdas_test.go` - Unit tests
- `params/protocol_params.go` - Gas limit constants
- `core/tx_pool.go` - Transaction validation
- `core/block_validator.go` - Block validation
- `miner/worker.go` - Mining/gas limit logic

## WATTx 0.1.7-dev Features (Completed)

- **X25X Multi-Algorithm Mining** - SHA256d, Scrypt, Ethash, RandomX, Equihash, X11, kHeavyHash
  - Mainnet activation: Block 100,000
  - Key files: `src/crypto/x25x/`, `src/node/x25x_miner.*`

- **Dynamic Stake Maturity** - Halves with block reward halvings
  - Key file: `src/consensus/params.h`

## Related Projects

| Project | Path | Purpose |
|---------|------|---------|
| WATTx Explorer | `/home/nuts/Documents/WATTx/wattx-explorer/` | Block explorer (React + Node.js) |
| WATTx Bridge | `/home/nuts/Documents/WATTx/wattx-bridge/` | LayerZero cross-chain bridge |
| Altcoinchain GUI | `/home/nuts/Documents/Altcoinchain GUI staking node wallet/` | Validator wallet |

## Build Commands

```bash
# WATTx
cd /home/nuts/Documents/WATTx/WATTx-0.1.7-dev
mkdir build && cd build
cmake .. && make -j$(nproc)

# Altcoinchain
cd /home/nuts/Documents/go-altcoinchain_FUSAKA
make geth
```

## Recent Work (2026-01-25)

**AuxPoW Merged Mining Implementation** - COMPLETE
- **Problem:** ValidateShare only incremented counters, didn't construct/submit AuxPoW blocks
- **Solution:** Implemented full AuxPoW block construction and submission
- **Files modified:**
  - `src/stratum/merged_stratum.h` - Added `MoneroCoinbaseData` struct, extended `MergedJob`
  - `src/stratum/merged_stratum.cpp` - Added Monero blob parsing, AuxPoW construction, block submission
  - `src/interfaces/mining.h` - Added `submitAuxPowSolution()` method to `BlockTemplate`
  - `src/node/interfaces.cpp` - Implemented `submitAuxPowSolution()` for AuxPoW block submission
- **Key functions added:**
  - `ParseMoneroBlockBlob()` - Extracts coinbase data from Monero block template
  - `BuildMoneroHeader()` - Constructs `CMoneroBlockHeader` from parsed data
  - `GetMoneroBlockTemplateExtended()` - Fetches full Monero template with coinbase
  - `ConstructAndSubmitAuxPowBlock()` - Creates `CAuxPow` proof and submits WATTx block
- **Status:** Compiles, ready for testing

**Genesis Hash Backward Compatibility Fix** - COMPLETE (commit 40e26db5d)
- **Problem:** Node fails to start due to genesis hash mismatch after geth upgrade
- **Genesis Hash:** `0x04e12dc501c4f51306351345e0587ec8bee495a9780ce9234401a0aa512e299b` (from explorer)
- **Files modified:**
  - `params/config.go` - Added `AltcoinchainGenesisHash` constant
  - `core/genesis.go` - Added `isValidAltcoinchainGenesisHash()` function
- **Status:** Committed and tested

**Mining Block Number Bug Fix** - COMPLETE (commit e10680a4a)
- **Problem:** Miner created block 2 directly after genesis, skipping block 1
- **Root cause:** `big.Int` pointer mutation - same pointer used for header.Number and GasLimit calc
- **File modified:** `miner/worker.go` - Created new `big.Int` for nextBlockNum
- **Status:** Committed and tested - local 2-node sync verified

### ⚠️ BLOCKED: Mainnet Sync Test Required Before Push

**Commits ready but NOT pushed:**
- `40e26db5d` - Genesis hash backward compatibility
- `e10680a4a` - Mining block number bug fix

**Requirement:** User explicitly requested mainnet sync test before pushing

**Problem:** All known network nodes are unreachable:
- `154.12.237.243:30303/30304` - No route to host
- `99.248.100.186:30303` - Connection refused
- `62.72.177.111:30303` - Timeout
- `69.171.199.247:30303` - Timeout

**To resume:** Get fresh enode addresses from Altcoinchain network operator

**Genesis verified:** Hash `04e12d..2e299b` matches block explorer ✅

## Recent Work (2026-01-27)

**Cross-Chain Privacy Pool Contracts** - COMPLETE
- **Purpose:** Enable anonymous cross-chain USDT transfers with Monero-style privacy
- **Design:** Liquidity pools on external chains, shielded commitments on WATTx EVM
- **Location:** `contracts/privacy/`

**Contracts Created:**
| File | Description |
|------|-------------|
| `PrivacyPool.sol` | Liquidity pool for each chain (ETH, BSC, Polygon) |
| `PrivacyController.sol` | Central controller on WATTx EVM |
| `MerkleTree.sol` | Incremental Merkle tree for commitments (20 levels) |
| `IVerifier.sol` | ZK proof verifier interface |
| `MockVerifier.sol` | Testing verifier (returns true) |
| `StealthAddress.sol` | Stealth address utilities |
| `testing/MockUSDT.sol` | Mock USDT for testing |
| `testing/MerkleTreeTest.sol` | Test helper for MerkleTree |

**Infrastructure:**
- `hardhat.config.js` - Multi-network deployment config
- `package.json` - Dependencies (LayerZero v2, OpenZeppelin)
- `scripts/deploy.js` - Deployment scripts
- `test/PrivacyPool.test.js` - Basic tests
- `PRIVACY_POOLS.md` - Full documentation

**Privacy Flow:**
1. User deposits USDT on any chain (fixed denominations: 100, 1k, 10k, 100k)
2. USDT locked in chain's PrivacyPool
3. LayerZero message to WATTx creates shielded commitment
4. User generates ZK proof off-chain
5. User withdraws to ANY chain with proof (no link to deposit)

**Dependencies:**
- LayerZero OApp v2 for cross-chain messaging
- OpenZeppelin contracts for security
- ZK circuits needed for production (circom/snarkjs)

## Recent Work (2026-01-29)

**Mining Game dApp Frontend** - COMPLETE
- **Location:** Saved to `/home/nuts/Documents/mining game/`
- **Purpose:** NFT Mining Rig Builder for Polygon/Altcoinchain

**Frontend Changes:**
- Fixed NFT specs parsing (hashrate, WATT consumption were incorrectly parsed)
- Updated component specs to balanced values:
  - Gaming PC: 100 H/s, 0.5 WATT/hr
  - XL1 CPU: 80 H/s, 0.3 WATT/hr
  - TX120 GPU: 60 H/s, 0.25 WATT/hr
  - GP50 GPU: 150 H/s, 0.4 WATT/hr
- Simplified stats panel (removed stake weight, luck boost)
- Removed Genesis Badge from rig builder (staking-only item)
- Added "Coming Soon" placeholder for 3D builder
- Fixed npm version conflicts (@react-three, @google/model-viewer, three.js)

**Files Modified:**
- `frontend/src/utils/constants.js` - Fixed specs strings
- `frontend/src/utils/specsParser.js` - WATT scaling factor
- `frontend/src/components/StatsPanel.jsx` - Simplified stats
- `frontend/src/components/RigBuilder.jsx` - Removed badge slot
- `frontend/src/App.jsx` - 3D builder coming soon

**Deployed Contracts (existing):**
| Network | Contract | Address |
|---------|----------|---------|
| Polygon | Mining Game NFT | `0x970a8b10147e3459d3cbf56329b76ac18d329728` |
| Polygon | WATT Token | `0xE960d5076cd3169C343Ee287A2c3380A222e5839` |
| Polygon | NFT Staking | `0xcbfcA68D10B2ec60a0FB2Bc58F7F0Bfd32CD5275` |
| Altcoinchain | Mining Game NFT | `0xf9670e5D46834561813CA79854B3d7147BBbFfb2` |
| Altcoinchain | WATT Token | `0x6645143e49B3a15d8F205658903a55E520444698` |
| Altcoinchain | NFT Staking | `0xe463045318393095F11ed39f1a98332aBCc1A7b1` |

## Recent Work (2026-01-29 continued)

**EIP-7594 PeerDAS Implementation** - 80% COMPLETE

Implemented core PeerDAS (Peer Data Availability Sampling) for FUSAKA upgrade:

**What is PeerDAS?**
PeerDAS allows nodes to verify block data availability by sampling instead of downloading 100% of data. Uses erasure coding so data can be reconstructed from any 50%+ of samples.

**Files Created:**
| File | Description |
|------|-------------|
| `consensus/peerdas/peerdas.go` | Core types, sample verification, Merkle proofs |
| `consensus/peerdas/erasure.go` | XOR-based erasure coding (4 data + 2 parity shards) |
| `consensus/peerdas/protocol.go` | P2P messages (Request, Response, Announce, Push) |
| `consensus/peerdas/validator.go` | Block validation hooks, DA commitments |
| `consensus/peerdas/peerdas_test.go` | Unit tests (all passing) |

**Key Types:**
- `DataSample` - Individual data shard with Merkle proof
- `SampleCommitment` - Merkle root commitment for all samples
- `ErasureCoding` - Encode/decode with redundancy
- `DAValidator` - Block DA verification
- `Protocol` - P2P sample requests/responses
- `SampleCache` - TTL cache for samples

**Remaining Work:**
- Integrate protocol into `eth/protocols/` directory
- Add DA commitment to block header structure
- Wire up P2P handlers in devp2p layer

## Recent Work (2026-05-26)

**Full WATTx Node + FCMP++ Build** - COMPLETE ✅

Built the complete WATTx 0.1.7-dev node including the FCMP++ privacy subsystem.

**Build Command:**
```bash
cd /home/nuts/Documents/WATTx/WATTx-0.1.7-dev/build
make -j$(nproc)
# Run with:
LD_LIBRARY_PATH=/home/nuts/Documents/WATTx/WATTx-0.1.7-dev/build/bin ./bin/wattxd
```

**Test Results (all pass):**
| Binary | Tests | Result |
|--------|-------|--------|
| `test_ed25519` | Ed25519 scalar/point/Pedersen ops | ✅ All pass |
| `test_curvetree` | Curve tree CRUD, LevelDB persistence | ✅ All pass |
| `test_fcmp` | Rust FFI wrapper (init, scalars, points, commitments) | ✅ 14/14 |
| `test_wattx --run_test=privacy*` | Ring sigs, stealth addrs, RingCT, FCMP tx types | ✅ 25/25 |

**Reference Rust FCMP++ tests (fcmp-research/fcmp-plus-plus):**
```bash
cd /home/nuts/Documents/WATTx/fcmp-research/fcmp-plus-plus
cargo test -p monero-fcmp-plus-plus --lib -- tests::test
# → 1 passed (full prove+verify, ~60s)
```

**Key Binaries Built:**
- `build/bin/wattxd` - Full daemon with FCMP++ compiled in (`HAVE_FCMP` defined)
- `build/bin/wattx-cli` - RPC client
- `build/bin/test_fcmp` - FCMP FFI test suite
- `build/bin/test_curvetree` - Curve tree test suite

**FCMP Architecture Note:**
- The Rust FFI (`src/privacy/fcmp/rust/`) is a scaffold using `curve25519-dalek` for now
- The reference Rust FCMP++ library (`fcmp-research/fcmp-plus-plus`) uses Ed25519+Selene+Helios curve cycle
- Full wiring (uncomment `full-chain-membership-proofs` in `rust/Cargo.toml`) is the next step for production-grade proofs
- LevelDB curvetree + key image DB in `.wattx/fcmp/` are operational

## Recent Work (2026-05-26 continued)

**FCMP++ Full Wiring — COMPLETE ✅**
- Replaced Schnorr-sigma scaffold with real `full-chain-membership-proofs` crate
- **Cargo.toml**: Added 7 path deps (`monero-fcmp-plus-plus`, `dalek-ff-group`, `ciphersuite`, `ec-divisors`, `multiexp`, `generalized-bulletproofs`, `monero-generators`) + `[patch.crates-io]` for `lazy_static` and `crypto-bigint`
- **Three new FFI functions added to `src/privacy/fcmp/rust/src/lib.rs`:**
  - `fcmp_prove_full` — full curve-tree membership proof (Generalized Bulletproofs + SAL)
  - `fcmp_verify_full` — verifies a `fcmp_prove_full` proof via batch verifiers
  - `fcmp_compute_leaf_root` — computes the Selene (C1) root from a leaf branch
- **`fcmp_proof_size`** updated to use `FcmpPlusPlus::proof_size` (exact real size, ~5KB for 1 input/10 layers)
- **`fcmp_version`** bumped to `"0.2.0"`
- **All 14 C++ FFI tests pass** — `test_fcmp` suite green
- **All 7 Rust unit tests pass**
- **Architecture**: 1-layer proof (leaves → Selene root). Multi-layer support requires adding `curve_1_layers`/`curve_2_layers` to Path.

**Declared in `fcmp_ffi.h`:** `fcmp_prove_full`, `fcmp_verify_full`, `fcmp_compute_leaf_root`

## Pending Work

1. **EIP-7594 PeerDAS Network Integration** - Wire protocol into devp2p (Altcoinchain)
2. **LayerZero Bridge** - Contracts compiled, awaiting Sepolia deployment
3. **Trust Tier System** - Planned, not implemented
4. **AuxPoW Testing** - Integration testing with Monero testnet needed
5. **FCMP++ Multi-Layer Support** - Extend `fcmp_prove_full`/`fcmp_verify_full` to handle `curve_1_layers` and `curve_2_layers` for trees deeper than 1 layer
6. **ZK Circuits** - Groth16 circuits for withdraw proofs (circom)
7. **Altcoinchain Mainnet Sync** - Blocked on getting fresh enode addresses

---
*Last updated: 2026-01-29*
