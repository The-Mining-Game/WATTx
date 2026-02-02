# WATTx Core

WATTx is a hybrid Proof-of-Work/Proof-of-Stake blockchain featuring multi-algorithm mining, smart contracts, and privacy-focused features. Built on QTUM's foundation with significant enhancements for mining flexibility, cross-chain interoperability, and user privacy.

## Key Features

### Multi-Algorithm Mining (X25X)
Mine using any of 7 supported algorithms:
| Algorithm | Target Hardware |
|-----------|-----------------|
| SHA256d | Bitcoin ASICs |
| Scrypt | Litecoin miners |
| RandomX | CPU miners (Monero) |
| Ethash | Ethereum Classic miners |
| Equihash | Zcash miners |
| kHeavyHash | Kaspa miners |
| X11 | Dash miners |

### Privacy Features
- **Cross-Chain Privacy Pools** - Anonymous cross-chain USDT transfers with Monero-style privacy
- **Shielded Commitments** - Merkle tree commitments on WATTx EVM
- **Stealth Addresses** - One-time addresses for unlinkable transactions
- **P2P Encrypted Messaging** - End-to-end encrypted chat between wallet instances
- **FCMP Privacy Transactions** - Full-chain membership proofs (activates block 210,000)

### Smart Contracts
- Full EVM compatibility (Solidity)
- Built-in contract compiler
- Contract verification via block explorer

### Hybrid Consensus
- **PoW Mining** - Multi-algorithm support via X25X
- **PoS Staking** - Dynamic stake maturity that halves with block reward halvings
- **AuxPoW Merged Mining** - Mine WATTx while mining Monero, BTC, LTC, KAS, ALT, ETC (any coin with suppoprted algorithm)

### Cross-Chain Bridge
- LayerZero-based OFT token bridge
- Bridge between WATTx, Ethereum, BSC, Polygon

## Network Parameters

| Parameter | Mainnet | Testnet | Regtest |
|-----------|---------|---------|---------|
| Block Time | 2 minutes | 2 minutes | 2 minutes |
| Block Reward | 5 WTX (PoW) + 5 WTX (PoS) | Same | Same |
| Halving Interval | 1,051,200 blocks (~4 years) | Same | 200 blocks |
| Base Stake Maturity | 500 blocks | 500 blocks | 20 blocks |
| Stake Maturity Floor | 10 blocks | 10 blocks | 2 blocks |
| X25X Activation | Block 210,000 | Block 1,000 | Block 1 |
| RandomX Activation | Block 210,000 | Block 1,000 | Block 1 |
| FCMP Activation | Block 210,000 | Block 1,000 | Block 1 |
| P2P Port | 18888 | 13888 | 18444 |
| RPC Port | 18889 | 13889 | 18443 |

## Quick Start

### Running a Node

```bash
# Start daemon
./wattxd -daemon

# Create wallet
./wattx-cli createwallet "mywallet"

# Get new address
./wattx-cli getnewaddress

# Check sync status
./wattx-cli getblockchaininfo
```

### Mining (GUI)

1. Open `wattx-qt`
2. Go to **Stake > Mining**
3. Select mining mode (Solo/Pool)
4. Choose RandomX mode (Light 256MB / Full 2GB)
5. Set number of CPU threads
6. Click **Start Miner**

### Mining (CLI)

```bash
# Generate blocks to address (regtest)
./wattx-cli generatetoaddress 100 "your_address"

# Check mining info
./wattx-cli getmininginfo

# Get network hashrate
./wattx-cli getnetworkhashps
```

### Staking

```bash
# Check staking status
./wattx-cli getstakinginfo

# Enable staking (wallet must be unlocked)
./wattx-cli walletpassphrase "your_passphrase" 999999999 true
```

### Smart Contracts

```bash
# Deploy contract (via GUI or CLI)
./wattx-cli createcontract "bytecode" 1000000 0.00000040

# Call contract
./wattx-cli callcontract "contract_address" "data"

# Send to contract
./wattx-cli sendtocontract "contract_address" "data" 0 1000000
```

### P2P Encrypted Messaging

1. Open `wattx-qt`
2. Go to **Messaging**
3. Create a chat identity
4. Add contacts by their public key
5. Send encrypted messages directly between wallets

## Building from Source

### Dependencies (Ubuntu/Debian)

```bash
sudo apt-get install build-essential libtool autotools-dev automake pkg-config \
    bsdmainutils python3 libevent-dev libboost-dev libboost-system-dev \
    libboost-filesystem-dev libboost-test-dev libsqlite3-dev libminiupnpc-dev \
    libnatpmp-dev libzmq3-dev systemtap-sdt-dev qt5-default libqt5gui5 \
    libqt5core5a libqt5dbus5 qttools5-dev qttools5-dev-tools libqrencode-dev
```

### Build

```bash
mkdir build && cd build
cmake -DBUILD_GUI=ON ..
make -j$(nproc)
```

### Cross-Compile for Windows

```bash
# Build depends
cd depends
make HOST=x86_64-w64-mingw32 -j$(nproc)

# Build WATTx
cd ../build-win64
cmake -DCMAKE_TOOLCHAIN_FILE=../depends/x86_64-w64-mingw32/toolchain.cmake ..
make -j$(nproc)
```

### Binaries

After building, binaries are in `build/bin/`:
- `wattxd` - Full node daemon
- `wattx-cli` - Command-line interface
- `wattx-qt` - Qt GUI wallet
- `wattx-tx` - Transaction utility
- `wattx-wallet` - Wallet utility

## Downloads

Pre-built binaries available at:
- [GitHub Releases](https://github.com/The-Mining-Game/WATTx/releases)

### Windows Requirements
The Windows release includes all required DLLs:
- libgcc_s_seh-1.dll
- librandomx.dll
- libssp-0.dll
- libstdc++-6.dll
- libwinpthread-1.dll
- zlib1.dll

## Development Progress

### Completed Features
- X25X Multi-Algorithm Mining Framework
- Dynamic Stake Maturity System
- RandomX CPU Mining Integration
- AuxPoW Merged Mining (Monero)
- Cross-Chain Privacy Pools
- P2P Encrypted Messaging
- LayerZero Bridge Contracts
- Block Explorer with Contract Verification
- Compact Qt Wallet UI

### In Progress
- EIP-7594 PeerDAS (80% complete)
- Trust Tier System
- ZK Circuits for Privacy Pools

## Related Projects

| Project | Description |
|---------|-------------|
| [WATTx Explorer](https://github.com/The-Mining-Game/wattx-explorer) | Block explorer with contract verification |
| [WATTx Bridge](https://github.com/The-Mining-Game/wattx-bridge) | LayerZero cross-chain bridge |
| [Mining Game](https://github.com/The-Mining-Game/mining-game) | NFT Mining Rig Builder dApp |

## License

WATTx Core is released under the MIT license. See [COPYING](COPYING) for more information.

Based on QTUM Core, which is based on Bitcoin Core.
