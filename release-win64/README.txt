================================================================================
                    WATTx 0.1.7 Node Distribution
================================================================================

WATTx is a hybrid Proof-of-Work / Proof-of-Stake blockchain with 1-second
block times, tiered trust scoring for validators, and EVM compatibility.

BINARIES INCLUDED:
------------------
  wattx-qt       - GUI Wallet (recommended for most users)
  wattxd         - Daemon (headless server)
  wattx-cli      - Command-line interface
  wattx-tx       - Transaction utility
  wattx-util     - General utility tool
  wattx-wallet   - Wallet management tool
  janus          - EVM Bridge (for MetaMask/Rabby wallet integration)
  librandomx.so  - RandomX proof-of-work library (Linux)
  librandomx.dll - RandomX proof-of-work library (Windows)

QUICK START (GUI):
------------------
  Linux:   ./launch-wattx-qt.sh
  Windows: Double-click launch-wattx-qt.bat

  1. Wait for blockchain to sync
  2. Create or import a wallet
  3. Receive WATTx to start staking

QUICK START (Server/Daemon):
----------------------------
  Linux:   ./launch-wattxd.sh -daemon
  Windows: launch-wattxd.bat -daemon

  Check status:
    wattx-cli getblockchaininfo
    wattx-cli getstakinginfo

CONFIGURATION:
--------------
  1. Create config directory:
     Linux:   mkdir -p ~/.wattx
     Windows: Create %APPDATA%\WATTx

  2. Copy wattx.conf.example to the config directory and rename to wattx.conf

  3. Edit wattx.conf with your RPC credentials:
     rpcuser=your_username
     rpcpassword=your_password

CONNECTING TO THE NETWORK:
--------------------------
  Add seed nodes to your wattx.conf:
    addnode=<SEED_NODE_IP>:18888

  Or connect manually:
    wattx-cli addnode <IP>:18888 add

================================================================================
                      NEW FEATURES IN 0.1.7
================================================================================

METAMASK / RABBY WALLET INTEGRATION (Janus EVM Bridge):
--------------------------------------------------------
  WATTx includes Janus, an EVM compatibility bridge that lets you use
  MetaMask, Rabby, and other Ethereum wallets with WATTx.

  Setup:
  1. Start the WATTx daemon with RPC enabled
  2. Launch Janus:
     Linux:   ./launch-janus.sh
     Windows: launch-janus.bat
  3. Add WATTx network to MetaMask/Rabby:
     - Network Name: WATTx
     - RPC URL: http://localhost:23889
     - Chain ID: 2335 (mainnet) / 8889 (testnet) / 8890 (regtest)
     - Currency Symbol: WTX
  4. Export your EVM key:
     wattx-cli exportevmkey "wallet_name" "address"

  Note: Edit launch-janus script to set your RPC username/password.

STEALTH ADDRESSES (Privacy):
-----------------------------
  Generate a stealth address:
    wattx-cli generatestealthaddress "wallet_name"

  Send to a stealth address:
    wattx-cli sendstealthtx "wallet_name" "stealth_address" amount

  List stealth addresses:
    wattx-cli liststealthaddresses "wallet_name"

ENCRYPTED MESSAGING:
--------------------
  Send an encrypted message:
    wattx-cli sendmessage "wallet_name" "recipient_address" "message"

  Read messages:
    wattx-cli getmessages "wallet_name"

EVM KEY EXPORT:
---------------
  Export your Keccak-256 derived EVM private key for use in MetaMask:
    wattx-cli exportevmkey "wallet_name" "address"

  This derives an Ethereum-compatible private key from your WATTx key
  using secp256k1 uncompressed public key + Keccak-256 hashing.

FCMP (Full Chain Membership Proofs):
------------------------------------
  Privacy-preserving proofs that activate at block 500 on regtest.
  Miner outputs include cryptographic commitments (O, I, C, R points).

================================================================================
                      REFERENCE
================================================================================

STAKING REQUIREMENTS:
---------------------
  - Minimum stake: 100,000 WATTx (for full validator status)
  - Coins must be mature (600+ confirmations)
  - Wallet must be unlocked for staking

PORTS:
------
  Mainnet:  18888 (P2P), 18890 (RPC)
  Testnet:  18889 (P2P), 18891 (RPC)

BLOCKCHAIN PARAMETERS:
----------------------
  Block Time:        1 second
  Block Reward:      0.08333333 WATTx (~50 WATTx per 10 minutes)
  Halving Interval:  126,000,000 blocks (~4 years)
  Total Supply:      ~21 million WATTx
  Consensus:         Hybrid PoW/PoS (PoS after block 1000)

SUPPORT:
--------
  For issues, please check the project documentation or contact the developers.

================================================================================
