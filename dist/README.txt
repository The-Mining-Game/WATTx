================================================================================
                         WATTx Node Distribution
================================================================================

WATTx is a Proof-of-Stake blockchain with 1-second block times and tiered
trust scoring for validators.

BINARIES INCLUDED:
------------------
  wattx-qt     - GUI Wallet (recommended for most users)
  wattxd       - Daemon (headless server)
  wattx-cli    - Command-line interface
  wattx-tx     - Transaction utility

QUICK START (GUI):
------------------
1. Run: ./wattx-qt
2. Wait for blockchain to sync
3. Create or import a wallet
4. Receive WATTx to start staking

QUICK START (Server/Daemon):
----------------------------
1. Create config directory:
   Linux:   mkdir -p ~/.wattx
   macOS:   mkdir -p ~/Library/Application\ Support/WATTx
   Windows: Create %APPDATA%\WATTx

2. Copy wattx.conf.example to the config directory and rename to wattx.conf

3. Start daemon:
   ./wattxd -daemon

4. Check status:
   ./wattx-cli getblockchaininfo
   ./wattx-cli getstakinginfo

CONNECTING TO THE NETWORK:
--------------------------
Add seed nodes to your wattx.conf:
  addnode=<SEED_NODE_IP>:18888

Or connect manually:
  ./wattx-cli addnode <IP>:18888 add

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
  Consensus:         Proof-of-Stake (after block 1000)

SUPPORT:
--------
For issues, please check the project documentation or contact the developers.

================================================================================
