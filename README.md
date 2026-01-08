What is WATTx?
--------------

WATTx is a Proof-of-Stake blockchain built on QTUM's foundation, featuring a unique tiered trust system for validators. WATTx serves as the backbone for the WATTxChange decentralized exchange platform.

Key Features
------------

1. **Tiered Trust System** - Validators earn rewards based on their uptime reliability:
   - Bronze (95%+ uptime): 1.0x rewards
   - Silver (97%+ uptime): 1.25x rewards
   - Gold (99%+ uptime): 1.5x rewards
   - Platinum (99.9%+ uptime): 2.0x rewards

2. **Validator Pools** - Stake 100,000 WATTx to become a validator with configurable pool fees

3. **Delegation System** - Delegate stake to validators and earn proportional rewards

4. **EVM Compatibility** - Full Ethereum Virtual Machine support for smart contracts

5. **Fast Block Times** - 1-second block generation for rapid transaction confirmations

6. **Bitcoin-like Tokenomics** - ~21 million total supply with halving schedule

Network Parameters
------------------

| Parameter | Value |
|-----------|-------|
| Block Time | 1 second |
| Block Reward | ~0.083 WATTx (~50 WATTx/10 min) |
| Halving Interval | 126,000,000 blocks (~4 years) |
| Total Supply | ~21 million WATTx |
| Min Validator Stake | 100,000 WATTx |
| Min Delegation | 1,000 WATTx |
| Mainnet Port | 18888 |
| Testnet Port | 13888 |

Quick Start
-----------

### Running a Node

```bash
# Start daemon
./wattxd -daemon

# Create wallet
./wattx-cli createwallet "mywallet"

# Get new address
./wattx-cli getnewaddress
```

### Becoming a Validator

```bash
# Register as validator (requires 100k WATTx balance)
./wattx-cli registervalidator 500 "MyValidator"
# 500 = 5% pool fee

# Check validator status
./wattx-cli getmyvalidator

# Update pool fee
./wattx-cli setvalidatorpoolfee 300  # 3%
```

### Delegating Stake

```bash
# List validators
./wattx-cli listvalidators

# Delegate to a validator
./wattx-cli delegatestake "validatorId" 10000

# Check your delegations
./wattx-cli getmydelegations

# Claim rewards
./wattx-cli claimrewards

# Undelegate
./wattx-cli undelegatestake "validatorId" 5000
```

### Trust Tier Information

```bash
# Get trust tier thresholds and multipliers
./wattx-cli gettrusttierinfo

# Get network validator statistics
./wattx-cli getvalidatorstats
```

Building from Source
--------------------

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
cmake ..
make -j$(nproc)
```

### Binaries

After building, binaries are located in `build/bin/`:
- `wattxd` - Full node daemon
- `wattx-cli` - Command-line interface
- `wattx-qt` - Qt GUI wallet
- `wattx-tx` - Transaction utility
- `wattx-wallet` - Wallet utility

RPC Commands
------------

### Validator Commands

| Command | Description |
|---------|-------------|
| `registervalidator [fee] [name]` | Register as validator |
| `setvalidatorpoolfee <fee>` | Update pool fee rate |
| `getmyvalidator` | Get your validator info |
| `listvalidators [maxFee] [activeOnly]` | List validators |
| `getvalidator <id>` | Get specific validator |
| `getvalidatorstats` | Network statistics |

### Delegation Commands

| Command | Description |
|---------|-------------|
| `delegatestake <validatorId> <amount>` | Delegate stake |
| `undelegatestake <validatorId> [amount]` | Undelegate |
| `getmydelegations` | List your delegations |
| `listdelegations <keyId> [type]` | List delegations |
| `claimrewards [validatorId]` | Claim rewards |
| `getpendingrewards <delegatorId>` | Check pending rewards |

### Trust Commands

| Command | Description |
|---------|-------------|
| `gettrusttierinfo` | Tier thresholds and multipliers |

License
-------

WATTx Core is released under the MIT license. See [COPYING](COPYING) for more information.

Based on QTUM Core which is based on Bitcoin Core.
