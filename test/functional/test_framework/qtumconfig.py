COINBASE_MATURITY = 500
INITIAL_BLOCK_REWARD = 20000
INITIAL_BLOCK_REWARD_POS = 4

# WATTx block subsidy (src/kernel/chainparams.cpp regtest + validation.cpp
# GetBlockSubsidy). Qtum's 20000-per-block bootstrap does not apply here:
# regtest sets nLastBigReward = 0 ("fair launch"), so only genesis gets it and
# every other block pays the base reward with halvings. Paying Qtum's amount
# makes ConnectBlock reject the block with "block-reward-invalid".
WATTX_BASE_BLOCK_REWARD = 5              # nBaseBlockReward = 500000000 sat
WATTX_LAST_BIG_REWARD = 0                # regtest: fair launch
WATTX_REDUCE_BLOCKTIME_HEIGHT = 0        # regtest
WATTX_BLOCKTIME_DOWNSCALE_FACTOR = 4     # regtest
WATTX_SUBSIDY_HALVING_INTERVAL = WATTX_BLOCKTIME_DOWNSCALE_FACTOR * 50  # 200
WATTX_MAX_HALVINGS = 7                   # reward is forced to zero after this


def wattx_block_subsidy(height):
    """Mirror of GetBlockSubsidy() for regtest, in satoshis.

    Verified against the node: getblocktemplate at height 353 reports
    coinbasevalue 250000000, and this returns the same.
    """
    if height <= WATTX_LAST_BIG_REWARD:
        return 20000 * 100000000

    factor = (WATTX_BLOCKTIME_DOWNSCALE_FACTOR
              if height >= WATTX_REDUCE_BLOCKTIME_HEIGHT else 1)
    block_count = height - WATTX_LAST_BIG_REWARD
    before_downscale = 0 if factor == 1 else (
        WATTX_REDUCE_BLOCKTIME_HEIGHT - WATTX_LAST_BIG_REWARD - 1)
    weight = block_count - before_downscale + before_downscale * factor

    halvings = (weight - 1) // WATTX_SUBSIDY_HALVING_INTERVAL
    if halvings >= WATTX_MAX_HALVINGS:
        return 0
    return (WATTX_BASE_BLOCK_REWARD * 100000000) >> halvings
INITIAL_HASH_UTXO_ROOT = 0x21b463e3b52f6201c0ad6c991be0485b6ef8c092e64583ffa655cc1b171fe856
#INITIAL_HASH_STATE_ROOT = 0x9514771014c9ae803d8cea2731b2063e83de44802b40dce2d06acd02d0ff65e9
INITIAL_HASH_STATE_ROOT = 0xe347448b257b1ec40ec2ace0a909751c1b8a07eabd4d13bf6c2f3c4c854f493b
MAX_BLOCK_BASE_SIZE = 2000000
QTUM_MIN_GAS_PRICE = 40
QTUM_MIN_GAS_PRICE_STR = "0.00000040"
NUM_DEFAULT_DGP_CONTRACTS = 6
MPOS_PARTICIPANTS = 10
LAST_POW_BLOCK = 5000
BLOCKS_BEFORE_PROPOSAL_EXPIRATION = 216
DELEGATION_CONTRACT_ADDRESS = "0000000000000000000000000000000000000086"
BLOCKTIME = 128
TIMESTAMP_MASK = 15
FACTOR_REDUCED_BLOCK_TIME = 1
MAX_BLOCK_SIGOPS = 20000

ENABLE_REDUCED_BLOCK_TIME = True
 
if ENABLE_REDUCED_BLOCK_TIME:
	FACTOR_REDUCED_BLOCK_TIME = 4
	TIMESTAMP_MASK = 3
	INITIAL_BLOCK_REWARD_POS = 4 / FACTOR_REDUCED_BLOCK_TIME
	MAX_BLOCK_BASE_SIZE //= FACTOR_REDUCED_BLOCK_TIME
	COINBASE_MATURITY = 2000
	BLOCKTIME //= FACTOR_REDUCED_BLOCK_TIME
	MAX_BLOCK_SIGOPS //= FACTOR_REDUCED_BLOCK_TIME

MAX_BLOCK_SIGOPS_WEIGHT = MAX_BLOCK_SIGOPS * 4