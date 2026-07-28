#!/usr/bin/env python3
# Copyright (c) 2015-2016 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *
from test_framework.script import *
from test_framework.p2p import *
from test_framework.blocktools import *
from test_framework.address import *
from test_framework.key import ECKey
from test_framework.qtumconfig import TIMESTAMP_MASK, WATTX_POS_LIMIT_NBITS, WATTX_POS_TIMESTAMP_MASK, wattx_block_subsidy
import io
import struct

class QtumPOSTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [[]]
        self.tip = None

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def bootstrap_p2p(self):
        """Add a P2P connection to the node.

        Helper to connect and wait for version handshake."""
        self.nodes[0].add_p2p_connection(P2PDataStore())
        # We need to wait for the initial getheaders from the peer before we
        # start populating our blockstore. If we don't, then we may run ahead
        # to the next subtest before we receive the getheaders. We'd then send
        # an INV for the next block and receive two getheaders - one for the
        # IBD and one for the INV. We'd respond to both and could get
        # unexpectedly disconnected if the DoS score for that error is 50.
        self.nodes[0].p2ps[0].wait_for_getheaders(timeout=5)

    def reconnect_p2p(self):
        """Tear down and bootstrap the P2P connection to the node.

        The node gets disconnected several times in this test. This helper
        method reconnects the p2p and restarts the network thread."""
        self.nodes[0].disconnect_p2ps()
        self.bootstrap_p2p()


    def sync_all_blocks(self, blocks, success=True, reject_code=None, reject_reason=None, force_send=False, reconnect=False, timeout=5):
        """Sends blocks to test node. Syncs and verifies that tip has advanced to most recent block.

        Call with success = False if the tip shouldn't advance to the most recent block."""
        self.nodes[0].p2ps[0].send_blocks_and_test(blocks, self.nodes[0], success=success, reject_reason=reject_reason, force_send=force_send, timeout=timeout, expect_disconnect=reconnect)

        if reconnect:
            self.reconnect_p2p()

    def _remove_from_staking_prevouts(self, block):
        for j in range(len(self.staking_prevouts)):
            prevout = self.staking_prevouts[j]
            if prevout[0].serialize() == block.prevoutStake.serialize():
                self.staking_prevouts.pop(j)
                break

    def run_test(self):
        self.node = self.nodes[0]
        privkey_bytes = hash256(struct.pack('<I', 0))
        privkey = byte_to_base58(privkey_bytes, 239)
        self.node.importprivkey(privkey)
        # Derive the address from the key just imported rather than hardcoding
        # it. The literal here was a Qtum address, which WATTx rejects outright
        # (different base58 prefix), and a hardcoded address silently rots
        # again the next time a prefix changes.
        key = ECKey()
        # Uncompressed: byte_to_base58() appends no 0x01 compression flag, so
        # the node imports an uncompressed key. Deriving the address as
        # compressed yields a different pubkey hash, the generated coinbases pay
        # an address the wallet does not own, and the balance stays at zero.
        key.set(privkey_bytes, False)
        self.staking_address = key_to_p2pkh(key.get_pubkey().get_bytes())
        self.bootstrap_p2p()
        # returns a test case that asserts that the current tip was accepted
        # First generate some blocks so we have some spendable coins
        block_hashes = self.generatetoaddress(self.node, 100, self.staking_address)

        for i in range(COINBASE_MATURITY):
            self.tip = create_block(int(self.node.getbestblockhash(), 16), create_coinbase(self.node.getblockcount()+1), int(time.time()))
            self.tip.solve()
            self.sync_all_blocks([self.tip], success=True)

        # Amount per staking output. Qtum's 1000 assumed its 20000-per-block
        # bootstrap subsidy; WATTx pays 5 WTX a block, so 100 matured coinbases
        # are ~500 WTX total and ten 1000-WTX sends fail with "Insufficient
        # funds". Sized to fit what the matured coinbases actually provide.
        stake_amount = 5
        self.log.info('wallet balance before staking sends: %s' % self.node.getbalance())
        for _ in range(10):
            self.node.sendtoaddress(self.staking_address, stake_amount)
        block_hashes += self.generatetoaddress(self.node, 1, self.staking_address)

        blocks = []
        for block_hash in block_hashes:
            blocks.append(self.node.getblock(block_hash))


        # These are our staking txs
        self.staking_prevouts = []
        self.bad_vout_staking_prevouts = []
        self.bad_txid_staking_prevouts = []
        self.unconfirmed_staking_prevouts = []

        for unspent in self.node.listunspent():
            for block in blocks:
                if unspent['txid'] in block['tx']:
                    tx_block_time = block['time']
                    break
            else:
                assert(False)

            if unspent['confirmations'] > COINBASE_MATURITY:
                self.staking_prevouts.append((COutPoint(int(unspent['txid'], 16), unspent['vout']), int(unspent['amount'])*COIN, tx_block_time))
                self.bad_vout_staking_prevouts.append((COutPoint(int(unspent['txid'], 16), 0xff), int(unspent['amount'])*COIN, tx_block_time))
                self.bad_txid_staking_prevouts.append((COutPoint(int(unspent['txid'], 16)+1, unspent['vout']), int(unspent['amount'])*COIN, tx_block_time))


            if unspent['confirmations'] < COINBASE_MATURITY:
                self.unconfirmed_staking_prevouts.append((COutPoint(int(unspent['txid'], 16), unspent['vout']), int(unspent['amount'])*COIN, tx_block_time))




        # First let 25 seconds pass so that we do not submit blocks directly after the last one
        #time.sleep(100)
        block_count = self.node.getblockcount()


        # 1 A block that does not have the correct timestamp mask
        t = int(time.time()) | 1
        (self.tip, block_sig_key) = self.create_unsigned_pos_block(self.staking_prevouts, nTime=t)
        self.tip.sign_block(block_sig_key)
        self.tip.rehash()
        self.sync_all_blocks([self.tip], success=False, force_send=True, reconnect=True)
        self._remove_from_staking_prevouts(self.tip)


        # 2 A block that with a too high reward
        (self.tip, block_sig_key) = self.create_unsigned_pos_block(self.staking_prevouts, outNValue=30006)
        self.tip.sign_block(block_sig_key)
        self.tip.rehash()
        self.sync_all_blocks([self.tip], success=False, reconnect=True)
        self._remove_from_staking_prevouts(self.tip)


        # 3 A block with an incorrect block sig
        bad_key = ECKey()
        bad_key.set(hash256(b'horse staple battery'), False)
        (self.tip, block_sig_key) = self.create_unsigned_pos_block(self.staking_prevouts)
        self.tip.sign_block(bad_key)
        self.tip.rehash()
        self.sync_all_blocks([self.tip], success=False, reconnect=True, force_send=True)
        self._remove_from_staking_prevouts(self.tip)


        # 4 A block that stakes with txs with too few confirmations
        (self.tip, block_sig_key) = self.create_unsigned_pos_block(self.unconfirmed_staking_prevouts)
        self.tip.sign_block(block_sig_key)
        self.tip.rehash()
        self.sync_all_blocks([self.tip], success=False, reconnect=True, force_send=True)
        self._remove_from_staking_prevouts(self.tip)


        # 5 A block that with a coinbase reward
        (self.tip, block_sig_key) = self.create_unsigned_pos_block(self.staking_prevouts)
        self.tip.vtx[0].vout[0].nValue = 1
        self.tip.hashMerkleRoot = self.tip.calc_merkle_root()
        self.tip.sign_block(block_sig_key)
        self.tip.rehash()
        self.sync_all_blocks([self.tip], success=False, reconnect=True)
        self._remove_from_staking_prevouts(self.tip)


        # 6 A block that with no vout in the coinbase
        (self.tip, block_sig_key) = self.create_unsigned_pos_block(self.staking_prevouts)
        self.tip.vtx[0].vout = []
        self.tip.hashMerkleRoot = self.tip.calc_merkle_root()
        self.tip.sign_block(block_sig_key)
        self.tip.rehash()
        self.sync_all_blocks([self.tip], success=False, reconnect=True)
        self._remove_from_staking_prevouts(self.tip)


        # 7 A block way into the future
        t = (int(time.time())+100) & 0xfffffff0
        (self.tip, block_sig_key) = self.create_unsigned_pos_block(self.staking_prevouts, nTime=t)
        self.tip.sign_block(block_sig_key)
        self.tip.rehash()
        self.sync_all_blocks([self.tip], success=False, force_send=True)
        self._remove_from_staking_prevouts(self.tip)


        # 8 No vout in the staking tx
        (self.tip, block_sig_key) = self.create_unsigned_pos_block(self.staking_prevouts)
        self.tip.vtx[1].vout = []
        self.tip.hashMerkleRoot = self.tip.calc_merkle_root()
        self.tip.sign_block(block_sig_key)
        self.tip.rehash()
        self.sync_all_blocks([self.tip], success=False, reconnect=True)
        self._remove_from_staking_prevouts(self.tip)


        # 9 Unsigned coinstake.
        (self.tip, block_sig_key) = self.create_unsigned_pos_block(self.staking_prevouts, signStakeTx=False)
        self.tip.sign_block(block_sig_key)
        self.tip.rehash()
        self.sync_all_blocks([self.tip], success=False, reconnect=True)
        self._remove_from_staking_prevouts(self.tip)
        

        # 10 A block without a coinstake tx.
        (self.tip, block_sig_key) = self.create_unsigned_pos_block(self.staking_prevouts)
        self.tip.vtx.pop(-1)
        self.tip.hashMerkleRoot = self.tip.calc_merkle_root()
        self.tip.sign_block(block_sig_key)
        self.tip.rehash()
        self.sync_all_blocks([self.tip], success=False, reconnect=True)
        self._remove_from_staking_prevouts(self.tip)


        # 11 A block without a coinbase.
        (self.tip, block_sig_key) = self.create_unsigned_pos_block(self.staking_prevouts)
        self.tip.vtx.pop(0)
        self.tip.hashMerkleRoot = self.tip.calc_merkle_root()
        self.tip.sign_block(block_sig_key)
        self.tip.rehash()
        self.sync_all_blocks([self.tip], success=False, reconnect=True)
        self._remove_from_staking_prevouts(self.tip)


        # 12 A block where the coinbase has no outputs
        (self.tip, block_sig_key) = self.create_unsigned_pos_block(self.staking_prevouts)
        self.tip.vtx[0].vout = []
        self.tip.hashMerkleRoot = self.tip.calc_merkle_root()
        self.tip.sign_block(block_sig_key)
        self.tip.rehash()
        self.sync_all_blocks([self.tip], success=False, reconnect=True)
        self._remove_from_staking_prevouts(self.tip)


        # 13 A block where the coinstake has no outputs
        (self.tip, block_sig_key) = self.create_unsigned_pos_block(self.staking_prevouts)
        self.tip.vtx[1].vout.pop(-1)
        self.tip.vtx[1].vout.pop(-1)
        stake_tx_signed_raw_hex = self.node.signrawtransactionwithwallet(bytes_to_hex_str(self.tip.vtx[1].serialize()))['hex']
        f = io.BytesIO(hex_str_to_bytes(stake_tx_signed_raw_hex))
        self.tip.vtx[1] = CTransaction()
        self.tip.vtx[1].deserialize(f)
        self.tip.hashMerkleRoot = self.tip.calc_merkle_root()
        self.tip.sign_block(block_sig_key)
        self.tip.rehash()
        self.sync_all_blocks([self.tip], success=False, reconnect=True)
        self._remove_from_staking_prevouts(self.tip)


        # 14 A block with an incorrect hashStateRoot
        (self.tip, block_sig_key) = self.create_unsigned_pos_block(self.staking_prevouts)
        self.tip.hashStateRoot = 0xe
        self.tip.sign_block(block_sig_key)
        self.tip.rehash()
        self.sync_all_blocks([self.tip], success=False, reconnect=True)
        self._remove_from_staking_prevouts(self.tip)


        # 15 A block with an incorrect hashUTXORoot
        (self.tip, block_sig_key) = self.create_unsigned_pos_block(self.staking_prevouts)
        self.tip.hashUTXORoot = 0xe
        self.tip.sign_block(block_sig_key)
        self.tip.rehash()
        self.sync_all_blocks([self.tip], success=False, reconnect=True)
        self._remove_from_staking_prevouts(self.tip)


        # 16 A block with an a signature on wrong header data
        (self.tip, block_sig_key) = self.create_unsigned_pos_block(self.staking_prevouts)
        self.tip.sign_block(block_sig_key)
        self.tip.nNonce = 0xfffe
        self.tip.rehash()
        self.sync_all_blocks([self.tip], success=False, reconnect=True, force_send=True)
        self._remove_from_staking_prevouts(self.tip)

        # 17 A block with where the pubkey of the second output of the coinstake has been modified after block signing
        (self.tip, block_sig_key) = self.create_unsigned_pos_block(self.staking_prevouts)
        scriptPubKey = self.tip.vtx[1].vout[1].scriptPubKey
        # Modify a byte of the pubkey
        self.tip.vtx[1].vout[1].scriptPubKey = scriptPubKey[0:20] + bytes.fromhex(hex(ord(scriptPubKey[20:21])+1)[2:4]) + scriptPubKey[21:] 
        assert_equal(len(scriptPubKey), len(self.tip.vtx[1].vout[1].scriptPubKey))
        stake_tx_signed_raw_hex = self.node.signrawtransactionwithwallet(bytes_to_hex_str(self.tip.vtx[1].serialize()))['hex']
        f = io.BytesIO(hex_str_to_bytes(stake_tx_signed_raw_hex))
        self.tip.vtx[1] = CTransaction()
        self.tip.vtx[1].deserialize(f)
        self.tip.hashMerkleRoot = self.tip.calc_merkle_root()
        self.tip.sign_block(block_sig_key)
        self.tip.rehash()
        self.sync_all_blocks([self.tip], success=False, reconnect=True)
        self._remove_from_staking_prevouts(self.tip)

        # 18. A block in the past
        t = (int(time.time())-700) & 0xfffffff0
        (self.tip, block_sig_key) = self.create_unsigned_pos_block(self.staking_prevouts, nTime=t)
        self.tip.sign_block(block_sig_key)
        self.tip.rehash()
        self.sync_all_blocks([self.tip], success=False, force_send=True, reconnect=True)
        self._remove_from_staking_prevouts(self.tip)


        # 19. A block with too many coinbase vouts
        (self.tip, block_sig_key) = self.create_unsigned_pos_block(self.staking_prevouts)
        self.tip.vtx[0].vout.append(CTxOut(0, CScript([OP_TRUE])))
        self.tip.vtx[0].rehash()
        self.tip.hashMerkleRoot = self.tip.calc_merkle_root()
        self.tip.sign_block(block_sig_key)
        self.tip.rehash()
        self.sync_all_blocks([self.tip], success=False, reconnect=True)
        self._remove_from_staking_prevouts(self.tip)


        # 20. A block where the coinstake's vin is not the prevout specified in the block
        (self.tip, block_sig_key) = self.create_unsigned_pos_block(self.staking_prevouts, coinStakePrevout=self.staking_prevouts[-1][0])
        self.tip.sign_block(block_sig_key)
        self.tip.rehash()
        self.sync_all_blocks([self.tip], success=False, reconnect=True)
        self._remove_from_staking_prevouts(self.tip)


        # 21. A block that stakes with valid txs but invalid vouts
        (self.tip, block_sig_key) = self.create_unsigned_pos_block(self.bad_vout_staking_prevouts)
        self.tip.sign_block(block_sig_key)
        self.tip.rehash()
        self.sync_all_blocks([self.tip], success=False, reconnect=True, force_send=True)
        self._remove_from_staking_prevouts(self.tip)


        # 22. A block that stakes with txs that do not exist
        (self.tip, block_sig_key) = self.create_unsigned_pos_block(self.bad_txid_staking_prevouts)
        self.tip.sign_block(block_sig_key)
        self.tip.rehash()
        self.sync_all_blocks([self.tip], success=False, reconnect=True, force_send=True)
        self._remove_from_staking_prevouts(self.tip)


        # Make sure for certain that no blocks were accepted. (This is also to make sure that no segfaults ocurred)
        assert_equal(self.node.getblockcount(), block_count)

        # And at last, make sure that a valid pos block is accepted
        (self.tip, block_sig_key) = self.create_unsigned_pos_block(self.staking_prevouts)
        self.tip.sign_block(block_sig_key)
        self.tip.rehash()
        self.sync_all_blocks([self.tip], success=True)
        assert_equal(self.node.getblockcount(), block_count+1)




    def create_unsigned_pos_block(self, staking_prevouts, nTime=None, outNValue=None, signStakeTx=True, bestBlockHash=None, coinStakePrevout=None, granule_attempts=6):
        # A caller that pins nTime is testing that exact timestamp, so never move
        # it. Otherwise the timestamp is ours to choose, and we may have to wait:
        # see the granule note at the solve_stake call below.
        pinned_nTime = nTime is not None
        if not nTime:
            # Round UP to the next aligned granule, deliberately: the parent was
            # mined moments ago and a PoS block's timestamp must be strictly after
            # it, so aligning down would land on or before the parent. Rounding up
            # stays inside FutureDrift, which allows exactly this much.
            current_time = int(time.time()) + WATTX_POS_TIMESTAMP_MASK
            nTime = current_time & (0xffffffff - WATTX_POS_TIMESTAMP_MASK)

        if not bestBlockHash:
            bestBlockHash = self.node.getbestblockhash()
            block_height = self.node.getblockcount()
        else:
            block_height = self.node.getblock(bestBlockHash)['height']

        parent_block_stake_modifier = int(self.node.getblock(bestBlockHash)['modifier'], 16)
        parent_block_raw_hex = self.node.getblock(bestBlockHash, False)
        f = io.BytesIO(hex_str_to_bytes(parent_block_raw_hex))
        parent_block = CBlock()
        parent_block.deserialize(f)
        coinbase = create_coinbase(block_height+1)
        coinbase.vout[0].nValue = 0
        coinbase.vout[0].scriptPubKey = b""
        coinbase.rehash()

        # Wait for a timestamp granule that yields a kernel.
        #
        # Only one timestamp is legal at a time (see solve_stake), and it is a
        # 16-second granule, so every case that runs inside the same granule
        # searches at the SAME nTime. At a fixed nTime the prevouts that can
        # produce a kernel are a fixed subset -- for a 5 WTX prevout the odds are
        # ((0x7fffff * nValue) mod 2**24) / 2**24, about a fifth -- and each case
        # consumes one of them via _remove_from_staking_prevouts. The suite runs
        # its cases in well under a second, so the winners in the current granule
        # run out and every later case fails at that nTime no matter how many
        # prevouts remain. Waiting for the clock to tick re-rolls all of them,
        # which is exactly what a real staker does.
        for attempt in range(granule_attempts if not pinned_nTime else 1):
            if attempt:
                granule = WATTX_POS_TIMESTAMP_MASK + 1
                time.sleep(granule - (int(time.time()) % granule) + 1)
                nTime = (int(time.time()) + WATTX_POS_TIMESTAMP_MASK) & (0xffffffff - WATTX_POS_TIMESTAMP_MASK)
            block = create_block(int(bestBlockHash, 16), coinbase, nTime)
            block.hashPrevBlock = int(bestBlockHash, 16)
            # create_block() fills in the PoW limit; a PoS block is measured
            # against the PoS limit instead (see WATTX_POS_LIMIT_NBITS).
            block.nBits = WATTX_POS_LIMIT_NBITS
            if block.solve_stake(parent_block_stake_modifier, staking_prevouts):
                break
        else:
            # Returning None here surfaces as "cannot unpack non-iterable
            # NoneType" at whichever caller happened to run out of luck, which
            # says nothing about why. Report the pool instead.
            self.log.error(
                'solve_stake found no kernel after %d granules, last nTime=%d, '
                'over %d prevouts (values: %s)' % (
                    granule_attempts, nTime, len(staking_prevouts),
                    sorted({v for _, v, _ in staking_prevouts})))
            return None

        # create a new private key used for block signing.
        block_sig_key = ECKey()
        block_sig_key.set(hash256(struct.pack('<I', 0)), False)
        pubkey = block_sig_key.get_pubkey().get_bytes()
        scriptPubKey = CScript([pubkey, OP_CHECKSIG])
        stake_tx_unsigned = CTransaction()

        if not coinStakePrevout:
            coinStakePrevout = block.prevoutStake

        if outNValue is None:
            # Qtum's 10002 was its 20000 stake input plus its 4 PoS reward, split
            # over two outputs. Neither number holds here: WATTx stakes 5 WTX
            # prevouts, and by the height these tests reach the subsidy has run
            # through all WATTX_MAX_HALVINGS and pays nothing at all. So the
            # coinstake has to return exactly what it consumed, or ConnectBlock
            # rejects the block with "block-reward-invalid" -- which it did, on
            # the one case that expects a valid block to be accepted.
            stake_value = 0
            for prevout, nValue, _ in staking_prevouts:
                if prevout.serialize() == coinStakePrevout.serialize():
                    stake_value = nValue
                    break
            out_each = (stake_value + wattx_block_subsidy(block_height + 1)) // 2
        else:
            out_each = int(outNValue*COIN)

        stake_tx_unsigned.vin.append(CTxIn(coinStakePrevout))
        stake_tx_unsigned.vout.append(CTxOut())
        stake_tx_unsigned.vout.append(CTxOut(out_each, scriptPubKey))
        stake_tx_unsigned.vout.append(CTxOut(out_each, scriptPubKey))

        if signStakeTx:
            stake_tx_signed_raw_hex = self.node.signrawtransactionwithwallet(bytes_to_hex_str(stake_tx_unsigned.serialize()))['hex']
            f = io.BytesIO(hex_str_to_bytes(stake_tx_signed_raw_hex))
            stake_tx_signed = CTransaction()
            stake_tx_signed.deserialize(f)
            block.vtx.append(stake_tx_signed)
        else:
            block.vtx.append(stake_tx_unsigned)
        block.hashMerkleRoot = block.calc_merkle_root()
        return (block, block_sig_key)

if __name__ == '__main__':
    QtumPOSTest(__file__).main()
