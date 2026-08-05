#!/usr/bin/env python3
# Copyright (c) 2026 The WATTx Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Solo-mined blocks must survive a node restart.

This is the regression test for a failure that took the mainnet seed node down:

  LoadBlockIndexGuts: CheckIndexProof failed: CBlockIndex(nHeight=2438 ...)
  Error loading block database.

The block was valid and the network had accepted it, but the node could not
re-validate it at startup and refused to start. Two separate defects combined:

1. getblocktemplate could not be told which algorithm a template was for, so it
   always produced a sha256d one. Solo mining any other algorithm was therefore
   impossible -- every solved block was rejected as high-hash -- and no
   solo-mined non-sha256d block had ever existed on the chain.

2. Because of (1), the only blocks that existed were merged-mined ones carrying
   AUXPOW_VERSION_FLAG, which return early from CheckHeaderPoWAtHeight without
   verifying the proof. That hid a verifier that initialised RandomX with an
   all-zero key and returned a hash from the wrong dataset.

So the moment (1) was fixed, (2) bricked every node on its next restart.

What this test locks down:
  * a template can be requested per algorithm, and carries that algorithm's tag
  * requesting a different algorithm does not return a cached template for the
    previous one
  * a block mined from such a template is accepted
  * AND THE NODE CAN RESTART AFTERWARDS -- the check that was skipped

The restart is the point. Accepting a block and being able to re-validate it
from disk are different code paths, and only the first was ever exercised.
"""

from test_framework.address import ADDRESS_BCRT1_UNSPENDABLE
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error

# Algorithm ids as consensus stores them in block version bits 8-15.
ALGO_BITS = {
    "sha256d": 0x00,
    "scrypt": 0x01,
    "randomx": 0x03,
}


def algo_of(version):
    return (version >> 8) & 0xFF


class SoloAlgoRestartTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True

    def run_test(self):
        node = self.nodes[0]

        self.log.info("Give the chain some history so difficulty is meaningful")
        # A fixed address keeps this test independent of wallet support.
        addr = ADDRESS_BCRT1_UNSPENDABLE
        self.generatetoaddress(node, 30, addr)

        self.log.info("A template must carry the algorithm it was requested for")
        for name, bits in ALGO_BITS.items():
            tmpl = node.getblocktemplate({"rules": ["segwit"], "algo": name})
            assert_equal(algo_of(tmpl["version"]), bits)

        self.log.info("Re-requesting an earlier algorithm must not return a stale "
                      "cached template built for the last one")
        # Interleave so a naive cache hands back the wrong algorithm. Two miners
        # on different algorithms would otherwise trade each other's work and
        # neither could produce a valid block.
        for name in ("randomx", "scrypt", "randomx", "sha256d", "randomx"):
            tmpl = node.getblocktemplate({"rules": ["segwit"], "algo": name})
            assert_equal(algo_of(tmpl["version"]), ALGO_BITS[name])

        self.log.info("An unknown or disabled algorithm must be refused, not "
                      "silently treated as sha256d")
        assert_raises_rpc_error(-8, None, node.getblocktemplate,
                                {"rules": ["segwit"], "algo": "nonsense"})

        self.log.info("Default is sha256d, so existing callers are unaffected")
        tmpl = node.getblocktemplate({"rules": ["segwit"]})
        assert_equal(algo_of(tmpl["version"]), ALGO_BITS["sha256d"])

        self.log.info("Mine actual RandomX blocks -- NOT the sha256d default")
        # This is the whole point of the test. generatetoaddress mines sha256d
        # unless told otherwise, and sha256d blocks re-validate fine at startup,
        # so a test that skips this passes while proving nothing. Verified by
        # reverting the fix: without explicit randomx here, the test still went
        # green.
        node.generatetoaddress(5, addr, 1000000, "randomx", called_by_framework=True)

        # Confirm we really produced RandomX blocks, so this cannot silently
        # degrade into a sha256d test again.
        tip_version = node.getblock(node.getbestblockhash())["version"]
        assert_equal(algo_of(tip_version), ALGO_BITS["randomx"])

        height_before = node.getblockcount()
        besthash_before = node.getbestblockhash()

        # THE TEST THAT WAS MISSING.
        #
        # Accepting a block and re-validating it from disk at startup are
        # different paths. The node had always been able to do the first; the
        # second failed on the first solo-mined RandomX block that ever existed,
        # and the node refused to start with "Error loading block database".
        self.log.info("Restart the node -- it must load the chain it just built")
        self.restart_node(0)

        assert_equal(node.getblockcount(), height_before)
        assert_equal(node.getbestblockhash(), besthash_before)

        self.log.info("And a second restart, to catch state only written on "
                      "clean shutdown")
        self.restart_node(0)
        assert_equal(node.getbestblockhash(), besthash_before)

        self.log.info("Node survives restart with solo-mined blocks on disk")


if __name__ == '__main__':
    SoloAlgoRestartTest(__file__).main()
