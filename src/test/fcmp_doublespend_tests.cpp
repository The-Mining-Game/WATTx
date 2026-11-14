// Copyright (c) 2026 The WATTx Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Regression: a shielded note must not be spendable twice.
//
// Two holes used to allow it.
//
//  1. Key-image uniqueness was checked against the chain DB only. A second
//     transaction spending the same note was accepted to the mempool, because
//     the first spend had not been written to that DB yet.
//
//  2. The number of curve-tree outputs a block added lived in an in-memory
//     map. After a restart, disconnecting that block unmarked the key image
//     (the DB survived) but left the note in the tree. The transparent
//     effects of the block were rolled back by the coins DB, and the note
//     could be spent again.

#include <boost/test/unit_test.hpp>

#include <chain.h>
#include <coins.h>
#include <consensus/validation.h>
#include <consensus/merkle.h>
#include <key.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <privacy/ed25519/ed25519_types.h>
#include <privacy/fcmp_consensus.h>
#include <privacy/fcmp_tx.h>
#include <privacy/privacy.h>
#include <script/script.h>
#include <streams.h>
#include <test/util/setup_common.h>

#include <cstring>
#include <vector>

using namespace privacy;

namespace {

COutPoint AddPoolCoin(CCoinsViewCache& view, CAmount value, uint32_t tag)
{
    CMutableTransaction funding;
    funding.nLockTime = tag;
    funding.vout.emplace_back(value, GetShieldedPoolScript());
    const COutPoint op(funding.GetHash(), 0);
    view.AddCoin(op, Coin(funding.vout[0], 1, /*fCoinBaseIn=*/false, /*fCoinStakeIn=*/false), false);
    return op;
}

CKeyImage MakeKeyImage(uint8_t tag)
{
    CKeyImage ki;
    ki.data.assign(33, tag);
    ki.data[0] = 0x02;
    return ki;
}

CTransaction SpendWithKeyImage(const COutPoint& pool, const CKeyImage& ki)
{
    CPrivacyTransaction priv;
    priv.nVersion = 2;
    priv.privacyType = PrivacyType::FCMP;
    CFcmpInput input;
    input.keyImage = ki;
    priv.fcmpInputs.push_back(input);

    DataStream body;
    body << priv;
    std::vector<unsigned char> payload{'F', 'C', 'M', 'P'};
    payload.resize(4 + body.size());
    std::memcpy(payload.data() + 4, body.data(), body.size());

    CMutableTransaction tx;
    tx.vin.resize(1);
    tx.vin[0].prevout = pool;
    tx.vin[0].scriptWitness.stack.push_back(payload);
    tx.vout.emplace_back(1 * COIN, GetShieldedPoolScript());
    return CTransaction(tx);
}

CScript NoteScript()
{
    const ed25519::Point G = ed25519::Point::BasePoint();
    std::vector<unsigned char> data{'F', 'C', 'M', 'P'};
    for (int i = 0; i < 3; ++i) {
        data.insert(data.end(), G.data.begin(), G.data.end());
    }
    CScript script;
    script << OP_RETURN << data;
    return script;
}

CBlock BlockWith(const CTransaction& tx, int height)
{
    CMutableTransaction coinbase;
    coinbase.vin.resize(1);
    coinbase.vin[0].prevout.SetNull();
    coinbase.vin[0].scriptSig = CScript() << height << OP_0;
    coinbase.vout.emplace_back(50 * COIN, CScript() << OP_TRUE);

    CBlock block;
    block.vtx.push_back(MakeTransactionRef(coinbase));
    block.vtx.push_back(MakeTransactionRef(tx));
    block.hashMerkleRoot = BlockMerkleRoot(block);
    return block;
}

struct FcmpTempState {
    explicit FcmpTempState(const fs::path& dir)
    {
        BOOST_REQUIRE(InitializeFcmpConsensus(dir));
        BOOST_REQUIRE(GetFcmpState().IsInitialized());
    }
    ~FcmpTempState() { ShutdownFcmpConsensus(); }
};

} // namespace

BOOST_FIXTURE_TEST_SUITE(fcmp_doublespend_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(mempool_rejects_second_spend_of_the_same_note)
{
    FcmpTempState state{m_path_root / "fcmp-mempool"};

    CCoinsView base;
    CCoinsViewCache view(&base);
    const COutPoint pool_a = AddPoolCoin(view, 10 * COIN, 1);
    const COutPoint pool_b = AddPoolCoin(view, 10 * COIN, 2);
    const CKeyImage ki = MakeKeyImage(0x11);

    const CTransaction first = SpendWithKeyImage(pool_a, ki);
    const CTransaction second = SpendWithKeyImage(pool_b, ki);
    BOOST_REQUIRE(first.GetHash() != second.GetHash());

    // The first spend is only in the mempool. Nothing has been written to the
    // chain key-image DB, which is what the old check consulted.
    GetFcmpState().AccountMempoolTx(first);

    TxValidationState inv;
    BOOST_CHECK(!GetFcmpState().CheckFcmpInputs(second, inv, view, /*nSpendHeight=*/2));
    BOOST_CHECK_EQUAL(inv.GetRejectReason(), "fcmp-keyimage-mempool-spent");

    // The transaction that already holds the claim is not a conflict with itself.
    TxValidationState self;
    const bool self_ok = GetFcmpState().CheckFcmpInputs(first, self, view, 2);
    if (!self_ok) {
        BOOST_CHECK(self.GetRejectReason() != "fcmp-keyimage-mempool-spent");
    }
}

BOOST_AUTO_TEST_CASE(block_rejects_two_spends_of_the_same_note)
{
    FcmpTempState state{m_path_root / "fcmp-block"};

    const CKeyImage ki = MakeKeyImage(0x22);
    CMutableTransaction a = CMutableTransaction(SpendWithKeyImage(COutPoint(Txid::FromUint256(uint256::ONE), 0), ki));
    CMutableTransaction b = a;
    b.nLockTime = 1; // distinct txid, same key image
    BOOST_REQUIRE(a.GetHash() != b.GetHash());

    CBlock block = BlockWith(CTransaction(a), 1);
    block.vtx.push_back(MakeTransactionRef(CTransaction(b)));

    CBlockIndex index;
    index.nHeight = 1;
    BOOST_CHECK(!GetFcmpState().ConnectBlock(block, &index));
    BOOST_CHECK(!GetFcmpState().IsKeyImageSpent(ki));
}

BOOST_AUTO_TEST_CASE(reorg_after_restart_removes_the_note)
{
    const fs::path dir = m_path_root / "fcmp-reorg";
    const CKeyImage ki = MakeKeyImage(0x33);

    CMutableTransaction tx;
    tx.vin.resize(1);
    tx.vin[0].prevout.SetNull();
    tx.vin[0].prevout.n = 1;
    {
        CPrivacyTransaction priv;
        priv.nVersion = 2;
        priv.privacyType = PrivacyType::FCMP;
        CFcmpInput input;
        input.keyImage = ki;
        priv.fcmpInputs.push_back(input);
        DataStream body;
        body << priv;
        std::vector<unsigned char> payload{'F', 'C', 'M', 'P'};
        payload.resize(4 + body.size());
        std::memcpy(payload.data() + 4, body.data(), body.size());
        tx.vin[0].scriptWitness.stack.push_back(payload);
    }
    tx.vout.emplace_back(1 * COIN, GetShieldedPoolScript());
    tx.vout.emplace_back(0, NoteScript());

    CBlock block = BlockWith(CTransaction(tx), 3);
    CBlockIndex index;
    index.nHeight = 3;

    {
        FcmpTempState state{dir};
        BOOST_REQUIRE(GetFcmpState().ConnectBlock(block, &index));
        BOOST_CHECK(GetFcmpState().IsKeyImageSpent(ki));
        BOOST_CHECK_EQUAL(GetFcmpState().GetTreeSize(), 1U);
    }

    // Process restart: the in-memory output map is gone, the DB is not.
    {
        FcmpTempState state{dir};
        BOOST_REQUIRE_EQUAL(GetFcmpState().GetTreeSize(), 1U);
        BOOST_REQUIRE(GetFcmpState().IsKeyImageSpent(ki));
        BOOST_REQUIRE(GetFcmpState().DisconnectBlock(block, &index));
        BOOST_CHECK(!GetFcmpState().IsKeyImageSpent(ki));
        BOOST_CHECK_EQUAL(GetFcmpState().GetTreeSize(), 0U);
    }
}

BOOST_AUTO_TEST_SUITE_END()
