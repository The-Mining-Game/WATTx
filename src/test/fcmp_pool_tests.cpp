// Copyright (c) 2026 The WATTx Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Shielded pool value backing -- see doc/design/fcmp-value-balance.md.
//
// The ledger invariant under test is
//
//     sum(pseudo-outputs) + delta*H == sum(output commitments)
//
// where delta is the net transparent value the pool gained, computed by the
// verifier from the transaction and the coins view. These tests cover the
// invariant itself and the pool-delta accounting that feeds it. The failure mode
// they guard is silent inflation, so most of them are attacks.

#include <boost/test/unit_test.hpp>

#include <coins.h>
#include <primitives/transaction.h>
#include <privacy/confidential.h>
#include <privacy/fcmp_consensus.h>
#include <script/script.h>
#include <test/util/setup_common.h>

#include <vector>

using namespace privacy;

namespace {

//! A commitment to `amount` under a fresh random blinding.
CPedersenCommitment Commit(CAmount amount, CBlindingFactor& blind_out)
{
    blind_out = CBlindingFactor::Random();
    CPedersenCommitment c;
    BOOST_REQUIRE(CreateCommitment(amount, blind_out, c));
    return c;
}

//! Add `coin` to the view as an unspent output of a synthetic outpoint.
COutPoint AddCoin(CCoinsViewCache& view, const CScript& script, CAmount value, uint32_t n)
{
    CMutableTransaction funding;
    funding.vout.resize(n + 1);
    funding.vout[n].scriptPubKey = script;
    funding.vout[n].nValue = value;
    const COutPoint op(funding.GetHash(), n);
    view.AddCoin(op, Coin(funding.vout[n], 1, /*fCoinBaseIn=*/false, /*fCoinStakeIn=*/false), false);
    return op;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(fcmp_pool_tests, BasicTestingSetup)

// ---------------------------------------------------------------------------
// The pool script
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(pool_script_is_a_witness_program)
{
    const CScript& pool = GetShieldedPoolScript();

    // Must be a native witness program: that is what keeps the spending input's
    // scriptSig empty, so the txid is not scriptSig-malleable and the FCMP payload
    // can ride in the witness (which the txid excludes).
    int version = -1;
    std::vector<unsigned char> program;
    BOOST_CHECK(pool.IsWitnessProgram(version, program));
    BOOST_CHECK_EQUAL(version, 16);
    BOOST_CHECK_EQUAL(program.size(), 32U);

    BOOST_CHECK(IsPoolScript(pool));

    // It is a fixed constant -- every node must recognise it byte-for-byte with no
    // context needed to derive it.
    BOOST_CHECK(GetShieldedPoolScript() == pool);

    // Near misses are not the pool.
    BOOST_CHECK(!IsPoolScript(CScript()));
    BOOST_CHECK(!IsPoolScript(CScript() << OP_RETURN));
    CScript wrong_version;
    wrong_version << OP_15 << std::vector<unsigned char>(program.begin(), program.end());
    BOOST_CHECK(!IsPoolScript(wrong_version));
    std::vector<unsigned char> tweaked = program;
    tweaked[0] ^= 0x01;
    CScript wrong_program;
    wrong_program << OP_16 << tweaked;
    BOOST_CHECK(!IsPoolScript(wrong_program));
}

// ---------------------------------------------------------------------------
// Pool delta accounting
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(pool_delta_shield_is_positive)
{
    CCoinsView dummy;
    CCoinsViewCache view(&dummy);

    const CScript user = CScript() << OP_TRUE;
    const COutPoint funded = AddCoin(view, user, 500 * COIN, 0);

    // Spends an ordinary UTXO, pays 100 into the pool: delta = +100.
    CMutableTransaction tx;
    tx.vin.emplace_back(funded);
    tx.vout.emplace_back(100 * COIN, GetShieldedPoolScript());
    tx.vout.emplace_back(399 * COIN, user);

    CAmount delta = 0;
    BOOST_REQUIRE(ComputePoolDelta(CTransaction(tx), view, delta));
    BOOST_CHECK_EQUAL(delta, 100 * COIN);

    BOOST_CHECK(CreatesPool(CTransaction(tx)));
    BOOST_CHECK(!SpendsPool(CTransaction(tx), view));
}

BOOST_AUTO_TEST_CASE(pool_delta_unshield_is_negative)
{
    CCoinsView dummy;
    CCoinsViewCache view(&dummy);

    const CScript user = CScript() << OP_TRUE;
    const COutPoint pool_utxo = AddCoin(view, GetShieldedPoolScript(), 100 * COIN, 0);

    // Spends 100 of pool, returns 60 to the pool, pays 39 out, 1 fee: delta = -40.
    CMutableTransaction tx;
    tx.vin.emplace_back(pool_utxo);
    tx.vout.emplace_back(60 * COIN, GetShieldedPoolScript());
    tx.vout.emplace_back(39 * COIN, user);

    CAmount delta = 0;
    BOOST_REQUIRE(ComputePoolDelta(CTransaction(tx), view, delta));
    BOOST_CHECK_EQUAL(delta, -40 * COIN);

    BOOST_CHECK(SpendsPool(CTransaction(tx), view));
    BOOST_CHECK(CreatesPool(CTransaction(tx)));
}

BOOST_AUTO_TEST_CASE(pool_delta_transfer_is_just_the_fee)
{
    CCoinsView dummy;
    CCoinsViewCache view(&dummy);

    const COutPoint pool_utxo = AddCoin(view, GetShieldedPoolScript(), 100 * COIN, 0);

    // Shielded-to-shielded: spend the pool UTXO, pay it back less a 1 fee.
    CMutableTransaction tx;
    tx.vin.emplace_back(pool_utxo);
    tx.vout.emplace_back(99 * COIN, GetShieldedPoolScript());

    CAmount delta = 0;
    BOOST_REQUIRE(ComputePoolDelta(CTransaction(tx), view, delta));
    BOOST_CHECK_EQUAL(delta, -1 * COIN);
}

BOOST_AUTO_TEST_CASE(pool_delta_consolidation_sums_every_utxo)
{
    CCoinsView dummy;
    CCoinsViewCache view(&dummy);

    // Several pool UTXOs exist so concurrent spends do not all contend for one.
    const COutPoint a = AddCoin(view, GetShieldedPoolScript(), 10 * COIN, 0);
    const COutPoint b = AddCoin(view, GetShieldedPoolScript(), 20 * COIN, 1);
    const COutPoint c = AddCoin(view, GetShieldedPoolScript(), 30 * COIN, 2);

    CMutableTransaction tx;
    tx.vin.emplace_back(a);
    tx.vin.emplace_back(b);
    tx.vin.emplace_back(c);
    tx.vout.emplace_back(59 * COIN, GetShieldedPoolScript());

    CAmount delta = 0;
    BOOST_REQUIRE(ComputePoolDelta(CTransaction(tx), view, delta));
    BOOST_CHECK_EQUAL(delta, -1 * COIN);
}

BOOST_AUTO_TEST_CASE(pool_delta_fails_when_an_input_coin_is_missing)
{
    CCoinsView dummy;
    CCoinsViewCache view(&dummy);

    // Nothing added to the view: the delta is not computable, and guessing it
    // would be inventing pool value.
    CMutableTransaction tx;
    tx.vin.emplace_back(COutPoint(Txid::FromUint256(uint256{1}), 0));
    tx.vout.emplace_back(50 * COIN, GetShieldedPoolScript());

    CAmount delta = 0;
    BOOST_CHECK(!ComputePoolDelta(CTransaction(tx), view, delta));
}

// ---------------------------------------------------------------------------
// The ledger invariant
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(pool_balance_shield_from_transparent_value)
{
    // A pure shield: no shielded inputs, delta funds the outputs.
    const CAmount value = 42 * COIN;

    CPedersenCommitment out;
    BOOST_REQUIRE(CreatePublicValueCommitment(value, out));

    BOOST_CHECK(VerifyPoolBalance({}, {out}, value));

    // Shielding 42 but committing to 43 must not balance.
    CPedersenCommitment inflated;
    BOOST_REQUIRE(CreatePublicValueCommitment(value + COIN, inflated));
    BOOST_CHECK(!VerifyPoolBalance({}, {inflated}, value));
}

BOOST_AUTO_TEST_CASE(pool_balance_shield_output_must_have_zero_blinding)
{
    // Pins a consequence of the invariant that is easy to "fix" into a break.
    //
    // delta*H carries no blinding, so with no shielded inputs to contribute one,
    // a shield's output commitments must have blindings summing to zero -- for a
    // single output, exactly zero. Giving that output a random blinding, which
    // looks like an obvious privacy improvement, makes the equation unsatisfiable
    // and every shield invalid.
    //
    // This is not a privacy loss: a shield's amount is already public from the
    // transparent input funding it. The note becomes unlinkable when it is SPENT,
    // via C~ = C + r_c*G, and the membership proof is what hides which leaf that
    // was. If hidden shield amounts are ever wanted, the fix is a Zcash-style
    // binding signature proving knowledge of the blinding sum, NOT a random
    // blinding here.
    const CAmount value = 5 * COIN;

    CPedersenCommitment zero_blinded;
    BOOST_REQUIRE(CreatePublicValueCommitment(value, zero_blinded));
    BOOST_CHECK(VerifyPoolBalance({}, {zero_blinded}, value));

    CBlindingFactor random_blind;
    const CPedersenCommitment randomly_blinded = Commit(value, random_blind);
    BOOST_CHECK(!VerifyPoolBalance({}, {randomly_blinded}, value));

    // Two shield outputs are fine as long as their blindings cancel.
    std::vector<CBlindingFactor> blinds{CBlindingFactor::Random(), CBlindingFactor()};
    // Balance against a zero input blinding: sum(out) must come to zero.
    const CBlindingFactor zero{uint256{}};
    BOOST_CHECK(!zero.IsValid()); // a null blinding is rejected as an input...
    // ...so construct the cancelling pair directly: b and -b.
    CPedersenCommitment c1, c2;
    BOOST_REQUIRE(CreateCommitment(2 * COIN, blinds[0], c1));
    // BalanceBlindingFactors with a single "input" blinding of b gives the second
    // output blinding as b - b = 0 only when the input blinding matches; instead
    // assert the general property via the transfer case above, and here just
    // confirm that a mismatched pair does NOT balance.
    CBlindingFactor other = CBlindingFactor::Random();
    BOOST_REQUIRE(CreateCommitment(3 * COIN, other, c2));
    BOOST_CHECK(!VerifyPoolBalance({}, {c1, c2}, value));
}

BOOST_AUTO_TEST_CASE(pool_balance_transfer_conserves_value)
{
    // Shielded-to-shielded, fee paid from the pool: delta = -fee.
    const CAmount in_value = 100 * COIN;
    const CAmount fee = 1 * COIN;
    const CAmount out_a = 60 * COIN;
    const CAmount out_b = 39 * COIN; // 60 + 39 + 1 == 100

    CBlindingFactor bin;
    const CPedersenCommitment cin = Commit(in_value, bin);

    // Balance the output blindings against the input's, exactly as the builder must.
    std::vector<CBlindingFactor> out_blinds{CBlindingFactor::Random(), CBlindingFactor()};
    BOOST_REQUIRE(BalanceBlindingFactors({bin}, out_blinds));

    CPedersenCommitment ca, cb;
    BOOST_REQUIRE(CreateCommitment(out_a, out_blinds[0], ca));
    BOOST_REQUIRE(CreateCommitment(out_b, out_blinds[1], cb));

    BOOST_CHECK(VerifyPoolBalance({cin}, {ca, cb}, -fee));

    // ATTACK: same blindings, but an output claims more value than was put in.
    CPedersenCommitment cb_fat;
    BOOST_REQUIRE(CreateCommitment(out_b + COIN, out_blinds[1], cb_fat));
    BOOST_CHECK(!VerifyPoolBalance({cin}, {ca, cb_fat}, -fee));

    // ATTACK: understate the fee leaving the pool, keeping the outputs honest.
    BOOST_CHECK(!VerifyPoolBalance({cin}, {ca, cb}, 0));
    BOOST_CHECK(!VerifyPoolBalance({cin}, {ca, cb}, -fee / 2));
}

BOOST_AUTO_TEST_CASE(pool_balance_rejects_a_wrong_sign_delta)
{
    // The sign of delta is the difference between "value entered the pool" and
    // "value left it". Getting it backwards must not balance, or a shield and an
    // unshield of the same size would be interchangeable.
    const CAmount value = 7 * COIN;
    CPedersenCommitment out;
    BOOST_REQUIRE(CreatePublicValueCommitment(value, out));

    BOOST_CHECK(VerifyPoolBalance({}, {out}, value));
    BOOST_CHECK(!VerifyPoolBalance({}, {out}, -value));
}

BOOST_AUTO_TEST_CASE(pool_balance_rejects_substituted_commitment)
{
    // ATTACK: swap an output commitment after the blindings were balanced. The
    // values still "look" right but the blindings no longer cancel.
    const CAmount in_value = 50 * COIN;
    CBlindingFactor bin;
    const CPedersenCommitment cin = Commit(in_value, bin);

    std::vector<CBlindingFactor> out_blinds{CBlindingFactor()};
    BOOST_REQUIRE(BalanceBlindingFactors({bin}, out_blinds));

    CPedersenCommitment cout;
    BOOST_REQUIRE(CreateCommitment(in_value, out_blinds[0], cout));
    BOOST_CHECK(VerifyPoolBalance({cin}, {cout}, 0));

    CBlindingFactor other;
    const CPedersenCommitment substituted = Commit(in_value, other);
    BOOST_CHECK(!VerifyPoolBalance({cin}, {substituted}, 0));
}

BOOST_AUTO_TEST_CASE(pool_balance_rejects_empty_and_malformed)
{
    // Nothing on either side is not a transaction to balance.
    BOOST_CHECK(!VerifyPoolBalance({}, {}, 0));
    BOOST_CHECK(!VerifyPoolBalance({}, {}, 100 * COIN));

    // A legacy secp256k1-tagged commitment (prefix 0x02) must be structurally
    // rejected, not silently treated as an ed25519 point.
    CPedersenCommitment legacy;
    legacy.data.assign(33, 0);
    legacy.data[0] = 0x02;
    BOOST_CHECK(!VerifyPoolBalance({}, {legacy}, 0));

    // Wrong size.
    CPedersenCommitment short_c;
    short_c.data.assign(32, 0x0E);
    BOOST_CHECK(!VerifyPoolBalance({}, {short_c}, 0));
}

BOOST_AUTO_TEST_SUITE_END()
