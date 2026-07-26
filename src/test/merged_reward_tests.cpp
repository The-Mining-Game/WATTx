// Copyright (c) 2024-2026 The WATTx Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <stratum/multi_merged_stratum.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cmath>
#include <string>
#include <vector>

using merged_stratum::ChainRewardInput;
using merged_stratum::ComputeRewardSplit;
using merged_stratum::RewardSplitResult;

BOOST_FIXTURE_TEST_SUITE(merged_reward_tests, BasicTestingSetup)

// Build one chain where each (ip,wallet) contributes `pct` percent of nethash.
// net is fixed at 1000 so a wallet at 50% has hashrate 500.
static ChainRewardInput MakeChain(
    const std::vector<std::tuple<std::string /*ip*/, std::string /*wallet*/, double /*pct*/>>& parts,
    uint64_t net = 1000)
{
    ChainRewardInput c;
    c.network_hashrate = net;
    for (const auto& [ip, w, pct] : parts) {
        c.ip_wallet_hashrates[ip][w] += static_cast<uint64_t>((pct / 100.0) * net);
    }
    return c;
}

// Every non-empty split must conserve value: shares + pool == 1, all finite [0,1].
static void CheckConserves(const RewardSplitResult& r)
{
    double sum = r.pool_share;
    BOOST_CHECK(std::isfinite(r.pool_share));
    BOOST_CHECK(r.pool_share >= -1e-12 && r.pool_share <= 1.0 + 1e-9);
    for (const auto& [w, s] : r.wallet_share) {
        BOOST_CHECK(std::isfinite(s));
        BOOST_CHECK(s >= -1e-12 && s <= 1.0 + 1e-9);
        sum += s;
    }
    BOOST_CHECK_CLOSE(sum, 1.0, 1e-6);
}

// Empty input -> no shares, no pool (nothing to divide).
BOOST_AUTO_TEST_CASE(empty_input)
{
    RewardSplitResult r = ComputeRewardSplit({}, 50.0, 50.0);
    BOOST_CHECK(r.wallet_share.empty());
    BOOST_CHECK_EQUAL(r.pool_share, 0.0);
}

// Two honest miners at 50/50 on one chain: each gets half, pool gets nothing.
BOOST_AUTO_TEST_CASE(two_miners_5050)
{
    ChainRewardInput c = MakeChain({{"1.1.1.1", "A", 50.0}, {"2.2.2.2", "B", 50.0}});
    RewardSplitResult r = ComputeRewardSplit({c}, 50.0, 50.0);
    CheckConserves(r);
    BOOST_CHECK_CLOSE(r.wallet_share["A"], 0.5, 1e-6);
    BOOST_CHECK_CLOSE(r.wallet_share["B"], 0.5, 1e-6);
    BOOST_CHECK_SMALL(r.pool_share, 1e-9);
}

// A single miner mining 100% of a chain is capped at 50%: the OTHER 50% is
// confiscated to the pool, NOT kept by the miner.
BOOST_AUTO_TEST_CASE(single_miner_100pct_excess_to_pool)
{
    ChainRewardInput c = MakeChain({{"1.1.1.1", "A", 100.0}});
    RewardSplitResult r = ComputeRewardSplit({c}, 50.0, 50.0);
    CheckConserves(r);
    BOOST_CHECK_CLOSE(r.wallet_share["A"], 0.5, 1e-6);
    BOOST_CHECK_CLOSE(r.pool_share, 0.5, 1e-6);
}

// The confiscated excess must NOT inflate other miners' shares. Miner A at 90%
// (capped to 50) and miner B at 10% on the same chain: B still gets exactly its
// raw 10/100, and the excess (40) goes to the pool — B does not benefit from A's
// over-contribution.
BOOST_AUTO_TEST_CASE(excess_not_redistributed_to_others)
{
    ChainRewardInput c = MakeChain({{"1.1.1.1", "A", 90.0}, {"2.2.2.2", "B", 10.0}});
    RewardSplitResult r = ComputeRewardSplit({c}, 50.0, 50.0);
    CheckConserves(r);
    // denom_raw = 90 + 10 = 100; A credited 50, B credited 10.
    BOOST_CHECK_CLOSE(r.wallet_share["A"], 0.50, 1e-6);
    BOOST_CHECK_CLOSE(r.wallet_share["B"], 0.10, 1e-6);
    BOOST_CHECK_CLOSE(r.pool_share, 0.40, 1e-6);
}

// Sybil: one IP splits 80% across two wallets (40% each) to dodge the per-wallet
// 50% cap. The per-IP aggregate cap catches it and confiscates the excess.
BOOST_AUTO_TEST_CASE(sybil_ip_split_capped)
{
    ChainRewardInput c = MakeChain({{"9.9.9.9", "S1", 40.0}, {"9.9.9.9", "S2", 40.0}});
    RewardSplitResult r = ComputeRewardSplit({c}, 50.0, 50.0);
    CheckConserves(r);
    // denom_raw = 80; each wallet-credited 40 (under 50), IP agg 80 > 50 ->
    // scale by 50/80 -> each 25. shares 25/80 = 0.3125; pool = (80-50)/80 = 0.375.
    BOOST_CHECK_CLOSE(r.wallet_share["S1"], 0.3125, 1e-6);
    BOOST_CHECK_CLOSE(r.wallet_share["S2"], 0.3125, 1e-6);
    BOOST_CHECK_CLOSE(r.pool_share, 0.375, 1e-6);
}

// With the IP cap disabled (0), the same sybil split is NOT caught: each wallet
// is under the per-wallet cap, so they keep everything and the pool gets nothing.
// (Demonstrates the knob works and why it defaults on.)
BOOST_AUTO_TEST_CASE(sybil_evades_when_ip_cap_disabled)
{
    ChainRewardInput c = MakeChain({{"9.9.9.9", "S1", 40.0}, {"9.9.9.9", "S2", 40.0}});
    RewardSplitResult r = ComputeRewardSplit({c}, 50.0, 0.0);
    CheckConserves(r);
    BOOST_CHECK_CLOSE(r.wallet_share["S1"], 0.5, 1e-6);
    BOOST_CHECK_CLOSE(r.wallet_share["S2"], 0.5, 1e-6);
    BOOST_CHECK_SMALL(r.pool_share, 1e-9);
}

// Two independent wallets from the SAME IP, each at 20% (agg 40% < 50%): a
// legitimate shared-IP case must NOT be penalised.
BOOST_AUTO_TEST_CASE(shared_ip_under_threshold_ok)
{
    ChainRewardInput c = MakeChain({{"5.5.5.5", "A", 20.0}, {"5.5.5.5", "B", 20.0},
                                    {"6.6.6.6", "C", 60.0}});
    RewardSplitResult r = ComputeRewardSplit({c}, 50.0, 50.0);
    CheckConserves(r);
    // denom_raw = 100; A=20, B=20 (IP agg 40 < 50, untouched), C capped 50, C excess 10 -> pool.
    BOOST_CHECK_CLOSE(r.wallet_share["A"], 0.20, 1e-6);
    BOOST_CHECK_CLOSE(r.wallet_share["B"], 0.20, 1e-6);
    BOOST_CHECK_CLOSE(r.wallet_share["C"], 0.50, 1e-6);
    BOOST_CHECK_CLOSE(r.pool_share, 0.10, 1e-6);
}

// Multi-chain: contributions from different chains sum into the denominator, and
// each chain's cap applies independently.
BOOST_AUTO_TEST_CASE(multi_chain_independent_caps)
{
    ChainRewardInput x = MakeChain({{"1.1.1.1", "A", 100.0}});                 // A: 100% of X -> capped 50
    ChainRewardInput y = MakeChain({{"2.2.2.2", "B", 50.0}, {"3.3.3.3", "C", 50.0}}); // B,C: 50/50 of Y
    RewardSplitResult r = ComputeRewardSplit({x, y}, 50.0, 50.0);
    CheckConserves(r);
    // denom_raw = 100 (X) + 100 (Y) = 200. A credited 50, B 50, C 50, sum 150.
    // shares: A 50/200=.25, B .25, C .25; pool (200-150)/200 = .25.
    BOOST_CHECK_CLOSE(r.wallet_share["A"], 0.25, 1e-6);
    BOOST_CHECK_CLOSE(r.wallet_share["B"], 0.25, 1e-6);
    BOOST_CHECK_CLOSE(r.wallet_share["C"], 0.25, 1e-6);
    BOOST_CHECK_CLOSE(r.pool_share, 0.25, 1e-6);
}

// A wallet mining the same chain from TWO IPs, 30% + 30% = 60% total. The
// per-wallet cap (50) applies to its 60% total; the credited 50 is attributed
// pro-rata to the two IPs (25 each), neither IP over 50 -> no extra IP cut.
BOOST_AUTO_TEST_CASE(wallet_across_two_ips_wallet_cap)
{
    ChainRewardInput c = MakeChain({{"1.1.1.1", "A", 30.0}, {"2.2.2.2", "A", 30.0},
                                    {"3.3.3.3", "B", 40.0}});
    RewardSplitResult r = ComputeRewardSplit({c}, 50.0, 50.0);
    CheckConserves(r);
    // denom_raw = 60 + 40 = 100; A credited 50 (wallet cap), B 40. pool = 10.
    BOOST_CHECK_CLOSE(r.wallet_share["A"], 0.50, 1e-6);
    BOOST_CHECK_CLOSE(r.wallet_share["B"], 0.40, 1e-6);
    BOOST_CHECK_CLOSE(r.pool_share, 0.10, 1e-6);
}

// network_hashrate == 0 falls back to pool_hashrate for the denominator so
// contributions still score (fair, functional) instead of vanishing.
BOOST_AUTO_TEST_CASE(pool_hashrate_fallback)
{
    ChainRewardInput c;
    c.network_hashrate = 0;
    c.pool_hashrate = 1000;
    c.ip_wallet_hashrates["1.1.1.1"]["A"] = 300;  // 30% of pool
    c.ip_wallet_hashrates["2.2.2.2"]["B"] = 700;  // 70% of pool -> capped 50
    RewardSplitResult r = ComputeRewardSplit({c}, 50.0, 50.0);
    CheckConserves(r);
    // denom_raw = 30 + 70 = 100; A 30, B capped 50, pool 20.
    BOOST_CHECK_CLOSE(r.wallet_share["A"], 0.30, 1e-6);
    BOOST_CHECK_CLOSE(r.wallet_share["B"], 0.50, 1e-6);
    BOOST_CHECK_CLOSE(r.pool_share, 0.20, 1e-6);
}

// Unknown IP ("") is never subject to the IP cap (can't attribute a source), but
// still gets the per-wallet cap.
BOOST_AUTO_TEST_CASE(unknown_ip_not_ip_capped)
{
    ChainRewardInput c = MakeChain({{"", "A", 40.0}, {"", "B", 40.0}});
    RewardSplitResult r = ComputeRewardSplit({c}, 50.0, 50.0);
    CheckConserves(r);
    // Both under the per-wallet cap; unknown IP is not aggregated -> no pool cut.
    BOOST_CHECK_CLOSE(r.wallet_share["A"], 0.5, 1e-6);
    BOOST_CHECK_CLOSE(r.wallet_share["B"], 0.5, 1e-6);
    BOOST_CHECK_SMALL(r.pool_share, 1e-9);
}

// Determinism: identical inputs always yield identical output (required — the
// payout coinbase is frozen into the AuxPoW job and must match at submit time).
BOOST_AUTO_TEST_CASE(deterministic)
{
    ChainRewardInput c = MakeChain({{"9.9.9.9", "S1", 40.0}, {"9.9.9.9", "S2", 40.0},
                                    {"1.2.3.4", "H", 20.0}});
    RewardSplitResult a = ComputeRewardSplit({c}, 50.0, 50.0);
    RewardSplitResult b = ComputeRewardSplit({c}, 50.0, 50.0);
    BOOST_CHECK_EQUAL(a.pool_share, b.pool_share);
    for (const auto& [w, s] : a.wallet_share) {
        BOOST_CHECK_EQUAL(s, b.wallet_share.at(w));
    }
}

BOOST_AUTO_TEST_SUITE_END()
