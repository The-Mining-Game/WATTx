// Copyright (c) 2025 The WATTx Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <rpc/server.h>
#include <rpc/server_util.h>
#include <rpc/util.h>
#include <rpc/blockchain.h>
#include <node/gapcoin_miner.h>
#include <node/context.h>
#include <node/miner.h>
#include <chainparams.h>
#include <consensus/gapcoin_pow.h>
#include <univalue.h>
#include <validation.h>
#include <key_io.h>
#include <script/script.h>
#include <pow.h>
#include <primitives/block.h>
#include <consensus/merkle.h>

#include <memory>
#include <thread>
#include <atomic>

using node::GapcoinMiner;
using node::GapcoinMiningResult;
using node::GapcoinMiningStats;
using node::GpuBackend;
using node::NodeContext;
using node::BlockAssembler;
using node::CBlockTemplate;

// Global miner instance
static std::unique_ptr<GapcoinMiner> g_gapcoin_miner;
static std::atomic<bool> g_mining_active{false};
static std::thread g_mining_thread;
static ChainstateManager* g_chainman = nullptr;
static std::atomic<uint64_t> g_blocks_found{0};

// Mining loop that creates blocks and submits when solution found
static void MiningLoop(ChainstateManager& chainman, const CScript& coinbase_script, uint32_t nShift, double targetMerit)
{
    LogPrintf("GapcoinMiner: Mining loop started with coinbase script size=%zu\n", coinbase_script.size());

    try {
        while (g_mining_active) {
            // Create a new block template
            std::unique_ptr<CBlockTemplate> pblocktemplate;
            {
                LOCK(cs_main);
                BlockAssembler::Options options;
                options.coinbase_output_script = coinbase_script;  // Set the coinbase output script!
                pblocktemplate = BlockAssembler(chainman.ActiveChainstate(), nullptr, options)
                    .CreateNewBlock(false);  // false = PoW block, not PoS
            }

            if (!pblocktemplate) {
                LogPrintf("GapcoinMiner: Failed to create block template\n");
                UninterruptibleSleep(std::chrono::milliseconds(1000));
                continue;
            }

            CBlock* pblock = &pblocktemplate->block;

            // Log current merkle root (already computed by BlockAssembler)
            LogPrintf("GapcoinMiner: Block template created, MerkleRoot=%s, nBits=%08x\n",
                     pblock->hashMerkleRoot.ToString(), pblock->nBits);

            // Set Gapcoin PoW fields (these don't affect merkle root)
            pblock->nShift = nShift;
            pblock->nAdder.SetNull();
            pblock->nGapSize = 0;

            // Mine this block template
            bool blockFound = false;
            uint32_t startTime = GetTime();

            // Get target from nBits
            arith_uint256 hashTarget = arith_uint256().SetCompact(pblock->nBits);

            // Try to find a solution for up to 60 seconds, then refresh template
            while (g_mining_active && !blockFound && (GetTime() - startTime < 60)) {
                // Update time in header (doesn't affect merkle root)
                pblock->nTime = GetTime();

                // Simple nonce-based mining (standard PoW)
                for (uint32_t nonce = 0; nonce < 0x1000000 && g_mining_active && !blockFound; nonce++) {
                    pblock->nNonce = nonce;
                    uint256 hash = pblock->GetHash();

                    if (UintToArith256(hash) <= hashTarget) {
                        // Found a valid PoW!
                        LogPrintf("GapcoinMiner: Found valid PoW! Hash=%s, Nonce=%u, Target=%s\n",
                                 hash.ToString(), nonce, hashTarget.ToString());

                        // DO NOT recalculate merkle root - it's already correct from BlockAssembler
                        // Modifying it would change the block hash and invalidate our PoW

                        // Submit the block
                        std::shared_ptr<const CBlock> shared_pblock = std::make_shared<const CBlock>(*pblock);
                        bool fNewBlock = false;

                        LogPrintf("GapcoinMiner: Submitting block with MerkleRoot=%s\n",
                                 pblock->hashMerkleRoot.ToString());

                        if (chainman.ProcessNewBlock(shared_pblock, true, true, &fNewBlock)) {
                            if (fNewBlock) {
                                g_blocks_found++;
                                LogPrintf("GapcoinMiner: Block ACCEPTED! Height=%d, Hash=%s\n",
                                         chainman.ActiveChain().Height(), hash.ToString());
                            } else {
                                LogPrintf("GapcoinMiner: Block processed but not new (duplicate?)\n");
                            }
                            blockFound = true;
                        } else {
                            LogPrintf("GapcoinMiner: Block REJECTED by ProcessNewBlock\n");
                            // Don't break - try next nonce in case of timing issue
                        }
                        break;
                    }
                }

                // Small sleep to prevent 100% CPU when not finding blocks quickly
                if (!blockFound) {
                    UninterruptibleSleep(std::chrono::milliseconds(1));
                }
            }

            if (!blockFound && g_mining_active) {
                LogPrintf("GapcoinMiner: Template expired, creating new one\n");
            }
        }
    } catch (const std::exception& e) {
        LogPrintf("GapcoinMiner: Exception in mining loop: %s\n", e.what());
    } catch (...) {
        LogPrintf("GapcoinMiner: Unknown exception in mining loop\n");
    }

    LogPrintf("GapcoinMiner: Mining loop stopped\n");
}

static RPCHelpMan startgapcoinmining()
{
    return RPCHelpMan{"startgapcoinmining",
        "\nStart Gapcoin prime gap mining.\n",
        {
            {"threads", RPCArg::Type::NUM, RPCArg::Default{0}, "Number of mining threads (0 = auto-detect)"},
            {"shift", RPCArg::Type::NUM, RPCArg::Default{25}, "Shift value for prime magnitude (14-65536)"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::BOOL, "started", "Whether mining was started"},
                {RPCResult::Type::NUM, "threads", "Number of mining threads"},
                {RPCResult::Type::NUM, "shift", "Shift value"},
            }
        },
        RPCExamples{
            HelpExampleCli("startgapcoinmining", "4 25")
            + HelpExampleRpc("startgapcoinmining", "4, 25")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            NodeContext& node = EnsureAnyNodeContext(request.context);
            ChainstateManager& chainman = EnsureChainman(node);

            if (g_mining_active) {
                throw JSONRPCError(RPC_MISC_ERROR, "Mining is already active. Stop it first with stopgapcoinmining.");
            }

            unsigned int nThreads = 0;
            if (!request.params[0].isNull()) {
                nThreads = request.params[0].getInt<int>();
            }
            if (nThreads == 0) {
                nThreads = std::thread::hardware_concurrency();
            }

            uint32_t nShift = 25;
            if (!request.params[1].isNull()) {
                nShift = request.params[1].getInt<int>();
                if (nShift < GAPCOIN_SHIFT_MIN || nShift > GAPCOIN_SHIFT_MAX) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER,
                        strprintf("Shift must be between %d and %d", GAPCOIN_SHIFT_MIN, GAPCOIN_SHIFT_MAX));
                }
            }

            // Create miner if not exists
            if (!g_gapcoin_miner) {
                g_gapcoin_miner = std::make_unique<GapcoinMiner>(nThreads);
            }

            g_gapcoin_miner->SetShift(nShift);

            // Get target merit from current difficulty
            double targetMerit = GAPCOIN_INITIAL_DIFFICULTY;

            // Get a coinbase address - use a dummy script for now
            // In production, this would come from wallet or RPC parameter
            CScript coinbase_script;

            // Try to get an address from the wallet via RPC
            try {
                // Create a simple OP_TRUE script as fallback (anyone can spend - for testing)
                // In production, this should be a proper address
                coinbase_script = CScript() << OP_TRUE;

                // Better approach: generate a proper P2PKH script
                // For now we'll use the chainparams genesis coinbase
            } catch (...) {
                coinbase_script = CScript() << OP_TRUE;
            }

            // Store chainman pointer for mining thread
            g_chainman = &chainman;

            // Start the Gapcoin miner threads for gap finding
            CBlockHeader dummyHeader;
            dummyHeader.nTime = GetTime();
            g_gapcoin_miner->StartMining(dummyHeader, targetMerit,
                [](const GapcoinMiningResult& result) {
                    if (result.found) {
                        LogPrintf("Gapcoin gap found! Gap=%d, Merit=%.4f\n",
                                  result.nGapSize, result.merit);
                    }
                });

            // Start the mining loop thread
            g_mining_active = true;
            g_mining_thread = std::thread(MiningLoop, std::ref(chainman), coinbase_script, nShift, targetMerit);

            UniValue obj(UniValue::VOBJ);
            obj.pushKV("started", true);
            obj.pushKV("threads", static_cast<int>(nThreads));
            obj.pushKV("shift", static_cast<int>(nShift));

            return obj;
        },
    };
}

static RPCHelpMan stopgapcoinmining()
{
    return RPCHelpMan{"stopgapcoinmining",
        "\nStop Gapcoin prime gap mining.\n",
        {},
        RPCResult{
            RPCResult::Type::BOOL, "", "Whether mining was stopped"
        },
        RPCExamples{
            HelpExampleCli("stopgapcoinmining", "")
            + HelpExampleRpc("stopgapcoinmining", "")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            if (!g_mining_active) {
                return false;
            }

            LogPrintf("GapcoinMiner: Stopping mining...\n");

            // Stop the mining loop first
            g_mining_active = false;

            // Stop the Gapcoin miner
            if (g_gapcoin_miner) {
                try {
                    g_gapcoin_miner->StopMining();
                } catch (...) {
                    LogPrintf("GapcoinMiner: Exception while stopping miner\n");
                }
            }

            // Wait for mining thread to finish with timeout
            if (g_mining_thread.joinable()) {
                try {
                    g_mining_thread.join();
                } catch (const std::exception& e) {
                    LogPrintf("GapcoinMiner: Exception joining thread: %s\n", e.what());
                } catch (...) {
                    LogPrintf("GapcoinMiner: Unknown exception joining thread\n");
                }
            }

            LogPrintf("GapcoinMiner: Mining stopped\n");
            return true;
        },
    };
}

static RPCHelpMan getgapcoinmininginfo()
{
    return RPCHelpMan{"getgapcoinmininginfo",
        "\nGet Gapcoin mining statistics.\n",
        {},
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::BOOL, "mining", "Whether mining is active"},
                {RPCResult::Type::NUM, "threads", "Number of mining threads"},
                {RPCResult::Type::NUM, "shift", "Current shift value"},
                {RPCResult::Type::NUM, "primes_checked", "Number of primes checked"},
                {RPCResult::Type::NUM, "gaps_found", "Number of gaps found"},
                {RPCResult::Type::NUM, "best_merit", "Best merit found"},
                {RPCResult::Type::NUM, "sieve_cycles", "Number of sieve cycles"},
                {RPCResult::Type::NUM, "blocks_found", "Number of blocks found"},
                {RPCResult::Type::BOOL, "gpu_enabled", "Whether GPU mining is enabled"},
                {RPCResult::Type::STR, "gpu_backend", "GPU backend (none, opencl, cuda)"},
            }
        },
        RPCExamples{
            HelpExampleCli("getgapcoinmininginfo", "")
            + HelpExampleRpc("getgapcoinmininginfo", "")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            UniValue obj(UniValue::VOBJ);

            obj.pushKV("mining", g_mining_active.load());

            if (!g_gapcoin_miner) {
                obj.pushKV("threads", 0);
                obj.pushKV("shift", 0);
                obj.pushKV("primes_checked", 0);
                obj.pushKV("gaps_found", 0);
                obj.pushKV("best_merit", 0.0);
                obj.pushKV("sieve_cycles", 0);
                obj.pushKV("blocks_found", static_cast<int64_t>(g_blocks_found.load()));
                obj.pushKV("gpu_enabled", false);
                obj.pushKV("gpu_backend", "none");
                return obj;
            }

            GapcoinMiningStats stats = g_gapcoin_miner->GetStats();

            obj.pushKV("threads", static_cast<int>(std::thread::hardware_concurrency()));
            obj.pushKV("shift", static_cast<int>(g_gapcoin_miner->GetShift()));
            obj.pushKV("primes_checked", static_cast<int64_t>(stats.primesChecked));
            obj.pushKV("gaps_found", static_cast<int64_t>(stats.gapsFound));
            obj.pushKV("best_merit", stats.bestMerit);
            obj.pushKV("sieve_cycles", static_cast<int64_t>(stats.sieveCycles));
            obj.pushKV("blocks_found", static_cast<int64_t>(g_blocks_found.load()));
            obj.pushKV("gpu_enabled", false);
            obj.pushKV("gpu_backend", "none");

            return obj;
        },
    };
}

static RPCHelpMan listgpudevices()
{
    return RPCHelpMan{"listgpudevices",
        "\nList available GPU devices for mining.\n",
        {
            {"backend", RPCArg::Type::STR, RPCArg::Default{"opencl"}, "GPU backend: opencl or cuda"},
        },
        RPCResult{
            RPCResult::Type::ARR, "", "",
            {
                {RPCResult::Type::OBJ, "", "",
                {
                    {RPCResult::Type::NUM, "id", "Device ID"},
                    {RPCResult::Type::STR, "name", "Device name"},
                }},
            }
        },
        RPCExamples{
            HelpExampleCli("listgpudevices", "opencl")
            + HelpExampleRpc("listgpudevices", "\"opencl\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            std::string backendStr = "opencl";
            if (!request.params[0].isNull()) {
                backendStr = request.params[0].get_str();
            }

            GpuBackend backend = GpuBackend::NONE;
            if (backendStr == "opencl") {
                backend = GpuBackend::OPENCL;
            } else if (backendStr == "cuda") {
                backend = GpuBackend::CUDA;
            } else {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid backend. Use 'opencl' or 'cuda'");
            }

            auto devices = GapcoinMiner::GetGpuDevices(backend);

            UniValue arr(UniValue::VARR);
            for (size_t i = 0; i < devices.size(); ++i) {
                UniValue obj(UniValue::VOBJ);
                obj.pushKV("id", static_cast<int>(i));
                obj.pushKV("name", devices[i]);
                arr.push_back(obj);
            }

            return arr;
        },
    };
}

static RPCHelpMan enablegpumining()
{
    return RPCHelpMan{"enablegpumining",
        "\nEnable GPU mining.\n",
        {
            {"backend", RPCArg::Type::STR, RPCArg::Optional::NO, "GPU backend: opencl or cuda"},
            {"device_id", RPCArg::Type::NUM, RPCArg::Default{0}, "GPU device ID"},
        },
        RPCResult{
            RPCResult::Type::BOOL, "", "Whether GPU was enabled successfully"
        },
        RPCExamples{
            HelpExampleCli("enablegpumining", "opencl 0")
            + HelpExampleRpc("enablegpumining", "\"opencl\", 0")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            std::string backendStr = request.params[0].get_str();

            GpuBackend backend = GpuBackend::NONE;
            if (backendStr == "opencl") {
                backend = GpuBackend::OPENCL;
            } else if (backendStr == "cuda") {
                backend = GpuBackend::CUDA;
            } else {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid backend. Use 'opencl' or 'cuda'");
            }

            int deviceId = 0;
            if (!request.params[1].isNull()) {
                deviceId = request.params[1].getInt<int>();
            }

            if (!g_gapcoin_miner) {
                g_gapcoin_miner = std::make_unique<GapcoinMiner>();
            }

            return g_gapcoin_miner->EnableGpu(backend, deviceId);
        },
    };
}

void RegisterGapcoinMiningRPCCommands(CRPCTable& t)
{
    static const CRPCCommand commands[]{
        {"mining", &startgapcoinmining},
        {"mining", &stopgapcoinmining},
        {"mining", &getgapcoinmininginfo},
        {"mining", &listgpudevices},
        {"mining", &enablegpumining},
    };
    for (const auto& c : commands) {
        t.appendCommand(c.name, &c);
    }
}
