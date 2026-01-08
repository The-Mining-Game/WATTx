// Copyright (c) 2025 The WATTx Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <rpc/server.h>
#include <rpc/util.h>
#include <node/gapcoin_miner.h>
#include <node/context.h>
#include <chainparams.h>
#include <consensus/gapcoin_pow.h>
#include <univalue.h>
#include <validation.h>

#include <memory>

using node::GapcoinMiner;
using node::GapcoinMiningResult;
using node::GapcoinMiningStats;
using node::GpuBackend;
using node::NodeContext;

// Global miner instance (optional - can be owned by NodeContext instead)
static std::unique_ptr<GapcoinMiner> g_gapcoin_miner;

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
            unsigned int nThreads = 0;
            if (!request.params[0].isNull()) {
                nThreads = request.params[0].getInt<int>();
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
            double targetMerit = GAPCOIN_INITIAL_DIFFICULTY;  // TODO: Get from chain state

            // Create dummy block header for now - in production this would come from getblocktemplate
            CBlockHeader block;
            block.nTime = GetTime();

            bool started = g_gapcoin_miner->StartMining(block, targetMerit,
                [](const GapcoinMiningResult& result) {
                    if (result.found) {
                        LogPrintf("Gapcoin solution found! Gap=%d, Merit=%.4f\n",
                                  result.nGapSize, result.merit);
                    }
                });

            UniValue obj(UniValue::VOBJ);
            obj.pushKV("started", started);
            obj.pushKV("threads", static_cast<int>(nThreads == 0 ? std::thread::hardware_concurrency() : nThreads));
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
            if (!g_gapcoin_miner) {
                return false;
            }

            g_gapcoin_miner->StopMining();
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

            if (!g_gapcoin_miner) {
                obj.pushKV("mining", false);
                obj.pushKV("threads", 0);
                obj.pushKV("shift", 0);
                obj.pushKV("primes_checked", 0);
                obj.pushKV("gaps_found", 0);
                obj.pushKV("best_merit", 0.0);
                obj.pushKV("sieve_cycles", 0);
                obj.pushKV("gpu_enabled", false);
                obj.pushKV("gpu_backend", "none");
                return obj;
            }

            GapcoinMiningStats stats = g_gapcoin_miner->GetStats();

            obj.pushKV("mining", g_gapcoin_miner->IsMining());
            obj.pushKV("threads", static_cast<int>(std::thread::hardware_concurrency()));
            obj.pushKV("shift", static_cast<int>(g_gapcoin_miner->GetShift()));
            obj.pushKV("primes_checked", static_cast<int64_t>(stats.primesChecked));
            obj.pushKV("gaps_found", static_cast<int64_t>(stats.gapsFound));
            obj.pushKV("best_merit", stats.bestMerit);
            obj.pushKV("sieve_cycles", static_cast<int64_t>(stats.sieveCycles));
            obj.pushKV("gpu_enabled", false);  // TODO: Get from miner
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
