// Copyright (c) 2024-2026 The WATTx Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <rpc/server.h>
#include <rpc/server_util.h>
#include <rpc/util.h>
#include <stratum/stratum_server.h>
#include <stratum/merged_stratum.h>
#include <stratum/multi_merged_stratum.h>
#include <stratum/parent_chain.h>
#include <interfaces/mining.h>
#include <node/context.h>
#include <univalue.h>

using node::NodeContext;

static RPCHelpMan startstratum()
{
    return RPCHelpMan{"startstratum",
        "\nStart the stratum mining server for XMRig.\n",
        {
            {"port", RPCArg::Type::NUM, RPCArg::Default{3335}, "Port to listen on"},
            {"address", RPCArg::Type::STR, RPCArg::Default{"0.0.0.0"}, "Address to bind to"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::BOOL, "success", "Whether server started successfully"},
                {RPCResult::Type::NUM, "port", "Port the server is listening on"},
            }
        },
        RPCExamples{
            HelpExampleCli("startstratum", "")
            + HelpExampleCli("startstratum", "3335")
            + HelpExampleCli("startstratum", "3335 \"127.0.0.1\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            NodeContext& node = EnsureAnyNodeContext(request.context);

            stratum::StratumConfig config;
            config.port = request.params[0].isNull() ? 3335 : request.params[0].getInt<int>();
            config.bind_address = request.params[1].isNull() ? "0.0.0.0" : request.params[1].get_str();

            stratum::StratumServer& server = stratum::GetStratumServer();

            if (server.IsRunning()) {
                throw JSONRPCError(RPC_MISC_ERROR, "Stratum server already running");
            }

            bool success = server.Start(config, node.mining.get());

            UniValue result(UniValue::VOBJ);
            result.pushKV("success", success);
            result.pushKV("port", (int)server.GetPort());
            return result;
        },
    };
}

static RPCHelpMan stopstratum()
{
    return RPCHelpMan{"stopstratum",
        "\nStop the stratum mining server.\n",
        {},
        RPCResult{
            RPCResult::Type::BOOL, "", "Always returns true"
        },
        RPCExamples{
            HelpExampleCli("stopstratum", "")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            stratum::StratumServer& server = stratum::GetStratumServer();
            server.Stop();
            return true;
        },
    };
}

static RPCHelpMan getstratuminfo()
{
    return RPCHelpMan{"getstratuminfo",
        "\nGet information about the stratum server.\n",
        {},
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::BOOL, "running", "Whether the server is running"},
                {RPCResult::Type::NUM, "port", "Port the server is listening on"},
                {RPCResult::Type::NUM, "clients", "Number of connected miners"},
                {RPCResult::Type::NUM, "shares_accepted", "Total accepted shares"},
                {RPCResult::Type::NUM, "shares_rejected", "Total rejected shares"},
                {RPCResult::Type::NUM, "blocks_found", "Total blocks found"},
            }
        },
        RPCExamples{
            HelpExampleCli("getstratuminfo", "")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            stratum::StratumServer& server = stratum::GetStratumServer();

            UniValue result(UniValue::VOBJ);
            result.pushKV("running", server.IsRunning());
            result.pushKV("port", (int)server.GetPort());
            result.pushKV("clients", (int)server.GetClientCount());
            result.pushKV("shares_accepted", (uint64_t)server.GetTotalSharesAccepted());
            result.pushKV("shares_rejected", (uint64_t)server.GetTotalSharesRejected());
            result.pushKV("blocks_found", (uint64_t)server.GetBlocksFound());
            return result;
        },
    };
}

static RPCHelpMan startmergedstratum()
{
    return RPCHelpMan{"startmergedstratum",
        "\nStart the merged mining stratum server for mining WATTx via parent chains (e.g., Monero).\n",
        {
            {"port", RPCArg::Type::NUM, RPCArg::Default{3337}, "Port to listen on"},
            {"monero_host", RPCArg::Type::STR, RPCArg::Default{"127.0.0.1"}, "Monero daemon host"},
            {"monero_port", RPCArg::Type::NUM, RPCArg::Default{18081}, "Monero daemon port"},
            {"monero_wallet", RPCArg::Type::STR, RPCArg::Optional::NO, "Monero wallet address for block rewards"},
            {"wattx_wallet", RPCArg::Type::STR, RPCArg::Optional::NO, "WATTx wallet address for block rewards"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::BOOL, "success", "Whether server started successfully"},
                {RPCResult::Type::NUM, "port", "Port the server is listening on"},
            }
        },
        RPCExamples{
            HelpExampleCli("startmergedstratum", "3337 \"127.0.0.1\" 18081 \"4...MoneroAddr\" \"W...WATTxAddr\"")
            + HelpExampleRpc("startmergedstratum", "3337, \"127.0.0.1\", 18081, \"4...MoneroAddr\", \"W...WATTxAddr\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            NodeContext& node = EnsureAnyNodeContext(request.context);

            merged_stratum::MergedStratumConfig config;
            config.port = request.params[0].isNull() ? 3337 : request.params[0].getInt<int>();
            config.monero_daemon_host = request.params[1].isNull() ? "127.0.0.1" : request.params[1].get_str();
            config.monero_daemon_port = request.params[2].isNull() ? 18081 : request.params[2].getInt<int>();
            config.monero_wallet_address = request.params[3].get_str();
            config.wattx_wallet_address = request.params[4].get_str();

            merged_stratum::MergedStratumServer& server = merged_stratum::GetMergedStratumServer();

            if (server.IsRunning()) {
                throw JSONRPCError(RPC_MISC_ERROR, "Merged stratum server already running");
            }

            bool success = server.Start(config, node.mining.get());

            UniValue result(UniValue::VOBJ);
            result.pushKV("success", success);
            result.pushKV("port", config.port);
            return result;
        },
    };
}

static RPCHelpMan stopmergedstratum()
{
    return RPCHelpMan{"stopmergedstratum",
        "\nStop the merged mining stratum server.\n",
        {},
        RPCResult{
            RPCResult::Type::BOOL, "", "Always returns true"
        },
        RPCExamples{
            HelpExampleCli("stopmergedstratum", "")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            merged_stratum::MergedStratumServer& server = merged_stratum::GetMergedStratumServer();
            server.Stop();
            return true;
        },
    };
}

static RPCHelpMan startmultimergedstratum()
{
    return RPCHelpMan{"startmultimergedstratum",
        "\nStart merged mining stratum servers for all supported parent-chain algorithms.\n"
        "Each algorithm gets its own port starting at base_port.\n",
        {
            {"bind_address", RPCArg::Type::STR, RPCArg::Default{"0.0.0.0"}, "Address to bind to"},
            {"base_port",    RPCArg::Type::NUM, RPCArg::Default{3333},       "Base port (each algo gets base_port + algo_index)"},
            {"parent_chains", RPCArg::Type::ARR, RPCArg::Optional::NO, "Array of parent chain configs",
                {
                    {"", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "Parent chain",
                        {
                            {"name",     RPCArg::Type::STR, RPCArg::Optional::NO,  "Chain name (e.g. 'bitcoin', 'monero')"},
                            {"algo",     RPCArg::Type::STR, RPCArg::Optional::NO,  "Algorithm: sha256d|scrypt|ethash|randomx|equihash|x11|kheavyhash"},
                            {"host",     RPCArg::Type::STR, RPCArg::Default{"127.0.0.1"}, "Daemon host"},
                            {"port",     RPCArg::Type::NUM, RPCArg::Optional::NO,  "Daemon RPC port"},
                            {"user",     RPCArg::Type::STR, RPCArg::Default{""},   "RPC username"},
                            {"password", RPCArg::Type::STR, RPCArg::Default{""},   "RPC password"},
                            {"address",  RPCArg::Type::STR, RPCArg::Default{""},   "Pool wallet address on parent chain"},
                            {"chain_id", RPCArg::Type::NUM, RPCArg::Default{0},    "Chain ID for replay protection"},
                            {"share_difficulty", RPCArg::Type::NUM, RPCArg::Default{0}, "Per-chain share difficulty override (0 = pool-global)"},
                            {"share_nbits", RPCArg::Type::NUM, RPCArg::Default{0}, "Per-chain share target as nBits compact, overrides share_difficulty (0 = pool-global)"},
                            {"equihash_n", RPCArg::Type::NUM, RPCArg::Default{0}, "Equihash N parameter override (with equihash_k; e.g. 144,5 mainnet BitcoinZ, 48,5 regtest)"},
                            {"equihash_k", RPCArg::Type::NUM, RPCArg::Default{0}, "Equihash K parameter override (with equihash_n)"},
                        }
                    },
                }
            },
            {"wattx_wallet", RPCArg::Type::STR, RPCArg::Optional::NO, "Default WATTx address for block rewards"},
            {"share_difficulty", RPCArg::Type::NUM, RPCArg::Default{10000}, "Pool share difficulty (lower = easier shares; set low for regtest)"},
            {"share_nbits", RPCArg::Type::NUM, RPCArg::Default{0}, "Explicit share target as nBits compact (0 = derive from share_difficulty; testing knob, e.g. 522190847 = 0x1f0fffff for regtest)"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::BOOL, "success",    "Whether server started successfully"},
                {RPCResult::Type::NUM,  "base_port",  "Base port"},
                {RPCResult::Type::NUM,  "chain_count","Number of parent chains configured"},
            }
        },
        RPCExamples{
            HelpExampleCli("startmultimergedstratum",
                "\"0.0.0.0\" 3333 "
                "'[{\"name\":\"monero\",\"algo\":\"randomx\",\"host\":\"127.0.0.1\",\"port\":18081,\"user\":\"\",\"password\":\"\",\"address\":\"4...\",\"chain_id\":1}]' "
                "\"WATTxAddr\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            NodeContext& node = EnsureAnyNodeContext(request.context);

            merged_stratum::MultiMergedConfig config;
            config.bind_address     = request.params[0].isNull() ? "0.0.0.0" : request.params[0].get_str();
            config.base_port        = request.params[1].isNull() ? 3333       : request.params[1].getInt<int>();
            config.wattx_wallet_address = request.params[3].get_str();
            if (request.params.size() > 4 && !request.params[4].isNull()) {
                config.share_difficulty = static_cast<uint64_t>(request.params[4].getInt<int64_t>());
            }
            if (request.params.size() > 5 && !request.params[5].isNull()) {
                config.share_nbits = static_cast<uint32_t>(request.params[5].getInt<int64_t>());
            }

            static const std::unordered_map<std::string, merged_stratum::ParentChainAlgo> algoMap{
                {"sha256d",    merged_stratum::ParentChainAlgo::SHA256D},
                {"scrypt",     merged_stratum::ParentChainAlgo::SCRYPT},
                {"ethash",     merged_stratum::ParentChainAlgo::ETHASH},
                {"randomx",    merged_stratum::ParentChainAlgo::RANDOMX},
                {"equihash",   merged_stratum::ParentChainAlgo::EQUIHASH},
                {"x11",        merged_stratum::ParentChainAlgo::X11},
                {"kheavyhash", merged_stratum::ParentChainAlgo::KHEAVYHASH},
            };

            const UniValue& chains = request.params[2].get_array();
            for (size_t i = 0; i < chains.size(); ++i) {
                const UniValue& c = chains[i];
                merged_stratum::ParentChainConfig pc;
                pc.name     = c["name"].get_str();
                pc.daemon_host     = c.exists("host")     ? c["host"].get_str()           : "127.0.0.1";
                pc.daemon_port     = c.exists("port")     ? c["port"].getInt<int>()        : 0;
                pc.daemon_user     = c.exists("user")     ? c["user"].get_str()            : "";
                pc.daemon_password = c.exists("password") ? c["password"].get_str()        : "";
                pc.wallet_address  = c.exists("address")  ? c["address"].get_str()         : "";
                pc.chain_id        = c.exists("chain_id") ? c["chain_id"].getInt<int>()    : (int)i + 1;
                if (c.exists("share_difficulty")) {
                    pc.share_difficulty = static_cast<uint64_t>(c["share_difficulty"].getInt<int64_t>());
                }
                if (c.exists("share_nbits")) {
                    pc.share_nbits = static_cast<uint32_t>(c["share_nbits"].getInt<int64_t>());
                }
                if (c.exists("equihash_n")) {
                    pc.equihash_n = static_cast<uint32_t>(c["equihash_n"].getInt<int64_t>());
                }
                if (c.exists("equihash_k")) {
                    pc.equihash_k = static_cast<uint32_t>(c["equihash_k"].getInt<int64_t>());
                }

                std::string algoStr = c["algo"].get_str();
                auto it = algoMap.find(algoStr);
                if (it == algoMap.end()) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Unknown algo: " + algoStr);
                }
                pc.algo = it->second;
                config.parent_chains.push_back(pc);
            }

            merged_stratum::MultiMergedStratumServer& server = merged_stratum::GetMultiMergedStratumServer();
            if (server.IsRunning()) {
                throw JSONRPCError(RPC_MISC_ERROR, "Multi-merged stratum server already running");
            }

            bool success = server.Start(config, node.mining.get());

            UniValue result(UniValue::VOBJ);
            result.pushKV("success",     success);
            result.pushKV("base_port",   (int)config.base_port);
            result.pushKV("chain_count", (int)config.parent_chains.size());
            return result;
        },
    };
}

static RPCHelpMan stopsmultimergedstratum()
{
    return RPCHelpMan{"stopmultimergedstratum",
        "\nStop the multi-algorithm merged stratum server.\n",
        {},
        RPCResult{RPCResult::Type::BOOL, "", "Always returns true"},
        RPCExamples{HelpExampleCli("stopmultimergedstratum", "")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            merged_stratum::MultiMergedStratumServer& server = merged_stratum::GetMultiMergedStratumServer();
            server.Stop();
            return true;
        },
    };
}

static RPCHelpMan startbitcoinmergedstratum()
{
    return RPCHelpMan{"startbitcoinmergedstratum",
        "\nStart merged mining stratum server for Bitcoin/SHA256d parent chain.\n",
        {
            {"port", RPCArg::Type::NUM, RPCArg::Default{3338}, "Port to listen on"},
            {"bitcoin_host", RPCArg::Type::STR, RPCArg::Default{"127.0.0.1"}, "Bitcoin daemon host"},
            {"bitcoin_port", RPCArg::Type::NUM, RPCArg::Default{8332}, "Bitcoin RPC port"},
            {"bitcoin_user", RPCArg::Type::STR, RPCArg::Optional::NO, "Bitcoin RPC username"},
            {"bitcoin_pass", RPCArg::Type::STR, RPCArg::Optional::NO, "Bitcoin RPC password"},
            {"wattx_wallet", RPCArg::Type::STR, RPCArg::Optional::NO, "WATTx wallet address for block rewards"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::BOOL, "success", "Whether server started successfully"},
                {RPCResult::Type::NUM, "port", "Port the server is listening on"},
                {RPCResult::Type::STR, "chain", "Parent chain type"},
            }
        },
        RPCExamples{
            HelpExampleCli("startbitcoinmergedstratum", "3338 \"127.0.0.1\" 18332 \"btcuser\" \"btcpass\" \"WATTxAddr\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            NodeContext& node = EnsureAnyNodeContext(request.context);

            // Configure Bitcoin parent chain
            merged_stratum::ParentChainConfig btc_config;
            btc_config.name = "bitcoin";
            btc_config.chain_id = 1;
            btc_config.algo = merged_stratum::ParentChainAlgo::SHA256D;
            btc_config.daemon_host = request.params[1].isNull() ? "127.0.0.1" : request.params[1].get_str();
            btc_config.daemon_port = request.params[2].isNull() ? 8332 : request.params[2].getInt<int>();
            btc_config.daemon_user = request.params[3].get_str();
            btc_config.daemon_password = request.params[4].get_str();
            btc_config.wallet_address = "";  // Bitcoin doesn't need wallet for getblocktemplate

            // Configure multi-chain server
            merged_stratum::MultiMergedConfig config;
            config.base_port = request.params[0].isNull() ? 3338 : request.params[0].getInt<int>();
            config.wattx_wallet_address = request.params[5].get_str();
            config.parent_chains.push_back(btc_config);

            merged_stratum::MultiMergedStratumServer& server = merged_stratum::GetMultiMergedStratumServer();

            if (server.IsRunning()) {
                throw JSONRPCError(RPC_MISC_ERROR, "Multi-merged stratum server already running");
            }

            bool success = server.Start(config, node.mining.get());

            UniValue result(UniValue::VOBJ);
            result.pushKV("success", success);
            result.pushKV("port", (int)config.base_port);
            result.pushKV("chain", "bitcoin");
            return result;
        },
    };
}

static RPCHelpMan getmergeminingdashboard()
{
    return RPCHelpMan{"getmergeminingdashboard",
        "\nGet live merged mining dashboard stats for all configured algorithms.\n",
        {},
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::BOOL, "running", "Whether stratum server is running"},
                {RPCResult::Type::NUM,  "wtx_blocks_found", "WATTx blocks found via merged mining"},
                {RPCResult::Type::NUM,  "started_at", "Unix timestamp when server started"},
                {RPCResult::Type::ARR,  "algos",  "Per-algorithm stats", {{RPCResult::Type::OBJ, std::string{""}, std::string{""}, {}}}},
                {RPCResult::Type::ARR,  "miners", "Connected miners",     {{RPCResult::Type::OBJ, std::string{""}, std::string{""}, {}}}},
            }
        },
        RPCExamples{HelpExampleCli("getmergeminingdashboard", "")},
        [&](const RPCHelpMan&, const JSONRPCRequest&) -> UniValue
        {
            merged_stratum::MultiMergedStratumServer& srv = merged_stratum::GetMultiMergedStratumServer();
            auto d = srv.GetDashboard();

            UniValue result(UniValue::VOBJ);
            result.pushKV("running",          d.running);
            result.pushKV("wtx_blocks_found", (uint64_t)d.wtx_blocks_found);
            result.pushKV("started_at",       d.started_at);

            UniValue algos(UniValue::VARR);
            for (const auto& a : d.algos) {
                UniValue o(UniValue::VOBJ);
                o.pushKV("algo",                 a.algo);
                o.pushKV("chain_name",           a.chain_name);
                o.pushKV("port",                 (int)a.port);
                o.pushKV("miners_connected",     (uint64_t)a.miners_connected);
                o.pushKV("shares_accepted",      (uint64_t)a.shares_accepted);
                o.pushKV("shares_rejected",      (uint64_t)a.shares_rejected);
                o.pushKV("parent_blocks_found",  (uint64_t)a.parent_blocks_found);
                o.pushKV("daemon_host",          a.daemon_host);
                o.pushKV("daemon_port",          a.daemon_port);
                o.pushKV("wallet_address",       a.wallet_address);
                algos.push_back(o);
            }
            result.pushKV("algos", algos);

            UniValue miners(UniValue::VARR);
            for (const auto& m : d.miners) {
                UniValue o(UniValue::VOBJ);
                o.pushKV("client_id",       m.client_id);
                o.pushKV("login",           m.login);
                o.pushKV("algo",            m.algo);
                o.pushKV("shares_accepted", (uint64_t)m.shares_accepted);
                o.pushKV("shares_rejected", (uint64_t)m.shares_rejected);
                o.pushKV("wtx_blocks",      (uint64_t)m.wtx_blocks_found);
                o.pushKV("connected_since", m.connected_since);
                o.pushKV("last_activity",   m.last_activity);
                miners.push_back(o);
            }
            result.pushKV("miners", miners);
            return result;
        },
    };
}

static RPCHelpMan setparentchainconfig()
{
    return RPCHelpMan{"setparentchainconfig",
        "\nUpdate a parent chain's daemon connection config at runtime.\n",
        {
            {"name",     RPCArg::Type::STR, RPCArg::Optional::NO,  "Chain name (e.g. 'bitcoin', 'monero')"},
            {"host",     RPCArg::Type::STR, RPCArg::Optional::NO,  "Daemon host"},
            {"port",     RPCArg::Type::NUM, RPCArg::Optional::NO,  "Daemon RPC port"},
            {"user",     RPCArg::Type::STR, RPCArg::Default{""},   "RPC username"},
            {"password", RPCArg::Type::STR, RPCArg::Default{""},   "RPC password"},
            {"address",  RPCArg::Type::STR, RPCArg::Default{""},   "Pool wallet address on parent chain"},
        },
        RPCResult{RPCResult::Type::BOOL, "", "true if chain was found and updated"},
        RPCExamples{
            HelpExampleCli("setparentchainconfig",
                "\"monero\" \"127.0.0.1\" 18081 \"\" \"\" \"4MyAddress...\"")
        },
        [&](const RPCHelpMan&, const JSONRPCRequest& request) -> UniValue
        {
            merged_stratum::MultiMergedStratumServer& srv = merged_stratum::GetMultiMergedStratumServer();
            if (!srv.IsRunning())
                throw JSONRPCError(RPC_MISC_ERROR, "Multi-merged stratum server not running");

            std::string name = request.params[0].get_str();
            merged_stratum::ParentChainConfig pc;
            pc.name            = name;
            pc.daemon_host     = request.params[1].get_str();
            pc.daemon_port     = request.params[2].getInt<int>();
            pc.daemon_user     = request.params[3].isNull() ? "" : request.params[3].get_str();
            pc.daemon_password = request.params[4].isNull() ? "" : request.params[4].get_str();
            pc.wallet_address  = request.params[5].isNull() ? "" : request.params[5].get_str();

            return srv.UpdateParentChainConfig(name, pc);
        },
    };
}

void RegisterStratumRPCCommands(CRPCTable& t)
{
    static const CRPCCommand commands[]{
        {"mining", &startstratum},
        {"mining", &stopstratum},
        {"mining", &getstratuminfo},
        {"mining", &startmultimergedstratum},
        {"mining", &stopsmultimergedstratum},
        {"mining", &startbitcoinmergedstratum},
        {"mining", &getmergeminingdashboard},
        {"mining", &setparentchainconfig},
        {"mining", &startmergedstratum},
        {"mining", &stopmergedstratum},
    };
    for (const auto& c : commands) {
        t.appendCommand(c.name, &c);
    }
}
