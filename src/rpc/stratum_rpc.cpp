// Copyright (c) 2024-2026 The WATTx Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <rpc/server.h>
#include <rpc/server_util.h>
#include <rpc/util.h>
#include <stratum/stratum_server.h>
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

void RegisterStratumRPCCommands(CRPCTable& t)
{
    static const CRPCCommand commands[]{
        {"mining", &startstratum},
        {"mining", &stopstratum},
        {"mining", &getstratuminfo},
    };
    for (const auto& c : commands) {
        t.appendCommand(c.name, &c);
    }
}
