// Copyright (c) 2024-2026 The WATTx Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <stratum/parent_chain.h>
#include <stratum/parent_chain_bitcoin.h>
#include <stratum/parent_chain_litecoin.h>
#include <stratum/parent_chain_monero.h>
#include <stratum/parent_chain_ethash.h>
#include <stratum/parent_chain_equihash.h>
#include <stratum/parent_chain_x11.h>
#include <stratum/parent_chain_kaspa.h>

namespace merged_stratum {

std::unique_ptr<IParentChainHandler> ParentChainFactory::Create(const ParentChainConfig& config) {
    switch (config.algo) {
        case ParentChainAlgo::SHA256D:
            return std::make_unique<BitcoinChainHandler>(config);

        case ParentChainAlgo::SCRYPT:
            if (config.name == "dogecoin" || config.name == "doge") {
                return std::make_unique<DogecoinChainHandler>(config);
            }
            return std::make_unique<LitecoinChainHandler>(config);

        case ParentChainAlgo::RANDOMX:
            return std::make_unique<MoneroChainHandler>(config);

        case ParentChainAlgo::ETHASH:
            return std::make_unique<EthashChainHandler>(config);

        case ParentChainAlgo::EQUIHASH: {
            std::unique_ptr<EquihashChainHandler> h;
            if (config.name == "horizen" || config.name == "zen") {
                h = std::make_unique<HorizenChainHandler>(config);
            } else if (config.name == "bitcoinz" || config.name == "btcz") {
                h = std::make_unique<BitcoinZChainHandler>(config);
            } else {
                h = std::make_unique<EquihashChainHandler>(config);
            }
            if (config.equihash_n && config.equihash_k) {
                h->SetEquihashParams(config.equihash_n, config.equihash_k);
            }
            return h;
        }

        case ParentChainAlgo::X11:
            return std::make_unique<DashChainHandler>(config);

        case ParentChainAlgo::KHEAVYHASH:
            return std::make_unique<KaspaChainHandler>(config);

        default:
            return nullptr;
    }
}

std::vector<ParentChainAlgo> ParentChainFactory::GetSupportedAlgos() {
    return {
        ParentChainAlgo::SHA256D,
        ParentChainAlgo::SCRYPT,
        ParentChainAlgo::RANDOMX,
        ParentChainAlgo::ETHASH,
        ParentChainAlgo::EQUIHASH,
        ParentChainAlgo::X11,
        ParentChainAlgo::KHEAVYHASH,
    };
}

std::string ParentChainFactory::AlgoToString(ParentChainAlgo algo) {
    switch (algo) {
        case ParentChainAlgo::SHA256D:    return "sha256d";
        case ParentChainAlgo::SCRYPT:     return "scrypt";
        case ParentChainAlgo::RANDOMX:    return "randomx";
        case ParentChainAlgo::ETHASH:     return "ethash";
        case ParentChainAlgo::EQUIHASH:   return "equihash";
        case ParentChainAlgo::X11:        return "x11";
        case ParentChainAlgo::KHEAVYHASH: return "kheavyhash";
        default:                          return "unknown";
    }
}

ParentChainAlgo ParentChainFactory::StringToAlgo(const std::string& name) {
    if (name == "sha256d" || name == "sha256" || name == "bitcoin") {
        return ParentChainAlgo::SHA256D;
    } else if (name == "scrypt" || name == "litecoin" || name == "dogecoin") {
        return ParentChainAlgo::SCRYPT;
    } else if (name == "randomx" || name == "monero") {
        return ParentChainAlgo::RANDOMX;
    } else if (name == "ethash" || name == "etc" || name == "ethereum_classic" ||
               name == "alt" || name == "altcoinchain" || name == "octa" || name == "octaspace") {
        return ParentChainAlgo::ETHASH;
    } else if (name == "equihash" || name == "zcash" || name == "horizen" ||
               name == "bitcoinz" || name == "btcz") {
        return ParentChainAlgo::EQUIHASH;
    } else if (name == "x11" || name == "dash") {
        return ParentChainAlgo::X11;
    } else if (name == "kheavyhash" || name == "kaspa") {
        return ParentChainAlgo::KHEAVYHASH;
    }
    return ParentChainAlgo::SHA256D;  // Default
}

}  // namespace merged_stratum
