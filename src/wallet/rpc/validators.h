// Copyright (c) 2024 The WATTx Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef WATTX_WALLET_RPC_VALIDATORS_H
#define WATTX_WALLET_RPC_VALIDATORS_H

#include <span.h>

class CRPCCommand;

namespace wallet {

Span<const CRPCCommand> GetValidatorWalletRPCCommands();

} // namespace wallet

#endif // WATTX_WALLET_RPC_VALIDATORS_H
