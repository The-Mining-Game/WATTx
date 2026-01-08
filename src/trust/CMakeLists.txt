# Copyright (c) 2024 The WATTx Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

add_library(wattx_trust STATIC EXCLUDE_FROM_ALL
  trustscore.cpp
  heartbeat_net.cpp
)

target_link_libraries(wattx_trust
  PRIVATE
    core_interface
    bitcoin_crypto
    bitcoin_consensus
    Boost::headers
)
