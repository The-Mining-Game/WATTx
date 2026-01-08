# Copyright (c) 2024 The WATTx Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

add_library(wattx_validators STATIC EXCLUDE_FROM_ALL
  validatordb.cpp
  delegation.cpp
)

target_link_libraries(wattx_validators
  PRIVATE
    core_interface
    bitcoin_crypto
    Boost::headers
)
