# Copyright (c) 2023-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

add_library(test_fuzz STATIC EXCLUDE_FROM_ALL
  check_globals.cpp
  descriptor.cpp
  mempool.cpp
  net.cpp
  ../fuzz.cpp
  ../util.cpp
)

target_link_libraries(test_fuzz
  PRIVATE
    core_interface
    test_util
    Boost::headers
)

# PoCX: bitcoin_node depends on bitcoin_wallet for block signing functions.
# Use LINK_GROUP:RESCAN to handle the circular dependency between these
# static libraries. This is the proper CMake 3.24+ solution - it tells the
# linker to rescan the group for unresolved symbols.
if(ENABLE_WALLET AND ENABLE_POCX)
  target_link_libraries(test_fuzz PRIVATE "$<LINK_GROUP:RESCAN,bitcoin_node,bitcoin_wallet>")
else()
  target_link_libraries(test_fuzz PRIVATE bitcoin_node)
endif()

if(NOT FUZZ_BINARY_LINKS_WITHOUT_MAIN_FUNCTION)
  target_compile_definitions(test_fuzz PRIVATE PROVIDE_FUZZ_MAIN_FUNCTION)
endif()
