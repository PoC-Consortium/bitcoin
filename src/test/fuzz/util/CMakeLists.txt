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
# This creates a circular dependency that requires special linker handling.
if(ENABLE_WALLET AND ENABLE_POCX)
  if(MSVC)
    # MSVC doesn't support LINK_GROUP:RESCAN. List libraries multiple times
    # to resolve circular dependencies (MSVC linker handles this).
    target_link_libraries(test_fuzz PRIVATE bitcoin_node bitcoin_wallet bitcoin_node)
  else()
    # Use LINK_GROUP:RESCAN on GNU/Clang (CMake 3.24+) - tells linker to
    # rescan the group for unresolved symbols.
    target_link_libraries(test_fuzz PRIVATE "$<LINK_GROUP:RESCAN,bitcoin_node,bitcoin_wallet>")
  endif()
else()
  target_link_libraries(test_fuzz PRIVATE bitcoin_node)
endif()

if(NOT FUZZ_BINARY_LINKS_WITHOUT_MAIN_FUNCTION)
  target_compile_definitions(test_fuzz PRIVATE PROVIDE_FUZZ_MAIN_FUNCTION)
endif()
