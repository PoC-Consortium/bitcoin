# Copyright (c) 2023-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

add_library(pocx_test_util STATIC EXCLUDE_FROM_ALL
  ${PROJECT_SOURCE_DIR}/src/test/util/blockfilter.cpp
  ${PROJECT_SOURCE_DIR}/src/test/util/coins.cpp
  ${PROJECT_SOURCE_DIR}/src/test/util/coverage.cpp
  ${PROJECT_SOURCE_DIR}/src/test/util/json.cpp
  ${PROJECT_SOURCE_DIR}/src/test/util/logging.cpp
  mining.cpp
  ${PROJECT_SOURCE_DIR}/src/test/util/net.cpp
  ${PROJECT_SOURCE_DIR}/src/test/util/random.cpp
  ${PROJECT_SOURCE_DIR}/src/test/util/script.cpp
  setup_common.cpp
  ${PROJECT_SOURCE_DIR}/src/test/util/str.cpp
  ${PROJECT_SOURCE_DIR}/src/test/util/time.cpp
  ${PROJECT_SOURCE_DIR}/src/test/util/transaction_utils.cpp
  ${PROJECT_SOURCE_DIR}/src/test/util/txmempool.cpp
  ${PROJECT_SOURCE_DIR}/src/test/util/validation.cpp
  $<$<BOOL:${ENABLE_WALLET}>:${PROJECT_SOURCE_DIR}/src/wallet/test/util.cpp>
)

target_link_libraries(pocx_test_util
  PRIVATE
    core_interface
    Boost::headers
  PUBLIC
    univalue
)

# Existing Qt/bench/fuzz consumers retain the support interface.
add_library(test_util ALIAS pocx_test_util)
