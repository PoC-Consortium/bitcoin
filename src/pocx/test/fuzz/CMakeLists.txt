# Copyright (c) 2026 The Bitcoin PoCX developers
# Distributed under the MIT software license; see COPYING.
include(sources.cmake)
add_subdirectory(${PROJECT_SOURCE_DIR}/src/test/fuzz/util ${CMAKE_CURRENT_BINARY_DIR}/util)
add_executable(fuzz ${POCX_FUZZ_SOURCES})
add_windows_application_manifest(fuzz)
target_link_libraries(fuzz core_interface fuzzer_interface test_fuzz bitcoin_cli
  bitcoin_common bitcoin_util minisketch leveldb univalue secp256k1 Boost::headers libevent::extra)
if(HAVE_AVX2)
  set_property(SOURCE shabal.cpp APPEND PROPERTY COMPILE_DEFINITIONS ENABLE_AVX2)
endif()
if(CMAKE_SYSTEM_PROCESSOR MATCHES "[xX]86_64|[aA][mM][dD]64")
  set_property(SOURCE shabal.cpp APPEND PROPERTY COMPILE_DEFINITIONS ENABLE_SSE2)
endif()
if(ENABLE_WALLET)
  add_subdirectory(${PROJECT_SOURCE_DIR}/src/wallet/test/fuzz ${CMAKE_CURRENT_BINARY_DIR}/wallet)
endif()
