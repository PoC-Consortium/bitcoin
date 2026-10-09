# Copyright (c) 2026 The Bitcoin PoCX developers
# Distributed under the MIT software license; see COPYING.
add_executable(pocx_kernel_fixture_generator fixture_generator.cpp)
target_link_libraries(pocx_kernel_fixture_generator PRIVATE core_interface bitcoin_node
  bitcoin_consensus bitcoin_common bitcoin_util secp256k1 univalue Boost::headers libevent::extra)
add_windows_application_manifest(pocx_kernel_fixture_generator)

find_package(Python3 REQUIRED COMPONENTS Interpreter)
set(fixture "${CMAKE_CURRENT_BINARY_DIR}/kernel-fixtures.json")
set(header "${CMAKE_CURRENT_BINARY_DIR}/pocx_kernel_block_data.h")
add_custom_command(OUTPUT "${fixture}" "${header}"
  COMMAND pocx_kernel_fixture_generator "${fixture}"
  COMMAND ${Python3_EXECUTABLE} "${PROJECT_SOURCE_DIR}/test/pocx/kernel/render_fixtures.py" "${fixture}" "${header}"
  DEPENDS pocx_kernel_fixture_generator "${PROJECT_SOURCE_DIR}/test/pocx/kernel/render_fixtures.py"
    "${PROJECT_SOURCE_DIR}/test/pocx/kernel/provenance.json"
  VERBATIM)

add_executable(test_kernel test_kernel.cpp "${header}")
target_include_directories(test_kernel PRIVATE "${CMAKE_CURRENT_BINARY_DIR}")
target_link_libraries(test_kernel PRIVATE core_interface bitcoinkernel Boost::headers)
add_windows_application_manifest(test_kernel)
add_test(NAME test_kernel COMMAND test_kernel)
