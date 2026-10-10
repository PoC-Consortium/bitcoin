# Copyright (c) 2026 The Bitcoin PoCX developers
# Distributed under the MIT software license; see COPYING.
find_package(Python3 REQUIRED COMPONENTS Interpreter)
set(fixture "${CMAKE_CURRENT_BINARY_DIR}/kernel-fixtures.json")
set(header "${CMAKE_CURRENT_BINARY_DIR}/pocx_kernel_block_data.h")
if(CMAKE_CROSSCOMPILING)
  # Target executables cannot generate build-host inputs. Use the byte-identical
  # independently verified snapshot; the host renderer still checks its hash.
  set(snapshot "${PROJECT_SOURCE_DIR}/test/pocx/kernel/fixtures.json")
  add_custom_command(OUTPUT "${fixture}" "${header}"
    COMMAND ${CMAKE_COMMAND} -E copy_if_different "${snapshot}" "${fixture}"
    COMMAND ${Python3_EXECUTABLE} "${PROJECT_SOURCE_DIR}/test/pocx/kernel/render_fixtures.py" "${fixture}" "${header}"
    DEPENDS "${snapshot}" "${PROJECT_SOURCE_DIR}/test/pocx/kernel/render_fixtures.py"
      "${PROJECT_SOURCE_DIR}/test/pocx/kernel/provenance.json"
    VERBATIM)
else()
  add_executable(pocx_kernel_fixture_generator fixture_generator.cpp)
  target_link_libraries(pocx_kernel_fixture_generator PRIVATE core_interface bitcoin_node
    bitcoin_consensus bitcoin_common bitcoin_util secp256k1 univalue Boost::headers libevent::extra)
  add_windows_application_manifest(pocx_kernel_fixture_generator)
  add_custom_command(OUTPUT "${fixture}" "${header}"
    COMMAND pocx_kernel_fixture_generator "${fixture}"
    COMMAND ${Python3_EXECUTABLE} "${PROJECT_SOURCE_DIR}/test/pocx/kernel/render_fixtures.py" "${fixture}" "${header}"
    DEPENDS pocx_kernel_fixture_generator "${PROJECT_SOURCE_DIR}/test/pocx/kernel/render_fixtures.py"
      "${PROJECT_SOURCE_DIR}/test/pocx/kernel/provenance.json"
    VERBATIM)
endif()

add_executable(test_kernel test_kernel.cpp "${header}")
target_include_directories(test_kernel PRIVATE "${CMAKE_CURRENT_BINARY_DIR}")
target_link_libraries(test_kernel PRIVATE core_interface bitcoinkernel Boost::headers)
add_windows_application_manifest(test_kernel)
add_test(NAME test_kernel COMMAND test_kernel)
