# Copyright (c) 2026 The Bitcoin PoCX developers
# Distributed under the MIT software license; see COPYING.
include(sources.cmake)
if(NOT POCX_TEST_SOURCES)
  message(FATAL_ERROR "Empty PoCX unit selection")
endif()
foreach(source IN LISTS POCX_TEST_SOURCES)
  if(NOT EXISTS "${source}")
    message(FATAL_ERROR "Missing PoCX unit source: ${source}")
  endif()
endforeach()
add_executable(test_pocx ${POCX_TEST_SOURCES})
target_link_libraries(test_pocx core_interface pocx_test_util bitcoin_cli bitcoin_node
  bitcoin_consensus minisketch secp256k1 Boost::headers libevent::extra
  $<TARGET_NAME_IF_EXISTS:USDT::headers>)
if(ENABLE_WALLET)
  target_link_libraries(test_pocx bitcoin_wallet)
endif()
if(ENABLE_IPC)
  target_link_libraries(test_pocx bitcoin_ipc_test bitcoin_ipc)
endif()
if(HAVE_AVX2)
  target_compile_definitions(test_pocx PRIVATE ENABLE_AVX2)
endif()
if(CMAKE_SYSTEM_PROCESSOR MATCHES "[xX]86_64|[aA][mM][dD]64")
  target_compile_definitions(test_pocx PRIVATE ENABLE_SSE2)
endif()
add_windows_application_manifest(test_pocx)
set(POCX_UNIT_INPUTS
  "${PROJECT_SOURCE_DIR}/CMakeLists.txt"
  "${PROJECT_SOURCE_DIR}/src/CMakeLists.txt"
  "${CMAKE_CURRENT_SOURCE_DIR}/CMakeLists.txt"
  "${CMAKE_CURRENT_SOURCE_DIR}/sources.cmake"
  "${CMAKE_CURRENT_SOURCE_DIR}/util/CMakeLists.txt"
  "${PROJECT_SOURCE_DIR}/test/pocx/register_unit.py"
  "${PROJECT_SOURCE_DIR}/test/pocx/unit_build.py")
# Reuse data without maintaining copies; headers live only in the build tree.
foreach(data base58_encode_decode bip341_wallet_vectors blockfilters key_io_invalid
    key_io_valid script_tests sighash tx_invalid tx_valid real_proof_vectors)
  set(input "${PROJECT_SOURCE_DIR}/src/test/data/${data}.json")
  if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/data/${data}.json")
    set(input "${CMAKE_CURRENT_SOURCE_DIR}/data/${data}.json")
  endif()
  list(APPEND POCX_UNIT_INPUTS "${input}")
  set(output "${CMAKE_CURRENT_BINARY_DIR}/data/${data}.json.h")
  add_custom_command(OUTPUT "${output}"
    COMMAND ${CMAKE_COMMAND} -DJSON_SOURCE_PATH=${input} -DHEADER_PATH=${output}
      -P ${PROJECT_SOURCE_DIR}/cmake/script/GenerateHeaderFromJson.cmake
    DEPENDS "${input}" ${PROJECT_SOURCE_DIR}/cmake/script/GenerateHeaderFromJson.cmake VERBATIM)
  target_sources(test_pocx PRIVATE "${output}")
endforeach()
set(input "${PROJECT_SOURCE_DIR}/src/test/data/asmap.raw")
list(APPEND POCX_UNIT_INPUTS "${input}")
set(output "${CMAKE_CURRENT_BINARY_DIR}/data/asmap.raw.h")
add_custom_command(OUTPUT "${output}"
  COMMAND ${CMAKE_COMMAND} -DRAW_SOURCE_PATH=${input} -DHEADER_PATH=${output}
    -DRAW_NAMESPACE=test::data -P ${PROJECT_SOURCE_DIR}/cmake/script/GenerateHeaderFromRaw.cmake
  DEPENDS "${input}" ${PROJECT_SOURCE_DIR}/cmake/script/GenerateHeaderFromRaw.cmake VERBATIM)
target_sources(test_pocx PRIVATE "${output}")
target_include_directories(test_pocx BEFORE PRIVATE "${CMAKE_CURRENT_BINARY_DIR}/..")

# Runtime discovery respects preprocessor gates and cannot miss generator sources.
# Record evaluated target sources and selected support/data inputs after linking.
# The runner rejects binaries whose source-selection evidence is stale.
find_package(Python3 REQUIRED COMPONENTS Interpreter)
get_target_property(POCX_SUPPORT_SOURCES pocx_test_util SOURCES)
foreach(source IN LISTS POCX_SUPPORT_SOURCES)
  if(IS_ABSOLUTE "${source}" OR source MATCHES "^\\$<")
    list(APPEND POCX_UNIT_INPUTS "${source}")
  else()
    list(APPEND POCX_UNIT_INPUTS "${CMAKE_CURRENT_SOURCE_DIR}/util/${source}")
  endif()
endforeach()
file(GLOB_RECURSE POCX_UNIT_HEADERS CONFIGURE_DEPENDS
  "${PROJECT_SOURCE_DIR}/src/test/*.h"
  "${CMAKE_CURRENT_SOURCE_DIR}/*.h")
list(APPEND POCX_UNIT_INPUTS ${POCX_UNIT_HEADERS})
set(unit_discovery_dir "${CMAKE_CURRENT_BINARY_DIR}")
if(CMAKE_CONFIGURATION_TYPES)
  # Each executable needs its own source/binary evidence and registrations.
  # Building Debug must never overwrite the discovery record for Release.
  string(APPEND unit_discovery_dir "/$<CONFIG>")
  file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/discovery-config.cmake" [=[
if(NOT CTEST_CONFIGURATION_TYPE)
  message(FATAL_ERROR "PoCX unit discovery requires an explicit CTest build configuration")
endif()
include("${CMAKE_CURRENT_LIST_DIR}/${CTEST_CONFIGURATION_TYPE}/discovered.cmake")
]=])
  set(unit_test_include "${CMAKE_CURRENT_BINARY_DIR}/discovery-config.cmake")
else()
  set(unit_test_include "${CMAKE_CURRENT_BINARY_DIR}/discovered.cmake")
endif()
set(unit_inputs "${unit_discovery_dir}/unit-inputs.txt")
if(CMAKE_CROSSCOMPILING AND CMAKE_SYSTEM_NAME STREQUAL "Windows")
  # The Windows artifact consumer discovers and runs all cases on Windows.
  # Executing this foreign PE binary on the Linux builder is invalid.
  list(APPEND POCX_UNIT_INPUTS "${PROJECT_SOURCE_DIR}/test/pocx/record_cross_unit.py")
endif()
file(GENERATE OUTPUT "${unit_inputs}"
  # CMake appends virtual .rule entries for generated headers; these are not files.
  CONTENT "$<JOIN:$<FILTER:$<TARGET_PROPERTY:test_pocx,SOURCES>,EXCLUDE,[.]rule$>,\n>\n$<JOIN:${POCX_UNIT_INPUTS},\n>\n")
set_property(TARGET test_pocx APPEND PROPERTY LINK_DEPENDS "${unit_inputs}"
  "${PROJECT_BINARY_DIR}/CMakeCache.txt" ${POCX_UNIT_INPUTS})
if(CMAKE_CROSSCOMPILING AND CMAKE_SYSTEM_NAME STREQUAL "Windows")
  add_custom_command(TARGET test_pocx POST_BUILD
    COMMAND ${Python3_EXECUTABLE} ${PROJECT_SOURCE_DIR}/test/pocx/record_cross_unit.py
      --binary $<TARGET_FILE:test_pocx> --output "${unit_discovery_dir}/cross-build.json"
      --inputs "${unit_inputs}" --cache "${PROJECT_BINARY_DIR}/CMakeCache.txt"
      --source "${PROJECT_SOURCE_DIR}"
    VERBATIM)
else()
  add_custom_command(TARGET test_pocx POST_BUILD
    COMMAND ${Python3_EXECUTABLE} ${PROJECT_SOURCE_DIR}/test/pocx/register_unit.py
      --binary $<TARGET_FILE:test_pocx> --output "${unit_discovery_dir}/discovered.cmake"
      --inputs "${unit_inputs}" --cache "${PROJECT_BINARY_DIR}/CMakeCache.txt"
    VERBATIM)
  set_property(DIRECTORY APPEND PROPERTY TEST_INCLUDE_FILES "${unit_test_include}")
endif()
install_binary_component(test_pocx INTERNAL)
