# Copyright (c) 2026 The Bitcoin PoCX developers
# Distributed under the MIT software license; see COPYING.
# Sidecar provenance for both products; original sources and flags are unchanged.
find_package(Python3 REQUIRED COMPONENTS Interpreter)
file(GLOB_RECURSE FUZZ_SOURCE_INPUTS CONFIGURE_DEPENDS
  "${PROJECT_SOURCE_DIR}/src/*.cpp"
  "${PROJECT_SOURCE_DIR}/src/*.c"
  "${PROJECT_SOURCE_DIR}/src/*.h"
  "${PROJECT_SOURCE_DIR}/src/*.cmake"
  "${PROJECT_SOURCE_DIR}/src/CMakeLists.txt")
list(APPEND FUZZ_SOURCE_INPUTS
  "${PROJECT_SOURCE_DIR}/CMakeLists.txt"
  "${PROJECT_SOURCE_DIR}/test/pocx/record_fuzz.py"
  "${PROJECT_SOURCE_DIR}/test/pocx/fuzz_build.py"
  "${PROJECT_SOURCE_DIR}/test/pocx/common.py"
  "${PROJECT_BINARY_DIR}/src/bitcoin-build-config.h")
set(fuzz_provenance_dir "${PROJECT_BINARY_DIR}/pocx-fuzz-build")
if(CMAKE_CONFIGURATION_TYPES)
  string(APPEND fuzz_provenance_dir "/$<CONFIG>")
endif()
# All selected fuzz SOURCES must be absolute in the manifest, including the
# unchanged upstream target's relative entries and conditional wallet sources.
get_target_property(fuzz_source_directory fuzz SOURCE_DIR)
get_target_property(fuzz_evaluated_sources fuzz SOURCES)
set(fuzz_absolute_sources)
foreach(source IN LISTS fuzz_evaluated_sources)
  if(IS_ABSOLUTE "${source}" OR source MATCHES "^\\$<")
    list(APPEND fuzz_absolute_sources "${source}")
  else()
    list(APPEND fuzz_absolute_sources "${fuzz_source_directory}/${source}")
  endif()
endforeach()
file(GENERATE OUTPUT "${fuzz_provenance_dir}/selection.txt"
  CONTENT "$<JOIN:${fuzz_absolute_sources},\n>\n")
file(GENERATE OUTPUT "${fuzz_provenance_dir}/build-inputs.txt"
  CONTENT "$<JOIN:${FUZZ_SOURCE_INPUTS},\n>\n$<JOIN:${fuzz_absolute_sources},\n>\n")
set_property(TARGET fuzz APPEND PROPERTY LINK_DEPENDS
  "${fuzz_provenance_dir}/build-inputs.txt" "${PROJECT_BINARY_DIR}/CMakeCache.txt" ${FUZZ_SOURCE_INPUTS})
add_custom_command(OUTPUT "${fuzz_provenance_dir}/build.json"
  COMMAND ${Python3_EXECUTABLE} ${PROJECT_SOURCE_DIR}/test/pocx/record_fuzz.py
    --binary $<TARGET_FILE:fuzz> --inputs "${fuzz_provenance_dir}/build-inputs.txt"
    --cache "${PROJECT_BINARY_DIR}/CMakeCache.txt" --output "${fuzz_provenance_dir}/build.json"
  DEPENDS fuzz "${fuzz_provenance_dir}/build-inputs.txt"
    "${PROJECT_BINARY_DIR}/CMakeCache.txt" ${FUZZ_SOURCE_INPUTS}
  VERBATIM)
add_custom_target(fuzz_provenance ALL DEPENDS "${fuzz_provenance_dir}/build.json")
