# Copyright (c) 2026 The Bitcoin PoCX developers
# Distributed under the MIT software license; see COPYING.

# Keep the installed tool and kernel API unchanged. The test executable compiles
# the original tool source and sets NodeClock before its original main executes.
get_target_property(kernel_type bitcoinkernel TYPE)
set(clock_kernel bitcoinkernel)
if(NOT kernel_type STREQUAL "STATIC_LIBRARY")
  # SetMockTime is intentionally absent from the shared kernel API. Build a
  # private static copy of exactly its selected implementation for this driver,
  # retaining the same compilation/link interfaces. Never install this library.
  get_target_property(kernel_sources bitcoinkernel SOURCES)
  get_target_property(kernel_directory bitcoinkernel SOURCE_DIR)
  set(clock_sources)
  foreach(source IN LISTS kernel_sources)
    if(source MATCHES "^\\$<")
      # The kernel's conditional sources are relative to src/kernel. Object
      # library expressions already evaluate to absolute object file paths.
      string(REPLACE ":../" ":${PROJECT_SOURCE_DIR}/src/" source "${source}")
    elseif(NOT IS_ABSOLUTE "${source}")
      set(source "${kernel_directory}/${source}")
    endif()
    list(APPEND clock_sources "${source}")
  endforeach()
  add_library(pocx_chainstate_test_kernel STATIC ${clock_sources})
  foreach(property COMPILE_DEFINITIONS COMPILE_OPTIONS INCLUDE_DIRECTORIES LINK_LIBRARIES)
    get_target_property(value bitcoinkernel ${property})
    if(value)
      set_property(TARGET pocx_chainstate_test_kernel PROPERTY ${property} "${value}")
    endif()
  endforeach()
  target_compile_definitions(pocx_chainstate_test_kernel PUBLIC BITCOINKERNEL_STATIC)
  set(clock_kernel pocx_chainstate_test_kernel)
endif()

# Compile the original entry point directly, preserving main's implicit success
# return and keeping implementation files out of preprocessor includes.
add_executable(pocx_chainstate_test_clock
  chainstate_test_clock.cpp
  ${PROJECT_SOURCE_DIR}/src/bitcoin-chainstate.cpp
)
target_link_libraries(pocx_chainstate_test_clock PRIVATE core_interface ${clock_kernel})
add_windows_application_manifest(pocx_chainstate_test_clock)

file(GENERATE OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/clock-kernel-sources.txt"
  CONTENT "$<JOIN:$<TARGET_PROPERTY:${clock_kernel},SOURCES>,\n>\n")
file(GENERATE OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/original-kernel-sources.txt"
  CONTENT "$<JOIN:$<TARGET_PROPERTY:bitcoinkernel,SOURCES>,\n>\n")
