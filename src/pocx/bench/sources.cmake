# Copyright (c) 2026 The Bitcoin PoCX developers
# Distributed under the MIT software license; see COPYING.
# Keep every original benchmark registration. Replace only reviewed sources.
get_target_property(pocx_benchmark_sources bench_bitcoin SOURCES)
set(pocx_adapted_benchmarks
  block_assemble blockencodings checkblock duplicate_inputs readwriteblock rpc_blockchain
)
if(ENABLE_WALLET)
  list(APPEND pocx_adapted_benchmarks wallet_balance wallet_create_tx)
endif()
foreach(name IN LISTS pocx_adapted_benchmarks)
  if(NOT "${name}.cpp" IN_LIST pocx_benchmark_sources)
    message(FATAL_ERROR "Original benchmark source missing: ${name}.cpp")
  endif()
  list(REMOVE_ITEM pocx_benchmark_sources "${name}.cpp")
  list(APPEND pocx_benchmark_sources "${PROJECT_SOURCE_DIR}/src/pocx/bench/${name}.cpp")
endforeach()
set_property(TARGET bench_bitcoin PROPERTY SOURCES "${pocx_benchmark_sources}")
