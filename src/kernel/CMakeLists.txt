# Copyright (c) 2024-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

include(GNUInstallDirs)

# TODO: libbitcoinkernel is a work in progress consensus engine
#       library, as more and more modules are decoupled from the
#       consensus engine, this list will shrink to only those
#       which are absolutely necessary.
add_library(bitcoinkernel
  bitcoinkernel.cpp
  chain.cpp
  checks.cpp
  chainparams.cpp
  coinstats.cpp
  context.cpp
  cs_main.cpp
  disconnected_transactions.cpp
  mempool_removal_reason.cpp
  ../arith_uint256.cpp
  ../chain.cpp
  ../coins.cpp
  ../compressor.cpp
  ../consensus/merkle.cpp
  ../consensus/tx_check.cpp
  ../consensus/tx_verify.cpp
  ../dbwrapper.cpp
  ../deploymentinfo.cpp
  ../deploymentstatus.cpp
  ../flatfile.cpp
  ../hash.cpp
  ../logging.cpp
  ../node/blockstorage.cpp
  ../node/chainstate.cpp
  ../node/utxo_snapshot.cpp
  ../policy/ephemeral_policy.cpp
  ../policy/feerate.cpp
  ../policy/packages.cpp
  ../policy/policy.cpp
  ../policy/rbf.cpp
  ../policy/settings.cpp
  ../policy/truc_policy.cpp
  $<$<NOT:$<BOOL:${ENABLE_POCX}>>:../pow.cpp>
  ../primitives/block.cpp
  ../primitives/transaction.cpp
  ../pubkey.cpp
  ../random.cpp
  ../randomenv.cpp
  ../script/interpreter.cpp
  ../script/script.cpp
  ../script/script_error.cpp
  ../script/sigcache.cpp
  ../script/solver.cpp
  ../signet.cpp
  ../streams.cpp
  ../support/lockedpool.cpp
  ../sync.cpp
  ../txdb.cpp
  ../txgraph.cpp
  ../txmempool.cpp
  ../uint256.cpp
  ../util/chaintype.cpp
  ../util/check.cpp
  ../util/expected.cpp
  ../util/feefrac.cpp
  ../util/fs.cpp
  ../util/fs_helpers.cpp
  ../util/hasher.cpp
  ../util/moneystr.cpp
  ../util/rbf.cpp
  ../util/serfloat.cpp
  ../util/signalinterrupt.cpp
  ../util/syserror.cpp
  ../util/threadnames.cpp
  ../util/time.cpp
  ../util/tokenpipe.cpp
  ../validation.cpp
  ../validationinterface.cpp
  ../versionbits.cpp
  $<$<BOOL:${ENABLE_POCX}>:../pocx/consensus/signature.cpp>
  $<$<BOOL:${ENABLE_POCX}>:../pocx/consensus/proof.cpp>
  $<$<BOOL:${ENABLE_POCX}>:../pocx/consensus/params.cpp>
  $<$<BOOL:${ENABLE_POCX}>:../pocx/consensus/batch_validation.cpp>
  $<$<BOOL:${ENABLE_POCX}>:../pocx/consensus/difficulty.cpp>
  $<$<BOOL:${ENABLE_POCX}>:../pocx/algorithms/time_bending.cpp>
  $<$<BOOL:${ENABLE_POCX}>:../pocx/algorithms/plot_generation.cpp>
  $<$<BOOL:${ENABLE_POCX}>:../pocx/algorithms/quality.cpp>
  $<$<BOOL:${ENABLE_POCX}>:../pocx/algorithms/encoding.cpp>
  $<$<BOOL:${ENABLE_POCX}>:../pocx/assignments/assignment_state.cpp>
  $<$<BOOL:${ENABLE_POCX}>:../pocx/assignments/opcodes.cpp>
  $<$<BOOL:${ENABLE_POCX}>:../pocx/assignments/replay.cpp>
  $<$<BOOL:${ENABLE_POCX}>:../pocx/mining/defensive_forge.cpp>
  $<TARGET_OBJECTS:bitcoin_clientversion>
  $<TARGET_OBJECTS:bitcoin_crypto>
  $<TARGET_OBJECTS:leveldb>
  $<TARGET_OBJECTS:crc32c>
)

# Compiler warnings that apply only to the kernel and its dependencies.
# These can be more strict and/or warnings that only apply to shared
# libs.
add_library(kernel_warn_interface INTERFACE)
if(NOT MSVC)
  try_append_cxx_flags("-Wunique-object-duplication" TARGET kernel_warn_interface SKIP_LINK)
endif()

# Also manually apply the warnings to the kernel's internal dependencies
target_link_libraries(bitcoin_clientversion PRIVATE kernel_warn_interface)
target_link_libraries(bitcoin_crypto PRIVATE kernel_warn_interface)
target_link_libraries(leveldb PRIVATE kernel_warn_interface)
target_link_libraries(crc32c PRIVATE kernel_warn_interface)

target_link_libraries(bitcoinkernel
  PRIVATE
    core_interface
    kernel_warn_interface
    secp256k1_objs
    $<$<PLATFORM_ID:Windows>:bcrypt>
    $<TARGET_NAME_IF_EXISTS:USDT::headers>
    Boost::headers
)

# Mark this TU as kernel-library build so validation.cpp can skip code
# paths that depend on symbols only present in bitcoin_node/bitcoin_common
# (e.g. Params(), regtest hot-path forger).
if(ENABLE_POCX)
  target_compile_definitions(bitcoinkernel PRIVATE BUILD_BITCOIN_KERNEL)
endif()

# Enable AVX2 for PoCX batch validation if available
if(ENABLE_POCX AND HAVE_AVX2)
  target_compile_definitions(bitcoinkernel PRIVATE ENABLE_AVX2)
endif()
# SSE2 is baseline on x86-64, no special compiler flags needed
if(ENABLE_POCX AND CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|amd64")
  target_compile_definitions(bitcoinkernel PRIVATE ENABLE_SSE2)
endif()

target_include_directories(bitcoinkernel PRIVATE $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/src/leveldb/include>)

# Add a convenience libbitcoinkernel target as a synonym for bitcoinkernel.
add_custom_target(libbitcoinkernel)
add_dependencies(libbitcoinkernel bitcoinkernel)

get_target_property(bitcoinkernel_type bitcoinkernel TYPE)
if(bitcoinkernel_type STREQUAL "STATIC_LIBRARY")
  target_compile_definitions(bitcoinkernel PUBLIC BITCOINKERNEL_STATIC)
endif()

configure_file(${PROJECT_SOURCE_DIR}/libbitcoinkernel.pc.in ${PROJECT_BINARY_DIR}/libbitcoinkernel.pc @ONLY)
install(FILES ${PROJECT_BINARY_DIR}/libbitcoinkernel.pc DESTINATION "${CMAKE_INSTALL_LIBDIR}/pkgconfig" COMPONENT libbitcoinkernel)

install(TARGETS bitcoinkernel
  RUNTIME
    DESTINATION ${CMAKE_INSTALL_BINDIR}
    COMPONENT libbitcoinkernel
  LIBRARY
    DESTINATION ${CMAKE_INSTALL_LIBDIR}
    COMPONENT libbitcoinkernel
  ARCHIVE
    DESTINATION ${CMAKE_INSTALL_LIBDIR}
    COMPONENT libbitcoinkernel
)

install(FILES bitcoinkernel.h DESTINATION ${CMAKE_INSTALL_INCLUDEDIR} COMPONENT libbitcoinkernel)
