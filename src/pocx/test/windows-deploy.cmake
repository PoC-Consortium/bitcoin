# Copyright (c) 2026 The Bitcoin PoCX developers
# Distributed under the MIT software license; see COPYING.

# The original Windows installer requires test_bitcoin. Keep that recipe intact
# and package the separately built native suite through its own deploy target.
function(pocx_add_windows_test_deploy_target)
  if(NOT ENABLE_POCX OR NOT MINGW OR TARGET deploy)
    return()
  endif()
  set(deploy_targets bitcoin bitcoin-qt bitcoind bitcoin-cli bitcoin-tx bitcoin-wallet bitcoin-util test_pocx)
  foreach(target IN LISTS deploy_targets)
    if(NOT TARGET ${target})
      return()
    endif()
  endforeach()
  find_program(MAKENSIS_EXECUTABLE makensis)
  if(NOT MAKENSIS_EXECUTABLE)
    add_custom_target(deploy
      COMMAND ${CMAKE_COMMAND} -E echo "Error: NSIS not found"
    )
    return()
  endif()

  # Reuse the original installer template with the native unit executable.
  set(abs_top_srcdir ${PROJECT_SOURCE_DIR})
  set(abs_top_builddir ${PROJECT_BINARY_DIR})
  set(CLIENT_URL ${PROJECT_HOMEPAGE_URL})
  set(POCX_BUILD "1")
  set(CLIENT_TARNAME "btcx")
  set(BITCOIN_WRAPPER_NAME "bitcoin")
  set(BITCOIN_GUI_NAME "bitcoin-qt")
  set(BITCOIN_DAEMON_NAME "bitcoind")
  set(BITCOIN_CLI_NAME "bitcoin-cli")
  set(BITCOIN_TX_NAME "bitcoin-tx")
  set(BITCOIN_WALLET_TOOL_NAME "bitcoin-wallet")
  set(BITCOIN_TEST_NAME "test_pocx")
  set(EXEEXT ${CMAKE_EXECUTABLE_SUFFIX})
  set(setup_name "bitcoin-pocx-win64-setup")
  configure_file(${PROJECT_SOURCE_DIR}/share/setup.nsi.in
    ${PROJECT_BINARY_DIR}/${setup_name}.nsi USE_SOURCE_PERMISSIONS @ONLY)
  set(strip_commands)
  foreach(target IN LISTS deploy_targets)
    list(APPEND strip_commands COMMAND ${CMAKE_STRIP} $<TARGET_FILE:${target}>
      -o ${PROJECT_BINARY_DIR}/release/$<TARGET_FILE_NAME:${target}>)
  endforeach()
  add_custom_command(
    OUTPUT ${PROJECT_BINARY_DIR}/${setup_name}.exe
    COMMAND ${CMAKE_COMMAND} -E make_directory ${PROJECT_BINARY_DIR}/release
    ${strip_commands}
    COMMAND ${MAKENSIS_EXECUTABLE} -V2 ${PROJECT_BINARY_DIR}/${setup_name}.nsi
    DEPENDS ${deploy_targets} ${PROJECT_BINARY_DIR}/${setup_name}.nsi
    VERBATIM
  )
  add_custom_target(deploy DEPENDS ${PROJECT_BINARY_DIR}/${setup_name}.exe)
endfunction()

# All executables and the original maintenance targets are defined by then.
cmake_language(DEFER DIRECTORY "${PROJECT_SOURCE_DIR}" CALL pocx_add_windows_test_deploy_target)
