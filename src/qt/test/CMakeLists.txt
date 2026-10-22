# Copyright (c) 2024-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

set(CMAKE_AUTOMOC_MOC_OPTIONS "-p${CMAKE_CURRENT_SOURCE_DIR}")

set(qt_rpcnested_sources rpcnestedtests.cpp)
set(qt_wallet_sources wallettests.cpp)
set(qt_main_sources test_main.cpp)
set(qt_native_sources)
if(ENABLE_POCX)
  include(${PROJECT_SOURCE_DIR}/src/pocx/test/qt/sources.cmake)
endif()

add_executable(test_bitcoin-qt
  apptests.cpp
  optiontests.cpp
  ${qt_rpcnested_sources}
  ${qt_main_sources}
  ${qt_native_sources}
  uritests.cpp
  util.cpp
  ../../init/bitcoin-qt.cpp
)

add_windows_application_manifest(test_bitcoin-qt)

target_link_libraries(test_bitcoin-qt
  core_interface
  bitcoinqt
  test_util
  bitcoin_node
  Boost::headers
  Qt6::Test
)

import_plugins(test_bitcoin-qt)

if(ENABLE_WALLET)
  target_sources(test_bitcoin-qt
    PRIVATE
      addressbooktests.cpp
      ${qt_wallet_sources}
      ../../wallet/test/wallet_test_fixture.cpp
  )
endif()

add_test(NAME test_bitcoin-qt
  COMMAND test_bitcoin-qt
)
if(WIN32 AND VCPKG_TARGET_TRIPLET)
  set(plugin_path "$<SHELL_PATH:$<PATH:GET_PARENT_PATH,$<PATH:GET_PARENT_PATH,$<TARGET_PROPERTY:Qt6::QWindowsIntegrationPlugin,LOCATION_$<CONFIG>>>>>")
  set_property(TEST test_bitcoin-qt APPEND PROPERTY
    ENVIRONMENT_MODIFICATION
      # On Windows, vcpkg configures Qt with `-opengl dynamic`, which makes
      # the "minimal" platform plugin unusable due to internal Qt bugs.
      QT_QPA_PLATFORM=set:windows
      QT_PLUGIN_PATH=set:${plugin_path}
  )
  unset(plugin_path)
endif()

install_binary_component(test_bitcoin-qt INTERNAL)
