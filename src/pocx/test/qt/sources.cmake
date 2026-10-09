# Copyright (c) 2026 The Bitcoin PoCX developers
# Distributed under the MIT software license; see COPYING.
# Reuse original Qt cases; select owned RPC/wallet expectations and native cases.
# Owned and reused headers have different directories; use AUTOMOC's defaults.
set(CMAKE_AUTOMOC_MOC_OPTIONS "")
set(qt_rpcnested_sources
  ${PROJECT_SOURCE_DIR}/src/pocx/test/qt/rpcnestedtests.cpp
  ${PROJECT_SOURCE_DIR}/src/qt/test/rpcnestedtests.h
)
set(qt_wallet_sources
  ${PROJECT_SOURCE_DIR}/src/pocx/test/qt/wallettests.cpp
  ${PROJECT_SOURCE_DIR}/src/qt/test/wallettests.h
)
set(qt_main_sources ${PROJECT_SOURCE_DIR}/src/pocx/test/qt/test_main.cpp)
set(qt_native_sources
  ${PROJECT_SOURCE_DIR}/src/pocx/test/qt/pocxuritests.cpp
  ${PROJECT_SOURCE_DIR}/src/pocx/test/qt/pocxuritests.h
)
