#!/usr/bin/env bash
# Copyright (c) 2026 The Bitcoin PoCX developers
# Distributed under the MIT software license; see COPYING.

export LC_ALL=C.UTF-8

# This file is sourced during both host setup and the Docker image build.
export INSTALL_BCC_TRACING_TOOLS=true
source ./ci/test/00_setup_env_native_asan.sh
