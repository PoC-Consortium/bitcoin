#!/usr/bin/env bash
# Copyright (c) 2026 The Bitcoin PoCX developers
# Distributed under the MIT software license; see COPYING.

export LC_ALL=C.UTF-8

# The original workflow enables BCC only in ASan. Keep all other original
# package/pip selections and privileges unchanged, including optional guards.
pocx_prepare_tracing_runtime() {
  if [[ "${RUN_FUZZ_TESTS:-false}" == true || "${RUN_FUNCTIONAL_TESTS:-true}" != true ||
        "${CONTAINER_NAME:-}" != ci_native_asan ]]; then
    return
  fi
  local pocx_capability
  # Use actual-host matching headers even with a cached container image. The
  # original ASan environment wrapper already provides BCC and privileges.
  for pocx_capability in '-v /usr/src:/usr/src:ro' '-v /lib/modules:/lib/modules:ro'; do
    case " ${CI_CONTAINER_CAP:-} " in
      *" $pocx_capability "*) ;;
      *) export CI_CONTAINER_CAP="${CI_CONTAINER_CAP:-} $pocx_capability" ;;
    esac
  done
}
pocx_prepare_tracing_runtime
unset -f pocx_prepare_tracing_runtime
