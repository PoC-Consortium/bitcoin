#!/usr/bin/env bash
# Copyright (c) 2026 The Bitcoin PoCX developers
# Distributed under the MIT software license; see COPYING.

# Sourced after the original environment, on the host and in the image build.
# These reviewed Linux recipes enable USDT and execute functional tests.
pocx_prepare_tracing_runtime() {
  if [[ "${RUN_FUZZ_TESTS:-false}" == true || "${RUN_FUNCTIONAL_TESTS:-true}" != true ]]; then
    return
  fi
  case "${CONTAINER_NAME:-}" in
    ci_native_asan|ci_native_tsan|ci_native_msan|ci_native_nowallet|\
    ci_native_previous_releases|ci_native_alpine_musl|ci_i686_no_multiprocess|ci_arm_linux) ;;
    *) return ;;
  esac

  local pocx_packages pocx_package pocx_capability pocx_has_capnp=false
  if [[ "${CI_IMAGE_NAME_TAG:-}" == *alpine* ]]; then
    pocx_packages='py3-bcc bcc-tools'
  else
    pocx_packages='python3-bpfcc bpfcc-tools python3-zmq'
    # The original runner allowed missing optional Python bindings to skip.
    # Strict enabled-feature coverage requires those dependencies in the image.
    # The i686 recipe explicitly disables IPC and does not need Cap'n Proto.
    if [[ "${CONTAINER_NAME}" != ci_i686_no_multiprocess ]]; then
      for pocx_package in ${PIP_PACKAGES:-}; do
        case "$pocx_package" in
          pycapnp|pycapnp==*) pocx_has_capnp=true ;;
        esac
      done
      if [[ "$pocx_has_capnp" == false ]]; then
        pocx_packages+=' python3-pip'
        # Ubuntu22.04's original pip predates this option and its Python is
        # not externally managed. Newer Debian/Ubuntu images require it.
        case "${CI_IMAGE_NAME_TAG:-}" in
          *ubuntu:22.04*) ;;
          *) case " ${PIP_PACKAGES:-} " in
               *' --break-system-packages '*) ;;
               *) export PIP_PACKAGES="${PIP_PACKAGES:-} --break-system-packages" ;;
             esac ;;
        esac
        export PIP_PACKAGES="${PIP_PACKAGES:-} pycapnp==2.2.4"
      fi
    fi
  fi
  for pocx_package in $pocx_packages; do
    case " ${PACKAGES:-} " in
      *" $pocx_package "*) ;;
      *) export PACKAGES="${PACKAGES:-} $pocx_package" ;;
    esac
  done
  for pocx_capability in '--privileged' \
    '-v /sys/kernel:/sys/kernel:rw' \
    '-v /usr/src:/usr/src:ro' '-v /lib/modules:/lib/modules:ro'; do
    case " ${CI_CONTAINER_CAP:-} " in
      *" $pocx_capability "*) ;;
      *) export CI_CONTAINER_CAP="${CI_CONTAINER_CAP:-} $pocx_capability" ;;
    esac
  done
}
pocx_prepare_tracing_runtime
unset -f pocx_prepare_tracing_runtime
