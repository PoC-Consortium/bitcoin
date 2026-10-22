# Copyright (c) 2023-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

add_library(bitcoin_crypto STATIC EXCLUDE_FROM_ALL
  aes.cpp
  chacha20.cpp
  chacha20poly1305.cpp
  hex_base.cpp
  hkdf_sha256_32.cpp
  hmac_sha256.cpp
  hmac_sha512.cpp
  muhash.cpp
  poly1305.cpp
  ripemd160.cpp
  sha1.cpp
  sha256.cpp
  sha256_sse4.cpp
  sha3.cpp
  sha512.cpp
  siphash.cpp
  ../support/cleanse.cpp
)
# Add PoCX crypto sources when enabled
if(ENABLE_POCX)
  target_sources(bitcoin_crypto PRIVATE
    ../pocx/crypto/shabal256.cpp
    ../pocx/crypto/shabal256_lite.cpp
  )
  # Add PoCX AVX2 sources if available (ENABLE_AVX2 already defined by SHA256 block below)
  if(HAVE_AVX2)
    target_sources(bitcoin_crypto PRIVATE
      ../pocx/crypto/shabal256_avx2.cpp
    )
    set_property(SOURCE ../pocx/crypto/shabal256_avx2.cpp PROPERTY
      COMPILE_OPTIONS ${AVX2_CXXFLAGS}
    )
  endif()
  # Add PoCX SSE2 sources (baseline on x86-64, no special flags needed)
  if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|amd64|AMD64")
    target_compile_definitions(bitcoin_crypto PRIVATE ENABLE_SSE2)
    target_sources(bitcoin_crypto PRIVATE
      ../pocx/crypto/shabal256_sse2.cpp
    )
  endif()
endif()

target_link_libraries(bitcoin_crypto
  PRIVATE
    core_interface
)

if(HAVE_SSE41)
  target_compile_definitions(bitcoin_crypto PRIVATE ENABLE_SSE41)
  target_sources(bitcoin_crypto PRIVATE sha256_sse41.cpp)
  set_property(SOURCE sha256_sse41.cpp PROPERTY
    COMPILE_OPTIONS ${SSE41_CXXFLAGS}
  )
endif()

if(HAVE_AVX2)
  target_compile_definitions(bitcoin_crypto PRIVATE ENABLE_AVX2)
  target_sources(bitcoin_crypto PRIVATE sha256_avx2.cpp)
  set_property(SOURCE sha256_avx2.cpp PROPERTY
    COMPILE_OPTIONS ${AVX2_CXXFLAGS}
  )
endif()

if(HAVE_SSE41 AND HAVE_X86_SHANI)
  target_compile_definitions(bitcoin_crypto PRIVATE ENABLE_SSE41 ENABLE_X86_SHANI)
  target_sources(bitcoin_crypto PRIVATE sha256_x86_shani.cpp)
  set_property(SOURCE sha256_x86_shani.cpp PROPERTY
    COMPILE_OPTIONS ${SSE41_CXXFLAGS} ${X86_SHANI_CXXFLAGS}
  )
endif()

if(HAVE_ARM_SHANI)
  target_compile_definitions(bitcoin_crypto PRIVATE ENABLE_ARM_SHANI)
  target_sources(bitcoin_crypto PRIVATE sha256_arm_shani.cpp)
  set_property(SOURCE sha256_arm_shani.cpp PROPERTY
    COMPILE_OPTIONS ${ARM_SHANI_CXXFLAGS}
  )
endif()
