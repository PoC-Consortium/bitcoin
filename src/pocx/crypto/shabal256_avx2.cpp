// Copyright (c) 2025 The Proof of Capacity Consortium
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// AVX2 implementation of Shabal256 - processes 8 independent streams in parallel.
// Based on mshabal from PoC-Consortium/engraver, adapted for PoCX block validation.

#include <pocx/crypto/shabal256_avx2.h>

#include <cstdint>
#include <cstring>

#if defined(__x86_64__) || defined(__amd64__) || defined(__i386__)
#include <cpuid.h>
#endif

#ifdef ENABLE_AVX2
#include <immintrin.h>
#endif

namespace pocx {
namespace crypto {

// Runtime AVX2 detection with caching
static int g_have_avx2 = -1; // -1 = not checked, 0 = no, 1 = yes

bool HaveAVX2() {
    if (g_have_avx2 >= 0) {
        return g_have_avx2 == 1;
    }

#if defined(__x86_64__) || defined(__amd64__) || defined(__i386__)
    uint32_t eax, ebx, ecx, edx;

    // Check for CPUID support and get max function
    __cpuid_count(0, 0, eax, ebx, ecx, edx);
    if (eax < 7) {
        g_have_avx2 = 0;
        return false;
    }

    // Check for AVX support (CPUID.1:ECX.AVX[bit 28])
    __cpuid_count(1, 0, eax, ebx, ecx, edx);
    bool have_avx = (ecx >> 28) & 1;
    bool have_xsave = (ecx >> 27) & 1;

    if (!have_avx || !have_xsave) {
        g_have_avx2 = 0;
        return false;
    }

    // Check if OS has enabled AVX registers (xgetbv)
    uint32_t xcr0_lo, xcr0_hi;
    __asm__("xgetbv" : "=a"(xcr0_lo), "=d"(xcr0_hi) : "c"(0));
    if ((xcr0_lo & 6) != 6) {
        g_have_avx2 = 0;
        return false;
    }

    // Check for AVX2 support (CPUID.7:EBX.AVX2[bit 5])
    __cpuid_count(7, 0, eax, ebx, ecx, edx);
    bool have_avx2 = (ebx >> 5) & 1;

    g_have_avx2 = have_avx2 ? 1 : 0;
    return g_have_avx2 == 1;
#else
    g_have_avx2 = 0;
    return false;
#endif
}

#ifdef ENABLE_AVX2

// Shabal256 initial state constants (same as scalar version)
alignas(32) static const uint32_t A_INIT_AVX2[12] = {
    0x52F84552, 0xE54B7999, 0x2D8EE3EC, 0xB9645191,
    0xE0078B86, 0xBB7C44C9, 0xD2B5C1CA, 0xB0D2EB8C,
    0x14CE5A45, 0x22AF50DC, 0xEFFDBC6B, 0xEB21B74A,
};

alignas(32) static const uint32_t B_INIT_AVX2[16] = {
    0xB555C6EE, 0x3E710596, 0xA72A652F, 0x9301515F,
    0xDA28C1FA, 0x696FD868, 0x9CB6BF72, 0x0AFE4002,
    0xA6E03615, 0x5138C1D4, 0xBE216306, 0xB38B8890,
    0x3EA8B96B, 0x3299ACE4, 0x30924DD4, 0x55CB34A5,
};

alignas(32) static const uint32_t C_INIT_AVX2[16] = {
    0xB405F031, 0xC4233EBA, 0xB3733979, 0xC0DD9D55,
    0xC51C28AE, 0xA327B8E1, 0x56C56167, 0xED614433,
    0x88B59D60, 0x60E2CEBA, 0x758B4B8B, 0x83E82A7F,
    0xBC968828, 0xE6E00BF7, 0xBA839E55, 0x9B491C60,
};

// AVX2 helper functions
static inline __m256i add_epi32(__m256i a, __m256i b) {
    return _mm256_add_epi32(a, b);
}

static inline __m256i sub_epi32(__m256i a, __m256i b) {
    return _mm256_sub_epi32(a, b);
}

static inline __m256i xor_si256(__m256i a, __m256i b) {
    return _mm256_xor_si256(a, b);
}

static inline __m256i andnot_si256(__m256i a, __m256i b) {
    return _mm256_andnot_si256(a, b);
}

static inline __m256i or_si256(__m256i a, __m256i b) {
    return _mm256_or_si256(a, b);
}

// Rotate left by n bits
static inline __m256i rotl(__m256i x, int n) {
    return or_si256(_mm256_slli_epi32(x, n), _mm256_srli_epi32(x, 32 - n));
}

// Load 8 uint32_t values from 8 different sources at the same offset
static inline __m256i load8(const uint32_t* src[8], size_t offset) {
    return _mm256_set_epi32(
        src[7] ? src[7][offset] : 0,
        src[6] ? src[6][offset] : 0,
        src[5] ? src[5][offset] : 0,
        src[4] ? src[4][offset] : 0,
        src[3] ? src[3][offset] : 0,
        src[2] ? src[2][offset] : 0,
        src[1] ? src[1][offset] : 0,
        src[0] ? src[0][offset] : 0
    );
}

// Load 8 bytes from 8 different byte arrays and convert to __m256i of uint32_t
static inline __m256i load8_bytes(const uint8_t* src[8], size_t byte_offset) {
    uint32_t vals[8];
    for (int i = 0; i < 8; i++) {
        if (src[i]) {
            memcpy(&vals[i], src[i] + byte_offset, 4);
        } else {
            vals[i] = 0;
        }
    }
    return _mm256_set_epi32(vals[7], vals[6], vals[5], vals[4],
                           vals[3], vals[2], vals[1], vals[0]);
}

// Store 8 uint32_t values to 8 different destinations
static inline void store8(uint8_t* dst[8], size_t byte_offset, __m256i val) {
    alignas(32) uint32_t tmp[8];
    _mm256_store_si256((__m256i*)tmp, val);
    for (int i = 0; i < 8; i++) {
        if (dst[i]) {
            memcpy(dst[i] + byte_offset, &tmp[i], 4);
        }
    }
}

// Broadcast single uint32_t to all 8 lanes
static inline __m256i broadcast(uint32_t val) {
    return _mm256_set1_epi32(static_cast<int>(val));
}

// Shabal permutation element macro (PP256 equivalent)
#define PERM_ELT(a, b, xa0, xa1, xb0, xb1, xb2, xb3, xc, xm) do { \
    __m256i tmp = rotl(a[xa1], 15); \
    tmp = _mm256_mullo_epi32(tmp, broadcast(5)); \
    a[xa0] = xor_si256(a[xa0], tmp); \
    a[xa0] = xor_si256(a[xa0], xc); \
    a[xa0] = _mm256_mullo_epi32(a[xa0], broadcast(3)); \
    a[xa0] = xor_si256(a[xa0], b[xb1]); \
    a[xa0] = xor_si256(a[xa0], andnot_si256(b[xb3], b[xb2])); \
    a[xa0] = xor_si256(a[xa0], xm); \
    __m256i tmp2 = rotl(b[xb0], 1); \
    b[xb0] = _mm256_xor_si256(tmp2, a[xa0]); \
    b[xb0] = _mm256_xor_si256(b[xb0], _mm256_set1_epi32(-1)); \
} while(0)

// Full permutation (48 elements, 3 rounds of 16)
static inline void perm(__m256i a[12], __m256i b[16], const __m256i c[16], const __m256i m[16]) {
    PERM_ELT(a, b, 0, 11, 0, 13, 9, 6, c[8], m[0]);
    PERM_ELT(a, b, 1, 0, 1, 14, 10, 7, c[7], m[1]);
    PERM_ELT(a, b, 2, 1, 2, 15, 11, 8, c[6], m[2]);
    PERM_ELT(a, b, 3, 2, 3, 0, 12, 9, c[5], m[3]);
    PERM_ELT(a, b, 4, 3, 4, 1, 13, 10, c[4], m[4]);
    PERM_ELT(a, b, 5, 4, 5, 2, 14, 11, c[3], m[5]);
    PERM_ELT(a, b, 6, 5, 6, 3, 15, 12, c[2], m[6]);
    PERM_ELT(a, b, 7, 6, 7, 4, 0, 13, c[1], m[7]);
    PERM_ELT(a, b, 8, 7, 8, 5, 1, 14, c[0], m[8]);
    PERM_ELT(a, b, 9, 8, 9, 6, 2, 15, c[15], m[9]);
    PERM_ELT(a, b, 10, 9, 10, 7, 3, 0, c[14], m[10]);
    PERM_ELT(a, b, 11, 10, 11, 8, 4, 1, c[13], m[11]);

    PERM_ELT(a, b, 0, 11, 12, 9, 5, 2, c[12], m[12]);
    PERM_ELT(a, b, 1, 0, 13, 10, 6, 3, c[11], m[13]);
    PERM_ELT(a, b, 2, 1, 14, 11, 7, 4, c[10], m[14]);
    PERM_ELT(a, b, 3, 2, 15, 12, 8, 5, c[9], m[15]);
    PERM_ELT(a, b, 4, 3, 0, 13, 9, 6, c[8], m[0]);
    PERM_ELT(a, b, 5, 4, 1, 14, 10, 7, c[7], m[1]);
    PERM_ELT(a, b, 6, 5, 2, 15, 11, 8, c[6], m[2]);
    PERM_ELT(a, b, 7, 6, 3, 0, 12, 9, c[5], m[3]);
    PERM_ELT(a, b, 8, 7, 4, 1, 13, 10, c[4], m[4]);
    PERM_ELT(a, b, 9, 8, 5, 2, 14, 11, c[3], m[5]);
    PERM_ELT(a, b, 10, 9, 6, 3, 15, 12, c[2], m[6]);
    PERM_ELT(a, b, 11, 10, 7, 4, 0, 13, c[1], m[7]);

    PERM_ELT(a, b, 0, 11, 8, 5, 1, 14, c[0], m[8]);
    PERM_ELT(a, b, 1, 0, 9, 6, 2, 15, c[15], m[9]);
    PERM_ELT(a, b, 2, 1, 10, 7, 3, 0, c[14], m[10]);
    PERM_ELT(a, b, 3, 2, 11, 8, 4, 1, c[13], m[11]);
    PERM_ELT(a, b, 4, 3, 12, 9, 5, 2, c[12], m[12]);
    PERM_ELT(a, b, 5, 4, 13, 10, 6, 3, c[11], m[13]);
    PERM_ELT(a, b, 6, 5, 14, 11, 7, 4, c[10], m[14]);
    PERM_ELT(a, b, 7, 6, 15, 12, 8, 5, c[9], m[15]);
    PERM_ELT(a, b, 8, 7, 0, 13, 9, 6, c[8], m[0]);
    PERM_ELT(a, b, 9, 8, 1, 14, 10, 7, c[7], m[1]);
    PERM_ELT(a, b, 10, 9, 2, 15, 11, 8, c[6], m[2]);
    PERM_ELT(a, b, 11, 10, 3, 0, 12, 9, c[5], m[3]);

    PERM_ELT(a, b, 0, 11, 4, 1, 13, 10, c[4], m[4]);
    PERM_ELT(a, b, 1, 0, 5, 2, 14, 11, c[3], m[5]);
    PERM_ELT(a, b, 2, 1, 6, 3, 15, 12, c[2], m[6]);
    PERM_ELT(a, b, 3, 2, 7, 4, 0, 13, c[1], m[7]);
    PERM_ELT(a, b, 4, 3, 8, 5, 1, 14, c[0], m[8]);
    PERM_ELT(a, b, 5, 4, 9, 6, 2, 15, c[15], m[9]);
    PERM_ELT(a, b, 6, 5, 10, 7, 3, 0, c[14], m[10]);
    PERM_ELT(a, b, 7, 6, 11, 8, 4, 1, c[13], m[11]);
    PERM_ELT(a, b, 8, 7, 12, 9, 5, 2, c[12], m[12]);
    PERM_ELT(a, b, 9, 8, 13, 10, 6, 3, c[11], m[13]);
    PERM_ELT(a, b, 10, 9, 14, 11, 7, 4, c[10], m[14]);
    PERM_ELT(a, b, 11, 10, 15, 12, 8, 5, c[9], m[15]);
}

// Apply full round: add input to B, XOR counters to A, permute, add C to A, sub input from C, swap B/C
static inline void apply_round(__m256i a[12], __m256i b[16], __m256i c[16],
                        const __m256i m[16], __m256i w_low, __m256i w_high) {
    // B = B + M
    for (int i = 0; i < 16; i++) {
        b[i] = add_epi32(b[i], m[i]);
    }

    // A[0] ^= W_low, A[1] ^= W_high
    a[0] = xor_si256(a[0], w_low);
    a[1] = xor_si256(a[1], w_high);

    // Rotate B left by 17
    for (int i = 0; i < 16; i++) {
        b[i] = rotl(b[i], 17);
    }

    // Permutation
    perm(a, b, c, m);

    // Add C values to A
    a[0] = add_epi32(a[0], add_epi32(c[11], add_epi32(c[15], c[3])));
    a[1] = add_epi32(a[1], add_epi32(c[12], add_epi32(c[0], c[4])));
    a[2] = add_epi32(a[2], add_epi32(c[13], add_epi32(c[1], c[5])));
    a[3] = add_epi32(a[3], add_epi32(c[14], add_epi32(c[2], c[6])));
    a[4] = add_epi32(a[4], add_epi32(c[15], add_epi32(c[3], c[7])));
    a[5] = add_epi32(a[5], add_epi32(c[0], add_epi32(c[4], c[8])));
    a[6] = add_epi32(a[6], add_epi32(c[1], add_epi32(c[5], c[9])));
    a[7] = add_epi32(a[7], add_epi32(c[2], add_epi32(c[6], c[10])));
    a[8] = add_epi32(a[8], add_epi32(c[3], add_epi32(c[7], c[11])));
    a[9] = add_epi32(a[9], add_epi32(c[4], add_epi32(c[8], c[12])));
    a[10] = add_epi32(a[10], add_epi32(c[5], add_epi32(c[9], c[13])));
    a[11] = add_epi32(a[11], add_epi32(c[6], add_epi32(c[10], c[14])));

    // C = C - M
    for (int i = 0; i < 16; i++) {
        c[i] = sub_epi32(c[i], m[i]);
    }

    // Swap B and C
    for (int i = 0; i < 16; i++) {
        __m256i tmp = b[i];
        b[i] = c[i];
        c[i] = tmp;
    }
}

// apply_p: rotate B by 17, permute, add C values to A
static inline void apply_p(__m256i a[12], __m256i b[16], const __m256i c[16], const __m256i m[16]) {
    // Rotate B left by 17
    for (int i = 0; i < 16; i++) {
        b[i] = rotl(b[i], 17);
    }

    // Permutation
    perm(a, b, c, m);

    // Add C values to A
    a[0] = add_epi32(a[0], add_epi32(c[11], add_epi32(c[15], c[3])));
    a[1] = add_epi32(a[1], add_epi32(c[12], add_epi32(c[0], c[4])));
    a[2] = add_epi32(a[2], add_epi32(c[13], add_epi32(c[1], c[5])));
    a[3] = add_epi32(a[3], add_epi32(c[14], add_epi32(c[2], c[6])));
    a[4] = add_epi32(a[4], add_epi32(c[15], add_epi32(c[3], c[7])));
    a[5] = add_epi32(a[5], add_epi32(c[0], add_epi32(c[4], c[8])));
    a[6] = add_epi32(a[6], add_epi32(c[1], add_epi32(c[5], c[9])));
    a[7] = add_epi32(a[7], add_epi32(c[2], add_epi32(c[6], c[10])));
    a[8] = add_epi32(a[8], add_epi32(c[3], add_epi32(c[7], c[11])));
    a[9] = add_epi32(a[9], add_epi32(c[4], add_epi32(c[8], c[12])));
    a[10] = add_epi32(a[10], add_epi32(c[5], add_epi32(c[9], c[13])));
    a[11] = add_epi32(a[11], add_epi32(c[6], add_epi32(c[10], c[14])));
}

void Shabal256_avx2(
    const uint8_t* data[8],
    size_t len,
    const uint32_t* pre_term[8],
    const uint32_t* term[8],
    uint8_t* output[8]
) {
    // Initialize state - broadcast initial values to all 8 lanes
    __m256i a[12], b[16], c[16];
    for (int i = 0; i < 12; i++) {
        a[i] = broadcast(A_INIT_AVX2[i]);
    }
    for (int i = 0; i < 16; i++) {
        b[i] = broadcast(B_INIT_AVX2[i]);
        c[i] = broadcast(C_INIT_AVX2[i]);
    }

    // Message counters (same for all lanes)
    __m256i w_low = broadcast(1);
    __m256i w_high = broadcast(0);

    // Process data blocks (64 bytes each)
    size_t num_blocks = len >> 6;
    for (size_t block = 0; block < num_blocks; block++) {
        // Load message block from all 8 sources
        __m256i m[16];
        for (int i = 0; i < 16; i++) {
            m[i] = load8_bytes(data, block * 64 + i * 4);
        }

        apply_round(a, b, c, m, w_low, w_high);

        // Increment counter
        w_low = add_epi32(w_low, broadcast(1));
        // Handle carry (simplified - assumes no overflow in practice)
    }

    // Process pre-termination block if provided
    bool have_pre_term = false;
    for (int i = 0; i < 8; i++) {
        if (pre_term[i]) {
            have_pre_term = true;
            break;
        }
    }

    if (have_pre_term) {
        __m256i m[16];
        for (int i = 0; i < 16; i++) {
            m[i] = load8(pre_term, i);
        }

        apply_round(a, b, c, m, w_low, w_high);

        w_low = add_epi32(w_low, broadcast(1));
    }

    // Process termination block
    __m256i m[16];
    for (int i = 0; i < 16; i++) {
        m[i] = load8(term, i);
    }

    // First termination round: input_block_add(b, term), xor_w, apply_p
    // (no input_block_sub, no swap_bc after first term round)
    for (int i = 0; i < 16; i++) {
        b[i] = add_epi32(b[i], m[i]);
    }
    a[0] = xor_si256(a[0], w_low);
    a[1] = xor_si256(a[1], w_high);
    apply_p(a, b, c, m);

    // 3 more final rounds: swap_bc, xor_w, apply_p
    for (int round = 0; round < 3; round++) {
        // Swap B and C
        for (int i = 0; i < 16; i++) {
            __m256i tmp = b[i];
            b[i] = c[i];
            c[i] = tmp;
        }

        // xor_w
        a[0] = xor_si256(a[0], w_low);
        a[1] = xor_si256(a[1], w_high);

        // apply_p
        apply_p(a, b, c, m);
    }

    // Output: B[8..15] contains the hash (32 bytes = 8 uint32_t)
    for (int i = 0; i < 8; i++) {
        store8(output, i * 4, b[8 + i]);
    }
}

#endif // ENABLE_AVX2

} // namespace crypto
} // namespace pocx
