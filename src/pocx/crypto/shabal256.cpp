// Copyright (c) 2025 The Proof of Capacity Consortium
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pocx/crypto/shabal256.h>
#include <cstring>

namespace pocx {
namespace crypto {

const uint32_t A_INIT[12] = {
    0x52F84552, 0xE54B7999, 0x2D8EE3EC, 0xB9645191, 0xE0078B86, 0xBB7C44C9,
    0xD2B5C1CA, 0xB0D2EB8C, 0x14CE5A45, 0x22AF50DC, 0xEFFDBC6B, 0xEB21B74A,
};

const uint32_t B_INIT[16] = {
    0xB555C6EE, 0x3E710596, 0xA72A652F, 0x9301515F, 0xDA28C1FA, 0x696FD868,
    0x9CB6BF72, 0x0AFE4002, 0xA6E03615, 0x5138C1D4, 0xBE216306, 0xB38B8890,
    0x3EA8B96B, 0x3299ACE4, 0x30924DD4, 0x55CB34A5,
};

const uint32_t C_INIT[16] = {
    0xB405F031, 0xC4233EBA, 0xB3733979, 0xC0DD9D55, 0xC51C28AE, 0xA327B8E1,
    0x56C56167, 0xED614433, 0x88B59D60, 0x60E2CEBA, 0x758B4B8B, 0x83E82A7F,
    0xBC968828, 0xE6E00BF7, 0xBA839E55, 0x9B491C60,
};

inline void input_block_add(uint32_t* b, const uint32_t* data) {
    for (int i = 0; i < 16; ++i) {
        b[i] += data[i];
    }
}


inline void input_block_sub(uint32_t* c, const uint32_t* data) {
    for (int i = 0; i < 16; ++i) {
        c[i] -= data[i];
    }
}


inline void xor_w(uint32_t* a, uint32_t w_low, uint32_t w_high) {
    a[0] ^= w_low;
    a[1] ^= w_high;
}

inline void perm_elt(uint32_t* a, uint32_t* b, int xa0, int xa1, int xb0, int xb1,
                     int xb2, int xb3, uint32_t xc, uint32_t xm) {
    a[xa0] = (a[xa0] ^ (((a[xa1] << 15) | (a[xa1] >> 17)) * 5) ^ xc) * 3
             ^ b[xb1] ^ (b[xb2] & ~b[xb3]) ^ xm;
    b[xb0] = ~(((b[xb0] << 1) | (b[xb0] >> 31)) ^ a[xa0]);
}

inline void perm(uint32_t* a, uint32_t* b, const uint32_t* c, const uint32_t* data) {
    perm_elt(a, b, 0, 11, 0, 13, 9, 6, c[8], data[0]);
    perm_elt(a, b, 1, 0, 1, 14, 10, 7, c[7], data[1]);
    perm_elt(a, b, 2, 1, 2, 15, 11, 8, c[6], data[2]);
    perm_elt(a, b, 3, 2, 3, 0, 12, 9, c[5], data[3]);
    perm_elt(a, b, 4, 3, 4, 1, 13, 10, c[4], data[4]);
    perm_elt(a, b, 5, 4, 5, 2, 14, 11, c[3], data[5]);
    perm_elt(a, b, 6, 5, 6, 3, 15, 12, c[2], data[6]);
    perm_elt(a, b, 7, 6, 7, 4, 0, 13, c[1], data[7]);
    perm_elt(a, b, 8, 7, 8, 5, 1, 14, c[0], data[8]);
    perm_elt(a, b, 9, 8, 9, 6, 2, 15, c[15], data[9]);
    perm_elt(a, b, 10, 9, 10, 7, 3, 0, c[14], data[10]);
    perm_elt(a, b, 11, 10, 11, 8, 4, 1, c[13], data[11]);
    perm_elt(a, b, 0, 11, 12, 9, 5, 2, c[12], data[12]);
    perm_elt(a, b, 1, 0, 13, 10, 6, 3, c[11], data[13]);
    perm_elt(a, b, 2, 1, 14, 11, 7, 4, c[10], data[14]);
    perm_elt(a, b, 3, 2, 15, 12, 8, 5, c[9], data[15]);
    perm_elt(a, b, 4, 3, 0, 13, 9, 6, c[8], data[0]);
    perm_elt(a, b, 5, 4, 1, 14, 10, 7, c[7], data[1]);
    perm_elt(a, b, 6, 5, 2, 15, 11, 8, c[6], data[2]);
    perm_elt(a, b, 7, 6, 3, 0, 12, 9, c[5], data[3]);
    perm_elt(a, b, 8, 7, 4, 1, 13, 10, c[4], data[4]);
    perm_elt(a, b, 9, 8, 5, 2, 14, 11, c[3], data[5]);
    perm_elt(a, b, 10, 9, 6, 3, 15, 12, c[2], data[6]);
    perm_elt(a, b, 11, 10, 7, 4, 0, 13, c[1], data[7]);
    perm_elt(a, b, 0, 11, 8, 5, 1, 14, c[0], data[8]);
    perm_elt(a, b, 1, 0, 9, 6, 2, 15, c[15], data[9]);
    perm_elt(a, b, 2, 1, 10, 7, 3, 0, c[14], data[10]);
    perm_elt(a, b, 3, 2, 11, 8, 4, 1, c[13], data[11]);
    perm_elt(a, b, 4, 3, 12, 9, 5, 2, c[12], data[12]);
    perm_elt(a, b, 5, 4, 13, 10, 6, 3, c[11], data[13]);
    perm_elt(a, b, 6, 5, 14, 11, 7, 4, c[10], data[14]);
    perm_elt(a, b, 7, 6, 15, 12, 8, 5, c[9], data[15]);
    perm_elt(a, b, 8, 7, 0, 13, 9, 6, c[8], data[0]);
    perm_elt(a, b, 9, 8, 1, 14, 10, 7, c[7], data[1]);
    perm_elt(a, b, 10, 9, 2, 15, 11, 8, c[6], data[2]);
    perm_elt(a, b, 11, 10, 3, 0, 12, 9, c[5], data[3]);
    perm_elt(a, b, 0, 11, 4, 1, 13, 10, c[4], data[4]);
    perm_elt(a, b, 1, 0, 5, 2, 14, 11, c[3], data[5]);
    perm_elt(a, b, 2, 1, 6, 3, 15, 12, c[2], data[6]);
    perm_elt(a, b, 3, 2, 7, 4, 0, 13, c[1], data[7]);
    perm_elt(a, b, 4, 3, 8, 5, 1, 14, c[0], data[8]);
    perm_elt(a, b, 5, 4, 9, 6, 2, 15, c[15], data[9]);
    perm_elt(a, b, 6, 5, 10, 7, 3, 0, c[14], data[10]);
    perm_elt(a, b, 7, 6, 11, 8, 4, 1, c[13], data[11]);
    perm_elt(a, b, 8, 7, 12, 9, 5, 2, c[12], data[12]);
    perm_elt(a, b, 9, 8, 13, 10, 6, 3, c[11], data[13]);
    perm_elt(a, b, 10, 9, 14, 11, 7, 4, c[10], data[14]);
    perm_elt(a, b, 11, 10, 15, 12, 8, 5, c[9], data[15]);
}

inline void apply_p(uint32_t* a, uint32_t* b, const uint32_t* c, const uint32_t* data) {
    for (int i = 0; i < 16; ++i) {
        b[i] = (b[i] << 17) | (b[i] >> 15);
    }
    perm(a, b, c, data);
    a[0] += c[11] + c[15] + c[3];
    a[1] += c[12] + c[0] + c[4];
    a[2] += c[13] + c[1] + c[5];
    a[3] += c[14] + c[2] + c[6];
    a[4] += c[15] + c[3] + c[7];
    a[5] += c[0] + c[4] + c[8];
    a[6] += c[1] + c[5] + c[9];
    a[7] += c[2] + c[6] + c[10];
    a[8] += c[3] + c[7] + c[11];
    a[9] += c[4] + c[8] + c[12];
    a[10] += c[5] + c[9] + c[13];
    a[11] += c[6] + c[10] + c[14];
}

inline void swap_bc(uint32_t* b, uint32_t* c) {
    for (int i = 0; i < 16; ++i) {
        uint32_t temp = b[i];
        b[i] = c[i];
        c[i] = temp;
    }
}

inline void incr_w(uint32_t* w_low, uint32_t* w_high) {
    ++(*w_low);
    if (*w_low == 0) {
        ++(*w_high);
    }
}

void Shabal256(const uint8_t* data, size_t len, const uint32_t* pre_term, const uint32_t* term, uint8_t* output) {
    uint32_t a[12], b[16], c[16];
    memcpy(a, A_INIT, sizeof(a));
    memcpy(b, B_INIT, sizeof(b));
    memcpy(c, C_INIT, sizeof(c));

    uint32_t w_high = 0;
    uint32_t w_low = 1;
    size_t num = len >> 6;
    size_t ptr = 0;

    uint32_t* data_aligned = nullptr;
    if (len > 0) {
        data_aligned = reinterpret_cast<uint32_t*>(const_cast<uint8_t*>(data));
    }
    while (num > 0) {
        input_block_add(b, &data_aligned[ptr]);
        xor_w(a, w_low, w_high);
        apply_p(a, b, c, &data_aligned[ptr]);
        input_block_sub(c, &data_aligned[ptr]);
        swap_bc(b, c);
        incr_w(&w_low, &w_high);
        ptr += 16;
        --num;
    }

    if (pre_term) {
        input_block_add(b, pre_term);
        xor_w(a, w_low, w_high);
        apply_p(a, b, c, pre_term);
        input_block_sub(c, pre_term);
        swap_bc(b, c);
        incr_w(&w_low, &w_high);
    }

    input_block_add(b, term);
    xor_w(a, w_low, w_high);
    apply_p(a, b, c, term);

    for (int i = 0; i < 3; ++i) {
        swap_bc(b, c);
        xor_w(a, w_low, w_high);
        apply_p(a, b, c, term);
    }

    memcpy(output, &b[8], 32);
}

} // namespace crypto
} // namespace pocx

// Runtime SIMD detection functions - always compiled here.
// The actual SIMD implementations are in shabal256_avx2.cpp and shabal256_sse2.cpp.
#include <pocx/crypto/shabal256_avx2.h>
#include <pocx/crypto/shabal256_sse2.h>

// Platform-specific includes for CPUID
#if defined(_M_X64) || defined(_M_IX86)
// MSVC on x86/x64
#include <intrin.h>
#define POCX_HAVE_CPUID
#elif defined(__x86_64__) || defined(__amd64__) || defined(__i386__)
// GCC/Clang on x86/x64
#include <cpuid.h>
#define POCX_HAVE_CPUID
#endif

namespace pocx {
namespace crypto {

static int g_have_avx2 = -1; // -1 = not checked, 0 = no, 1 = yes
static int g_have_sse2 = -1;

#ifdef POCX_HAVE_CPUID
static inline void pocx_cpuid(uint32_t leaf, uint32_t subleaf, uint32_t& eax, uint32_t& ebx, uint32_t& ecx, uint32_t& edx)
{
#if defined(_MSC_VER)
    int regs[4];
    __cpuidex(regs, leaf, subleaf);
    eax = regs[0];
    ebx = regs[1];
    ecx = regs[2];
    edx = regs[3];
#else
    __cpuid_count(leaf, subleaf, eax, ebx, ecx, edx);
#endif
}
#endif

bool HaveAVX2() {
    if (g_have_avx2 >= 0) {
        return g_have_avx2 == 1;
    }

#ifdef POCX_HAVE_CPUID
    uint32_t eax, ebx, ecx, edx;

    // Check for CPUID support and get max function
    pocx_cpuid(0, 0, eax, ebx, ecx, edx);
    if (eax < 7) {
        g_have_avx2 = 0;
        return false;
    }

    // Check for AVX support (CPUID.1:ECX.AVX[bit 28])
    pocx_cpuid(1, 0, eax, ebx, ecx, edx);
    bool have_avx = (ecx >> 28) & 1;
    bool have_xsave = (ecx >> 27) & 1;

    if (!have_avx || !have_xsave) {
        g_have_avx2 = 0;
        return false;
    }

    // Check if OS has enabled AVX registers (xgetbv)
#if defined(_MSC_VER)
    unsigned long long xcr0 = _xgetbv(0);
    if ((xcr0 & 6) != 6) {
        g_have_avx2 = 0;
        return false;
    }
#else
    uint32_t xcr0_lo, xcr0_hi;
    __asm__("xgetbv" : "=a"(xcr0_lo), "=d"(xcr0_hi) : "c"(0));
    if ((xcr0_lo & 6) != 6) {
        g_have_avx2 = 0;
        return false;
    }
#endif

    // Check for AVX2 support (CPUID.7:EBX.AVX2[bit 5])
    pocx_cpuid(7, 0, eax, ebx, ecx, edx);
    bool have_avx2 = (ebx >> 5) & 1;

    g_have_avx2 = have_avx2 ? 1 : 0;
    return g_have_avx2 == 1;
#else
    g_have_avx2 = 0;
    return false;
#endif
}

bool HaveSSE2() {
    if (g_have_sse2 >= 0) {
        return g_have_sse2 == 1;
    }

#ifdef POCX_HAVE_CPUID
    uint32_t eax, ebx, ecx, edx;

    // Check for CPUID support and get max function
    pocx_cpuid(0, 0, eax, ebx, ecx, edx);
    if (eax < 1) {
        g_have_sse2 = 0;
        return false;
    }

    // Check for SSE2 support (CPUID.1:EDX.SSE2[bit 26])
    pocx_cpuid(1, 0, eax, ebx, ecx, edx);
    bool have_sse2 = (edx >> 26) & 1;

    g_have_sse2 = have_sse2 ? 1 : 0;
    return g_have_sse2 == 1;
#else
    g_have_sse2 = 0;
    return false;
#endif
}

} // namespace crypto
} // namespace pocx
