// Copyright (c) 2025 The Proof of Capacity Consortium
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pocx/crypto/shabal256_lite.h>
#include <cstring>

namespace pocx {
namespace crypto {

const uint32_t A_INIT_LITE[12] = {
    0x52F84552, 0xE54B7999, 0x2D8EE3EC, 0xB9645191, 0xE0078B86, 0xBB7C44C9, 
    0xD2B5C1CA, 0xB0D2EB8C, 0x14CE5A45, 0x22AF50DC, 0xEFFDBC6B, 0xEB21B74A,
};

const uint32_t B_INIT_LITE[16] = {
    0xB555C6EE, 0x3E710596, 0xA72A652F, 0x9301515F, 0xDA28C1FA, 0x696FD868, 
    0x9CB6BF72, 0x0AFE4002, 0xA6E03615, 0x5138C1D4, 0xBE216306, 0xB38B8890, 
    0x3EA8B96B, 0x3299ACE4, 0x30924DD4, 0x55CB34A5,
};

const uint32_t C_INIT_LITE[16] = {
    0xB405F031, 0xC4233EBA, 0xB3733979, 0xC0DD9D55, 0xC51C28AE, 0xA327B8E1, 
    0x56C56167, 0xED614433, 0x88B59D60, 0x60E2CEBA, 0x758B4B8B, 0x83E82A7F, 
    0xBC968828, 0xE6E00BF7, 0xBA839E55, 0x9B491C60,
};

inline void perm_elt_lite(uint32_t* a, uint32_t* b, int xa0, int xa1, int xb0, int xb1, 
                          int xb2, int xb3, uint32_t xc, uint32_t xm) {
    a[xa0] = (a[xa0] ^ (((a[xa1] << 15) | (a[xa1] >> 17)) * 5) ^ xc) * 3 
             ^ b[xb1] ^ (b[xb2] & ~b[xb3]) ^ xm;
    b[xb0] = ~(((b[xb0] << 1) | (b[xb0] >> 31)) ^ a[xa0]);
}

uint64_t Shabal256Lite(const uint8_t* data, const uint8_t* gensig) {
    uint32_t a[12], b[16], c[16];
    memcpy(a, A_INIT_LITE, sizeof(a));
    memcpy(b, B_INIT_LITE, sizeof(b));
    memcpy(c, C_INIT_LITE, sizeof(c));
    
    uint32_t w_high = 0;
    uint32_t w_low = 1;
    
    uint32_t data_aligned[16];
    memcpy(data_aligned, data, 64);
    
    uint32_t gensig_u32[8];
    memcpy(gensig_u32, gensig, 32);
    
    uint32_t term[8] = {0};
    term[0] = 0x80;
    for (int i = 0; i < 8; ++i) {
        b[i] += gensig_u32[i];
        b[i + 8] += data_aligned[i];
    }
    
    a[0] ^= w_low;
    a[1] ^= w_high;
    for (int i = 0; i < 16; ++i) {
        b[i] = (b[i] << 17) | (b[i] >> 15);
    }
    
    perm_elt_lite(a, b, 0, 11, 0, 13, 9, 6, c[8], gensig_u32[0]);
    perm_elt_lite(a, b, 1, 0, 1, 14, 10, 7, c[7], gensig_u32[1]);
    perm_elt_lite(a, b, 2, 1, 2, 15, 11, 8, c[6], gensig_u32[2]);
    perm_elt_lite(a, b, 3, 2, 3, 0, 12, 9, c[5], gensig_u32[3]);
    perm_elt_lite(a, b, 4, 3, 4, 1, 13, 10, c[4], gensig_u32[4]);
    perm_elt_lite(a, b, 5, 4, 5, 2, 14, 11, c[3], gensig_u32[5]);
    perm_elt_lite(a, b, 6, 5, 6, 3, 15, 12, c[2], gensig_u32[6]);
    perm_elt_lite(a, b, 7, 6, 7, 4, 0, 13, c[1], gensig_u32[7]);
    perm_elt_lite(a, b, 8, 7, 8, 5, 1, 14, c[0], data_aligned[0]);
    perm_elt_lite(a, b, 9, 8, 9, 6, 2, 15, c[15], data_aligned[1]);
    perm_elt_lite(a, b, 10, 9, 10, 7, 3, 0, c[14], data_aligned[2]);
    perm_elt_lite(a, b, 11, 10, 11, 8, 4, 1, c[13], data_aligned[3]);
    perm_elt_lite(a, b, 0, 11, 12, 9, 5, 2, c[12], data_aligned[4]);
    perm_elt_lite(a, b, 1, 0, 13, 10, 6, 3, c[11], data_aligned[5]);
    perm_elt_lite(a, b, 2, 1, 14, 11, 7, 4, c[10], data_aligned[6]);
    perm_elt_lite(a, b, 3, 2, 15, 12, 8, 5, c[9], data_aligned[7]);
    
    perm_elt_lite(a, b, 4, 3, 0, 13, 9, 6, c[8], gensig_u32[0]);
    perm_elt_lite(a, b, 5, 4, 1, 14, 10, 7, c[7], gensig_u32[1]);
    perm_elt_lite(a, b, 6, 5, 2, 15, 11, 8, c[6], gensig_u32[2]);
    perm_elt_lite(a, b, 7, 6, 3, 0, 12, 9, c[5], gensig_u32[3]);
    perm_elt_lite(a, b, 8, 7, 4, 1, 13, 10, c[4], gensig_u32[4]);
    perm_elt_lite(a, b, 9, 8, 5, 2, 14, 11, c[3], gensig_u32[5]);
    perm_elt_lite(a, b, 10, 9, 6, 3, 15, 12, c[2], gensig_u32[6]);
    perm_elt_lite(a, b, 11, 10, 7, 4, 0, 13, c[1], gensig_u32[7]);
    perm_elt_lite(a, b, 0, 11, 8, 5, 1, 14, c[0], data_aligned[0]);
    perm_elt_lite(a, b, 1, 0, 9, 6, 2, 15, c[15], data_aligned[1]);
    perm_elt_lite(a, b, 2, 1, 10, 7, 3, 0, c[14], data_aligned[2]);
    perm_elt_lite(a, b, 3, 2, 11, 8, 4, 1, c[13], data_aligned[3]);
    perm_elt_lite(a, b, 4, 3, 12, 9, 5, 2, c[12], data_aligned[4]);
    perm_elt_lite(a, b, 5, 4, 13, 10, 6, 3, c[11], data_aligned[5]);
    perm_elt_lite(a, b, 6, 5, 14, 11, 7, 4, c[10], data_aligned[6]);
    perm_elt_lite(a, b, 7, 6, 15, 12, 8, 5, c[9], data_aligned[7]);
    
    perm_elt_lite(a, b, 8, 7, 0, 13, 9, 6, c[8], gensig_u32[0]);
    perm_elt_lite(a, b, 9, 8, 1, 14, 10, 7, c[7], gensig_u32[1]);
    perm_elt_lite(a, b, 10, 9, 2, 15, 11, 8, c[6], gensig_u32[2]);
    perm_elt_lite(a, b, 11, 10, 3, 0, 12, 9, c[5], gensig_u32[3]);
    perm_elt_lite(a, b, 0, 11, 4, 1, 13, 10, c[4], gensig_u32[4]);
    perm_elt_lite(a, b, 1, 0, 5, 2, 14, 11, c[3], gensig_u32[5]);
    perm_elt_lite(a, b, 2, 1, 6, 3, 15, 12, c[2], gensig_u32[6]);
    perm_elt_lite(a, b, 3, 2, 7, 4, 0, 13, c[1], gensig_u32[7]);
    perm_elt_lite(a, b, 4, 3, 8, 5, 1, 14, c[0], data_aligned[0]);
    perm_elt_lite(a, b, 5, 4, 9, 6, 2, 15, c[15], data_aligned[1]);
    perm_elt_lite(a, b, 6, 5, 10, 7, 3, 0, c[14], data_aligned[2]);
    perm_elt_lite(a, b, 7, 6, 11, 8, 4, 1, c[13], data_aligned[3]);
    perm_elt_lite(a, b, 8, 7, 12, 9, 5, 2, c[12], data_aligned[4]);
    perm_elt_lite(a, b, 9, 8, 13, 10, 6, 3, c[11], data_aligned[5]);
    perm_elt_lite(a, b, 10, 9, 14, 11, 7, 4, c[10], data_aligned[6]);
    perm_elt_lite(a, b, 11, 10, 15, 12, 8, 5, c[9], data_aligned[7]);
    
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
    
    for (int i = 0; i < 8; ++i) {
        c[i] -= gensig_u32[i];
        c[i + 8] -= data_aligned[i];
    }
    
    for (int i = 0; i < 16; ++i) {
        uint32_t temp = b[i];
        b[i] = c[i];
        c[i] = temp;
    }
    
    ++w_low;
    if (w_low == 0) {
        ++w_high;
    }
    
    
    for (int i = 0; i < 8; ++i) {
        b[i] += data_aligned[i + 8];
        b[i + 8] += term[i];
    }
    
    a[0] ^= w_low;
    a[1] ^= w_high;
    for (int i = 0; i < 16; ++i) {
        b[i] = (b[i] << 17) | (b[i] >> 15);
    }
    
    perm_elt_lite(a, b, 0, 11, 0, 13, 9, 6, c[8], data_aligned[8]);
    perm_elt_lite(a, b, 1, 0, 1, 14, 10, 7, c[7], data_aligned[9]);
    perm_elt_lite(a, b, 2, 1, 2, 15, 11, 8, c[6], data_aligned[10]);
    perm_elt_lite(a, b, 3, 2, 3, 0, 12, 9, c[5], data_aligned[11]);
    perm_elt_lite(a, b, 4, 3, 4, 1, 13, 10, c[4], data_aligned[12]);
    perm_elt_lite(a, b, 5, 4, 5, 2, 14, 11, c[3], data_aligned[13]);
    perm_elt_lite(a, b, 6, 5, 6, 3, 15, 12, c[2], data_aligned[14]);
    perm_elt_lite(a, b, 7, 6, 7, 4, 0, 13, c[1], data_aligned[15]);
    perm_elt_lite(a, b, 8, 7, 8, 5, 1, 14, c[0], term[0]);
    perm_elt_lite(a, b, 9, 8, 9, 6, 2, 15, c[15], term[1]);
    perm_elt_lite(a, b, 10, 9, 10, 7, 3, 0, c[14], term[2]);
    perm_elt_lite(a, b, 11, 10, 11, 8, 4, 1, c[13], term[3]);
    perm_elt_lite(a, b, 0, 11, 12, 9, 5, 2, c[12], term[4]);
    perm_elt_lite(a, b, 1, 0, 13, 10, 6, 3, c[11], term[5]);
    perm_elt_lite(a, b, 2, 1, 14, 11, 7, 4, c[10], term[6]);
    perm_elt_lite(a, b, 3, 2, 15, 12, 8, 5, c[9], term[7]);
    
    perm_elt_lite(a, b, 4, 3, 0, 13, 9, 6, c[8], data_aligned[8]);
    perm_elt_lite(a, b, 5, 4, 1, 14, 10, 7, c[7], data_aligned[9]);
    perm_elt_lite(a, b, 6, 5, 2, 15, 11, 8, c[6], data_aligned[10]);
    perm_elt_lite(a, b, 7, 6, 3, 0, 12, 9, c[5], data_aligned[11]);
    perm_elt_lite(a, b, 8, 7, 4, 1, 13, 10, c[4], data_aligned[12]);
    perm_elt_lite(a, b, 9, 8, 5, 2, 14, 11, c[3], data_aligned[13]);
    perm_elt_lite(a, b, 10, 9, 6, 3, 15, 12, c[2], data_aligned[14]);
    perm_elt_lite(a, b, 11, 10, 7, 4, 0, 13, c[1], data_aligned[15]);
    perm_elt_lite(a, b, 0, 11, 8, 5, 1, 14, c[0], term[0]);
    perm_elt_lite(a, b, 1, 0, 9, 6, 2, 15, c[15], term[1]);
    perm_elt_lite(a, b, 2, 1, 10, 7, 3, 0, c[14], term[2]);
    perm_elt_lite(a, b, 3, 2, 11, 8, 4, 1, c[13], term[3]);
    perm_elt_lite(a, b, 4, 3, 12, 9, 5, 2, c[12], term[4]);
    perm_elt_lite(a, b, 5, 4, 13, 10, 6, 3, c[11], term[5]);
    perm_elt_lite(a, b, 6, 5, 14, 11, 7, 4, c[10], term[6]);
    perm_elt_lite(a, b, 7, 6, 15, 12, 8, 5, c[9], term[7]);
    
    perm_elt_lite(a, b, 8, 7, 0, 13, 9, 6, c[8], data_aligned[8]);
    perm_elt_lite(a, b, 9, 8, 1, 14, 10, 7, c[7], data_aligned[9]);
    perm_elt_lite(a, b, 10, 9, 2, 15, 11, 8, c[6], data_aligned[10]);
    perm_elt_lite(a, b, 11, 10, 3, 0, 12, 9, c[5], data_aligned[11]);
    perm_elt_lite(a, b, 0, 11, 4, 1, 13, 10, c[4], data_aligned[12]);
    perm_elt_lite(a, b, 1, 0, 5, 2, 14, 11, c[3], data_aligned[13]);
    perm_elt_lite(a, b, 2, 1, 6, 3, 15, 12, c[2], data_aligned[14]);
    perm_elt_lite(a, b, 3, 2, 7, 4, 0, 13, c[1], data_aligned[15]);
    perm_elt_lite(a, b, 4, 3, 8, 5, 1, 14, c[0], term[0]);
    perm_elt_lite(a, b, 5, 4, 9, 6, 2, 15, c[15], term[1]);
    perm_elt_lite(a, b, 6, 5, 10, 7, 3, 0, c[14], term[2]);
    perm_elt_lite(a, b, 7, 6, 11, 8, 4, 1, c[13], term[3]);
    perm_elt_lite(a, b, 8, 7, 12, 9, 5, 2, c[12], term[4]);
    perm_elt_lite(a, b, 9, 8, 13, 10, 6, 3, c[11], term[5]);
    perm_elt_lite(a, b, 10, 9, 14, 11, 7, 4, c[10], term[6]);
    perm_elt_lite(a, b, 11, 10, 15, 12, 8, 5, c[9], term[7]);
    
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
    
    for (int loop = 0; loop < 3; ++loop) {
        for (int i = 0; i < 16; ++i) {
            uint32_t temp = b[i];
            b[i] = c[i];
            c[i] = temp;
        }
        
        a[0] ^= w_low;
        a[1] ^= w_high;
        for (int i = 0; i < 16; ++i) {
            b[i] = (b[i] << 17) | (b[i] >> 15);
        }
        
        perm_elt_lite(a, b, 0, 11, 0, 13, 9, 6, c[8], data_aligned[8]);
        perm_elt_lite(a, b, 1, 0, 1, 14, 10, 7, c[7], data_aligned[9]);
        perm_elt_lite(a, b, 2, 1, 2, 15, 11, 8, c[6], data_aligned[10]);
        perm_elt_lite(a, b, 3, 2, 3, 0, 12, 9, c[5], data_aligned[11]);
        perm_elt_lite(a, b, 4, 3, 4, 1, 13, 10, c[4], data_aligned[12]);
        perm_elt_lite(a, b, 5, 4, 5, 2, 14, 11, c[3], data_aligned[13]);
        perm_elt_lite(a, b, 6, 5, 6, 3, 15, 12, c[2], data_aligned[14]);
        perm_elt_lite(a, b, 7, 6, 7, 4, 0, 13, c[1], data_aligned[15]);
        perm_elt_lite(a, b, 8, 7, 8, 5, 1, 14, c[0], term[0]);
        perm_elt_lite(a, b, 9, 8, 9, 6, 2, 15, c[15], term[1]);
        perm_elt_lite(a, b, 10, 9, 10, 7, 3, 0, c[14], term[2]);
        perm_elt_lite(a, b, 11, 10, 11, 8, 4, 1, c[13], term[3]);
        perm_elt_lite(a, b, 0, 11, 12, 9, 5, 2, c[12], term[4]);
        perm_elt_lite(a, b, 1, 0, 13, 10, 6, 3, c[11], term[5]);
        perm_elt_lite(a, b, 2, 1, 14, 11, 7, 4, c[10], term[6]);
        perm_elt_lite(a, b, 3, 2, 15, 12, 8, 5, c[9], term[7]);
        
        perm_elt_lite(a, b, 4, 3, 0, 13, 9, 6, c[8], data_aligned[8]);
        perm_elt_lite(a, b, 5, 4, 1, 14, 10, 7, c[7], data_aligned[9]);
        perm_elt_lite(a, b, 6, 5, 2, 15, 11, 8, c[6], data_aligned[10]);
        perm_elt_lite(a, b, 7, 6, 3, 0, 12, 9, c[5], data_aligned[11]);
        perm_elt_lite(a, b, 8, 7, 4, 1, 13, 10, c[4], data_aligned[12]);
        perm_elt_lite(a, b, 9, 8, 5, 2, 14, 11, c[3], data_aligned[13]);
        perm_elt_lite(a, b, 10, 9, 6, 3, 15, 12, c[2], data_aligned[14]);
        perm_elt_lite(a, b, 11, 10, 7, 4, 0, 13, c[1], data_aligned[15]);
        perm_elt_lite(a, b, 0, 11, 8, 5, 1, 14, c[0], term[0]);
        perm_elt_lite(a, b, 1, 0, 9, 6, 2, 15, c[15], term[1]);
        perm_elt_lite(a, b, 2, 1, 10, 7, 3, 0, c[14], term[2]);
        perm_elt_lite(a, b, 3, 2, 11, 8, 4, 1, c[13], term[3]);
        perm_elt_lite(a, b, 4, 3, 12, 9, 5, 2, c[12], term[4]);
        perm_elt_lite(a, b, 5, 4, 13, 10, 6, 3, c[11], term[5]);
        perm_elt_lite(a, b, 6, 5, 14, 11, 7, 4, c[10], term[6]);
        perm_elt_lite(a, b, 7, 6, 15, 12, 8, 5, c[9], term[7]);
        
        perm_elt_lite(a, b, 8, 7, 0, 13, 9, 6, c[8], data_aligned[8]);
        perm_elt_lite(a, b, 9, 8, 1, 14, 10, 7, c[7], data_aligned[9]);
        perm_elt_lite(a, b, 10, 9, 2, 15, 11, 8, c[6], data_aligned[10]);
        perm_elt_lite(a, b, 11, 10, 3, 0, 12, 9, c[5], data_aligned[11]);
        perm_elt_lite(a, b, 0, 11, 4, 1, 13, 10, c[4], data_aligned[12]);
        perm_elt_lite(a, b, 1, 0, 5, 2, 14, 11, c[3], data_aligned[13]);
        perm_elt_lite(a, b, 2, 1, 6, 3, 15, 12, c[2], data_aligned[14]);
        perm_elt_lite(a, b, 3, 2, 7, 4, 0, 13, c[1], data_aligned[15]);
        perm_elt_lite(a, b, 4, 3, 8, 5, 1, 14, c[0], term[0]);
        perm_elt_lite(a, b, 5, 4, 9, 6, 2, 15, c[15], term[1]);
        perm_elt_lite(a, b, 6, 5, 10, 7, 3, 0, c[14], term[2]);
        perm_elt_lite(a, b, 7, 6, 11, 8, 4, 1, c[13], term[3]);
        perm_elt_lite(a, b, 8, 7, 12, 9, 5, 2, c[12], term[4]);
        perm_elt_lite(a, b, 9, 8, 13, 10, 6, 3, c[11], term[5]);
        perm_elt_lite(a, b, 10, 9, 14, 11, 7, 4, c[10], term[6]);
        perm_elt_lite(a, b, 11, 10, 15, 12, 8, 5, c[9], term[7]);
        
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
    
    const uint64_t* b_u64 = reinterpret_cast<const uint64_t*>(b);
    return b_u64[4];
}

} // namespace crypto
} // namespace pocx