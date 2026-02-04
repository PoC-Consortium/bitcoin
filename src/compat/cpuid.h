// Copyright (c) 2017-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_COMPAT_CPUID_H
#define BITCOIN_COMPAT_CPUID_H

#if defined(__x86_64__) || defined(__amd64__) || defined(__i386__) || defined(_M_X64) || defined(_M_IX86)
#define HAVE_GETCPUID

#include <cstdint>

#if defined(_MSC_VER)
#include <intrin.h>
#else
#include <cpuid.h>
#endif

// We can't use cpuid.h's __get_cpuid as it does not support subleafs.
void static inline GetCPUID(uint32_t leaf, uint32_t subleaf, uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d)
{
#if defined(_MSC_VER)
    int regs[4];
    __cpuidex(regs, leaf, subleaf);
    a = regs[0];
    b = regs[1];
    c = regs[2];
    d = regs[3];
#elif defined(__GNUC__)
    __cpuid_count(leaf, subleaf, a, b, c, d);
#else
  __asm__ ("cpuid" : "=a"(a), "=b"(b), "=c"(c), "=d"(d) : "0"(leaf), "2"(subleaf));
#endif
}

#endif // defined(__x86_64__) || defined(__amd64__) || defined(__i386__) || defined(_M_X64) || defined(_M_IX86)
#endif // BITCOIN_COMPAT_CPUID_H
