// Copyright (c) 2024-2025 The Bitcoin PoCX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_POCX_POCX_SEEDS_H
#define BITCOIN_POCX_POCX_SEEDS_H

#include <cstdint>
#include <string>
#include <vector>

// PoCX Testnet DNS Seeds
inline const std::vector<std::string> pocx_testnet_dns_seeds = {
    "testnet.seeds.bitcoin-pocx.org.",
};

// PoCX Testnet Fixed Seeds (BIP155 format)
// Format: 0x01=IPv4, 0x04=length, 4 IP bytes, 2 port bytes (big endian)
// Port 18338 = 0x47A2
inline const uint8_t pocx_seed_testnet[] = {
    0x01,0x04, 0x05,0x4e,0x7e,0x11, 0x47,0xa2,  // 5.78.126.17:18338
    0x01,0x04, 0x4e,0x2f,0xde,0x5b, 0x47,0xa2,  // 78.47.222.91:18338
    0x01,0x04, 0x2e,0xe0,0x52,0x27, 0x47,0xa2,  // 46.224.82.39:18338
};

// PoCX Mainnet DNS Seeds (to be configured before mainnet launch)
inline const std::vector<std::string> pocx_mainnet_dns_seeds = {
    // TODO: Add mainnet DNS seeds before launch
};

// #POCXTODO PoCX Mainnet Fixed Seeds (to be configured before mainnet launch)
inline const uint8_t pocx_seed_main[] = {0x00};

#endif // BITCOIN_POCX_POCX_SEEDS_H
