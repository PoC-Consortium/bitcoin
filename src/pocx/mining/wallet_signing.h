// Copyright (c) 2025 The Proof of Capacity Consortium
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_POCX_MINING_WALLET_SIGNING_H
#define BITCOIN_POCX_MINING_WALLET_SIGNING_H

#include <cstdint>
#include <string>
#include <uint256.h>

class CBlock;

namespace interfaces {
class Wallet;
}

namespace pocx {
namespace mining {

/** Outcome of probing a wallet for a PoCX account's signing key.
 *  Underlying type is fixed so the enum is forward-declarable from
 *  interfaces/wallet.h without pulling in this header. */
enum class AccountKeyAvailability : uint8_t {
    Available,    //!< Wallet holds the private key and can sign right now.
    Locked,       //!< Wallet holds an encrypted private key but is locked.
    Absent,       //!< Wallet does not hold a private key for this account.
};

/** Check if wallet has the key for a PoCX account.
 *  Internal helper used by the interfaces::Wallet implementation. */
AccountKeyAvailability HaveAccountKey(
    const std::string& account_id,
    interfaces::Wallet* wallet
);

/** Sign a PoCX block using wallet keys (supports descriptor and legacy wallets).
 *  Internal helper used by the interfaces::Wallet implementation. */
bool SignPoCXBlock(
    interfaces::Wallet* wallet,
    const uint256& block_hash,
    const std::string& account_id,
    CBlock& block
);

} // namespace mining
} // namespace pocx

#endif // BITCOIN_POCX_MINING_WALLET_SIGNING_H
