// Copyright (c) 2025 The Proof of Capacity Consortium
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_POCX_ASSIGNMENTS_TRANSACTIONS_H
#define BITCOIN_POCX_ASSIGNMENTS_TRANSACTIONS_H

#include <primitives/transaction.h>
#include <consensus/amount.h>
#include <util/result.h>
#include <string>

namespace wallet {
class CWallet;
class CCoinControl;
}

namespace pocx {
namespace assignments {

/** Create a forging assignment transaction (must spend from plot address to prove ownership) */
util::Result<CTransactionRef> CreateForgingAssignmentTransaction(
    ::wallet::CWallet& wallet,
    const std::string& plotAddress,
    const std::string& forgingAddress,
    const ::wallet::CCoinControl& coin_control,
    CAmount& fee
);

/** Create a forging revocation transaction (must spend from plot address to prove ownership) */
util::Result<CTransactionRef> CreateForgingRevocationTransaction(
    ::wallet::CWallet& wallet,
    const std::string& plotAddress,
    const ::wallet::CCoinControl& coin_control,
    CAmount& fee
);

} // namespace assignments
} // namespace pocx

#endif // BITCOIN_POCX_ASSIGNMENTS_TRANSACTIONS_H