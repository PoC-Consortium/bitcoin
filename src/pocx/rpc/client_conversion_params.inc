// Copyright (c) 2026 The Bitcoin PoCX developers
// Distributed under the MIT software license; see COPYING.
// Initializer fragment for the ENABLE_POCX branch of the RPC client table.
    { "create_assignment", 2, "fee_rate" },
    { "revoke_assignment", 1, "fee_rate" },
    { "get_assignment", 1, "height" },
    { "submit_nonce", 1, "height" },
    { "submit_nonce", 3, "base_target" },
    { "submit_nonce", 6, "nonce" },
    { "submit_nonce", 7, "compression" },
    { "submit_nonce", 8, "raw_quality" },
    { "submit_nonce", 9, "coinbase_outputs" },
