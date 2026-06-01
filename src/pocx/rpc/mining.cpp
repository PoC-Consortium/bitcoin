// Copyright (c) 2025 The Proof of Capacity Consortium
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bitcoin-build-config.h> // IWYU pragma: keep

#include <consensus/params.h>
#include <interfaces/mining.h>
#include <logging.h>
#include <node/context.h>
#include <rpc/server.h>
#include <rpc/server_util.h>
#include <rpc/util.h>
#include <util/strencodings.h>
#include <validation.h>

#include <pocx/consensus/params.h>
#include <pocx/consensus/difficulty.h>
#include <pocx/mining/block_context.h>
#include <pocx/mining/wallet_signing.h>
#include <pocx/rpc/assignments.h>

#ifdef ENABLE_WALLET
#include <addresstype.h>
#include <consensus/amount.h>
#include <interfaces/wallet.h>
#include <key_io.h>
#include <primitives/transaction.h>
#include <pocx/algorithms/time_bending.h>
#include <pocx/algorithms/encoding.h>
#include <pocx/consensus/proof.h>
#include <pocx/assignments/assignment_state.h>
#include <pocx/mining/scheduler.h>
#include <wallet/wallet.h>
#endif

#include <limits>
#include <mutex>

#ifdef ENABLE_WALLET
using interfaces::Mining;
#endif
using node::NodeContext;

namespace pocx {
namespace rpc {

#ifdef ENABLE_WALLET
// Global scheduler instance for handling PoCX mining deadlines
static std::unique_ptr<pocx::mining::PoCXScheduler> g_pocx_scheduler;
static std::mutex g_scheduler_init_mutex;  // Protects scheduler initialization

// Initialize PoCX scheduler (called from RPC when first needed)
static void EnsurePoCXScheduler(interfaces::Mining& mining) {
    std::lock_guard<std::mutex> lock(g_scheduler_init_mutex);
    if (!g_pocx_scheduler) {
        g_pocx_scheduler = std::make_unique<pocx::mining::PoCXScheduler>(mining);
        LogPrintf("PoCX: Scheduler initialized\n");
    }
}
#endif

/**
 * Get mining information
 * Returns height, generationSignature, baseTarget, targetDeadline
 */
static RPCHelpMan get_mining_info()
{
    return RPCHelpMan{"get_mining_info",
        "Get current mining information.\n",
        {},
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "generation_signature", "Current block generation signature"},
                {RPCResult::Type::NUM, "base_target", "Current difficulty base target"},
                {RPCResult::Type::NUM, "height", "Next block height"},
                {RPCResult::Type::STR_HEX, "block_hash", "Previous block hash"},
                {RPCResult::Type::NUM, "target_quality", "Target quality threshold (uint64 max when unused)"},
                {RPCResult::Type::NUM, "minimum_compression_level", "Minimum compression level for validation"},
                {RPCResult::Type::NUM, "target_compression_level", "Target compression level for optimization"},
            }
        },
        RPCExamples{
            HelpExampleCli("get_mining_info", "")
            + HelpExampleRpc("get_mining_info", "")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            NodeContext& node = EnsureAnyNodeContext(request.context);
            const ChainstateManager& chainman = EnsureChainman(node);

            if (chainman.m_blockman.LoadingBlocks()) {
                throw JSONRPCError(RPC_CLIENT_IN_INITIAL_DOWNLOAD, "Is initial block downloading!");
            }

            auto context = pocx::mining::GetNewBlockContext(chainman);
            const Consensus::Params& consensusParams = chainman.GetParams().GetConsensus();
            auto compression_bounds = pocx::consensus::GetPoCXCompressionBounds(context.height, consensusParams.nSubsidyHalvingInterval);

            UniValue result(UniValue::VOBJ);
            result.pushKV("generation_signature", context.generation_signature.ToString());
            result.pushKV("base_target", context.base_target);
            result.pushKV("height", context.height);
            result.pushKV("block_hash", context.block_hash.ToString());
            result.pushKV("target_quality", std::numeric_limits<uint64_t>::max());
            result.pushKV("minimum_compression_level", static_cast<int>(compression_bounds.nPoCXMinCompression));
            result.pushKV("target_compression_level", static_cast<int>(compression_bounds.nPoCXTargetCompression));
            return result;
        },
    };
}

#ifdef ENABLE_WALLET
/**
 * Submit mining nonce (PoCX protocol compatible)
 * Validates and submits nonce with full PoCX parameters
 */
static RPCHelpMan submit_nonce()
{
    return RPCHelpMan{"submit_nonce",
        "Submit a PoCX nonce solution.\n",
        {
            {"block_hash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Previous block hash"},
            {"height", RPCArg::Type::NUM, RPCArg::Optional::NO, "Block height for this submission"},
            {"generation_signature", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Generation signature"},
            {"base_target", RPCArg::Type::NUM, RPCArg::Optional::NO, "Base target for this block"},
            {"account_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Account ID (40 hex characters)"},
            {"seed", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Plot seed (64 hex characters)"},
            {"nonce", RPCArg::Type::NUM, RPCArg::Optional::NO, "Mining nonce"},
            {"compression", RPCArg::Type::NUM, RPCArg::Optional::NO, "Compression level used (1-6)"},
            {"raw_quality", RPCArg::Type::NUM, RPCArg::Optional::NO, "Raw quality from proof validation (advisory; server re-validates)"},
            {"coinbase_outputs", RPCArg::Type::ARR, RPCArg::Optional::OMITTED,
                "Optional pool payout split. If provided, the node builds the coinbase from these outputs and "
                "routes any remainder (unallocated reward plus all fees) to the effective signer. Absent => a "
                "single output to the effective signer (legacy behavior, unchanged).",
                {
                    {"", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "",
                        {
                            {"address", RPCArg::Type::STR, RPCArg::Optional::NO, "Payout destination address"},
                            {"amount_sat", RPCArg::Type::NUM, RPCArg::Optional::NO, "Payout amount in satoshis"},
                        },
                    },
                },
            },
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::NUM, "raw_quality", "Raw quality from proof validation"},
                {RPCResult::Type::NUM, "poc_time", "Time-bended forge time in seconds"},
            }
        },
        RPCExamples{
            HelpExampleCli("submit_nonce", "\"blockhash...\" 12345 \"gensig...\" 18325193796 \"1234567890abcdef1234567890abcdef12345678\" \"seed...\" 999888777 1 123456789")
            + HelpExampleRpc("submit_nonce", "\"blockhash...\", 12345, \"gensig...\", 18325193796, \"1234567890abcdef1234567890abcdef12345678\", \"seed...\", 999888777, 1, 123456789")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            NodeContext& node = EnsureAnyNodeContext(request.context);
            ChainstateManager& chainman = EnsureChainman(node);

            // Parse PoCX protocol parameters
            std::string block_hash = request.params[0].get_str();
            int height = request.params[1].getInt<int>();
            std::string generation_signature = request.params[2].get_str();
            uint64_t base_target = request.params[3].getInt<uint64_t>();
            std::string account_id = request.params[4].get_str();
            std::string seed = request.params[5].get_str();
            uint64_t nonce = request.params[6].getInt<uint64_t>();
            uint32_t compression = static_cast<uint32_t>(request.params[7].getInt<int>());
            uint64_t submitted_raw_quality = request.params[8].getInt<uint64_t>();

            // Optional pool payout split (Q1): [{address, amount_sat}, ...].
            // Validate at the boundary (Core won't reject a bad address downstream -
            // it would silently pay an unspendable script). Amounts are satoshis;
            // MoneyRange rejects negative / out-of-range. Absent => legacy path.
            std::vector<CTxOut> coinbase_outputs;
            if (request.params.size() > 9 && !request.params[9].isNull()) {
                for (const UniValue& entry : request.params[9].get_array().getValues()) {
                    const UniValue& addr_v = entry.find_value("address");
                    const UniValue& amt_v = entry.find_value("amount_sat");
                    if (!addr_v.isStr()) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "coinbase_outputs: each entry needs a string 'address'");
                    }
                    CTxDestination dest = DecodeDestination(addr_v.get_str());
                    if (!IsValidDestination(dest)) {
                        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY,
                                           strprintf("coinbase_outputs: invalid address %s", addr_v.get_str()));
                    }
                    if (!amt_v.isNum()) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "coinbase_outputs: each entry needs an integer 'amount_sat'");
                    }
                    const int64_t amount_sat = amt_v.getInt<int64_t>();
                    if (!MoneyRange(amount_sat)) {
                        throw JSONRPCError(RPC_TYPE_ERROR,
                                           strprintf("coinbase_outputs: amount_sat %d out of range", amount_sat));
                    }
                    coinbase_outputs.emplace_back(amount_sat, GetScriptForDestination(dest));
                }
            }

            UniValue result(UniValue::VOBJ);

            try {
                // 1. Fast format validation (fail early)
                // Account ID format validation
                if (account_id.length() != 40 || !IsHex(account_id)) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid account_id format - must be 40 hex characters");
                }

                // Seed format validation
                if (seed.length() != 64 || !IsHex(seed)) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid seed format - must be 64 hex characters");
                }

                // Parse account ID
                auto account_id_parsed = pocx::algorithms::ParseAccountID(account_id.c_str());
                if (!account_id_parsed) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid account_id format");
                }

                // Parse seed
                auto seed_bytes = ParseHex(seed);  // 64 hex chars → 32 bytes

                // 2. Get current block context (handles cs_main internally)
                auto context = pocx::mining::GetNewBlockContext(chainman);

                // 3. Quick context comparisons
                // Validate height matches current tip + 1
                if (height != context.height) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Invalid height: expected %d, got %d", context.height, height));
                }

                // Block hash validation
                auto submitted_block_hash = uint256::FromHex(block_hash);
                if (!submitted_block_hash || *submitted_block_hash != context.block_hash) {
                    throw JSONRPCError(RPC_VERIFY_REJECTED, "Block hash mismatch");
                }

                // Generation signature validation
                auto submitted_gen_sig = uint256::FromHex(generation_signature);
                if (!submitted_gen_sig || *submitted_gen_sig != context.generation_signature) {
                    throw JSONRPCError(RPC_VERIFY_REJECTED, "Generation signature mismatch");
                }

                // Base target validation
                if (base_target != context.base_target) {
                    throw JSONRPCError(RPC_VERIFY_REJECTED, strprintf("Base target mismatch: expected %llu, got %llu", context.base_target, base_target));
                }

                // 4. Wallet verification (before expensive proof work)
                if (node.wallet_loader) {
                    auto wallets = node.wallet_loader->getWallets();
                    std::string effective_signer_account = account_id;

                    // Render a 20-byte hash160 as its bech32 P2WPKH address for user-facing messages.
                    auto to_bech32 = [](const std::array<uint8_t, 20>& h) {
                        uint160 u; std::copy(h.begin(), h.end(), u.begin());
                        return EncodeDestination(WitnessV0KeyHash{u});
                    };
                    const std::string plot_address = to_bech32(*account_id_parsed);
                    std::string effective_signer_address = plot_address;

                    // Check for assignments to get the effective signer
                    {
                        LOCK(cs_main);
                        auto& active_chainstate = chainman.ActiveChainstate();
                        const CCoinsViewCache& view = active_chainstate.CoinsTip();

                        // Get effective signer considering assignments
                        std::array<uint8_t, 20> effective_signer = pocx::assignments::GetEffectiveSigner(*account_id_parsed, height, view);
                        effective_signer_account = HexStr(effective_signer);
                        effective_signer_address = to_bech32(effective_signer);

                        if (effective_signer_account != account_id) {
                            LogPrintf("PoCX: Plot %s has assignment, checking key for effective signer: %s\n",
                                    plot_address, effective_signer_address);
                        }
                    }

                    // Probe every loaded wallet. An Available outcome is enough to
                    // proceed; if every match is Locked we route to RPC_WALLET_UNLOCK_NEEDED
                    // so the operator gets the helpful "unlock first" message instead of
                    // a generic "no key" error.
                    auto availability = pocx::mining::AccountKeyAvailability::Absent;
                    for (auto& wallet : wallets) {
                        auto r = wallet->haveAccountKey(effective_signer_account);
                        if (r == pocx::mining::AccountKeyAvailability::Available) {
                            availability = r;
                            break;
                        }
                        if (r == pocx::mining::AccountKeyAvailability::Locked) {
                            availability = r;
                        }
                    }
                    if (availability == pocx::mining::AccountKeyAvailability::Locked) {
                        throw JSONRPCError(RPC_WALLET_UNLOCK_NEEDED,
                            strprintf("Wallet holding key for effective signer %s is locked - "
                                      "unlock with walletpassphrase first",
                                      effective_signer_address));
                    }
                    if (availability == pocx::mining::AccountKeyAvailability::Absent) {
                        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY,
                            strprintf("No private key available for effective signer %s (plot: %s)",
                                     effective_signer_address, plot_address));
                    }
                }

                // 5. Validate compression against bounds (before expensive proof validation)
                const Consensus::Params& consensusParams = chainman.GetParams().GetConsensus();
                auto compression_bounds = pocx::consensus::GetPoCXCompressionBounds(context.height, consensusParams.nSubsidyHalvingInterval);
                uint32_t min_compression = compression_bounds.nPoCXMinCompression;
                uint32_t max_compression = compression_bounds.nPoCXTargetCompression;

                if (compression < min_compression || compression > max_compression) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER,
                                      strprintf("Invalid compression level %u: must be in range [%u, %u]",
                                               compression, min_compression, max_compression));
                }

                // 6. Expensive proof validation (validate only the claimed compression level)

                pocx::consensus::ValidationResult validation_result;
                bool validation_success = pocx::consensus::pocx_validate_block(
                    generation_signature.c_str(),
                    context.base_target,
                    account_id_parsed->data(),
                    static_cast<uint64_t>(height),
                    nonce,
                    seed_bytes.data(),
                    compression,
                    &validation_result
                );

                if (!validation_success || !validation_result.is_valid) {
                    throw JSONRPCError(RPC_VERIFY_REJECTED, strprintf("PoCX validation failed: success=%s, is_valid=%s, error_code=%d",
                                                    validation_success ? "true" : "false",
                                                    validation_result.is_valid ? "true" : "false",
                                                    validation_result.error_code));
                }

                // Calculate deadlines
                uint64_t raw_quality = validation_result.quality;           // Raw quality from proof validation
                (void)submitted_raw_quality;  // Server validates independently; miner-submitted value not used
                uint64_t forge_time = pocx::algorithms::CalculateTimeBendedDeadline(raw_quality, context.base_target, consensusParams.nPowTargetSpacing);  // Time Bended forge time

                // Concise success logging with result
                LogPrintLevel(BCLog::POCX, BCLog::Level::Info,
                             "nonce=%llu height=%d gensig=...%s account=...%s seed=...%s raw_quality=%llu forge_time=%lus -> ACK\n",
                             nonce, height,
                             generation_signature.substr(std::max(0, (int)generation_signature.length()-8)),
                             account_id.substr(std::max(0, (int)account_id.length()-8)),
                             seed.substr(std::max(0, (int)seed.length()-8)),
                             raw_quality, forge_time);

                // Initialize scheduler and submit for timed forging
                Mining& miner = EnsureMining(node);
                EnsurePoCXScheduler(miner);
                if (!g_pocx_scheduler) {
                    throw JSONRPCError(RPC_INTERNAL_ERROR, "Failed to initialize PoCX scheduler");
                }

                bool queued = g_pocx_scheduler->SubmitNonce(
                    account_id, seed, nonce, raw_quality, compression, *submitted_block_hash, coinbase_outputs
                );

                if (!queued) {
                    throw JSONRPCError(RPC_CLIENT_IN_INITIAL_DOWNLOAD, "Submission queue is full, please try again later");
                }

                result.pushKV("raw_quality", raw_quality);
                result.pushKV("poc_time", forge_time);

                return result;

            } catch (const std::exception& e) {
                throw JSONRPCError(RPC_INTERNAL_ERROR, e.what());
            }
        },
    };
}
#endif // ENABLE_WALLET

std::span<const CRPCCommand> GetMiningRPCCommands()
{
    static const CRPCCommand commands[]{
        {"mining", &get_mining_info},
#ifdef ENABLE_WALLET
        {"mining", &submit_nonce},
#endif
    };
    return commands;
}

void RegisterPoCXRPCCommands(CRPCTable& t)
{
    for (const auto& c : GetMiningRPCCommands()) {
        t.appendCommand(c.name, &c);
    }

    for (const auto& c : GetAssignmentsNodeRPCCommands()) {
        t.appendCommand(c.name, &c);
    }
}

} // namespace rpc
} // namespace pocx

