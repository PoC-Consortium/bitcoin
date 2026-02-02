// Copyright (c) 2025 The Proof of Capacity Consortium
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/params.h>
#include <interfaces/mining.h>
#include <interfaces/wallet.h>
#include <logging.h>
#include <node/context.h>
#include <rpc/server.h>
#include <rpc/server_util.h>
#include <rpc/util.h>
#include <util/strencodings.h>
#include <validation.h>

#include <pocx/consensus/params.h>
#include <pocx/algorithms/time_bending.h>
#include <pocx/algorithms/encoding.h>
#include <pocx/consensus/proof.h>
#include <pocx/assignments/assignment_state.h>
#include <pocx/mining/scheduler.h>
#include <pocx/mining/wallet_signing.h>
#include <pocx/consensus/difficulty.h>
#include <pocx/rpc/assignments.h>
#include <wallet/wallet.h>

#include <limits>
#include <mutex>

using interfaces::Mining;
using node::NodeContext;

namespace pocx {
namespace rpc {

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
                {RPCResult::Type::NUM, "target_quality", "Target quality (optional)"},
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

            auto context = pocx::consensus::GetNewBlockContext(chainman);
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

/**
 * Submit mining nonce (PoCX protocol compatible)
 * Validates and submits nonce with full PoCX parameters
 */
static RPCHelpMan submit_nonce()
{
    return RPCHelpMan{"submit_nonce",
        "Submit a PoCX nonce solution.\n",
        {
            {"height", RPCArg::Type::NUM, RPCArg::Optional::NO, "Block height for this submission"},
            {"generation_signature", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Generation signature"},
            {"account_id", RPCArg::Type::STR, RPCArg::Optional::NO, "Account ID (20-byte hex or address)"},
            {"seed", RPCArg::Type::STR, RPCArg::Optional::NO, "Plot seed"},
            {"nonce", RPCArg::Type::NUM, RPCArg::Optional::NO, "Mining nonce"},
            {"compression", RPCArg::Type::NUM, RPCArg::Optional::NO, "Compression level used (1-6)"},
            {"quality", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Quality value (optional, not used by server)"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::NUM, "quality", "Adjusted quality (raw_quality / base_target)"},
                {RPCResult::Type::NUM, "poc_time", "Time to find nonce (milliseconds)"},
            }
        },
        RPCExamples{
            HelpExampleCli("submit_nonce", "12345 \"abcdef123456...\" \"1234567890abcdef1234567890abcdef12345678\" \"plot_seed\" 999888777 1 null")
            + HelpExampleRpc("submit_nonce", "12345, \"abcdef123456...\", \"1234567890abcdef1234567890abcdef12345678\", \"plot_seed\", 999888777, 1, null")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            NodeContext& node = EnsureAnyNodeContext(request.context);
            ChainstateManager& chainman = EnsureChainman(node);
            
            // Parse PoCX protocol parameters
            int height = request.params[0].getInt<int>();
            std::string generation_signature = request.params[1].get_str();
            std::string account_id = request.params[2].get_str();
            std::string seed = request.params[3].get_str();
            uint64_t nonce = request.params[4].getInt<uint64_t>();
            uint32_t compression = static_cast<uint32_t>(request.params[5].getInt<int>());

            // Optional parameters
            uint64_t quality = (request.params.size() > 6 && !request.params[6].isNull()) ?
                               request.params[6].getInt<uint64_t>() : 0;
            (void)quality; // Suppress unused parameter warning
            
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
                auto context = pocx::consensus::GetNewBlockContext(chainman);

                // 3. Quick context comparisons
                // Validate height matches current tip + 1
                if (height != context.height) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Invalid height: expected %d, got %d", context.height, height));
                }

                // Generation signature validation
                auto submitted_gen_sig = uint256::FromHex(generation_signature);
                if (!submitted_gen_sig || *submitted_gen_sig != context.generation_signature) {
                    throw JSONRPCError(RPC_VERIFY_REJECTED, "Generation signature mismatch");
                }

                // 4. Wallet verification (before expensive proof work)
                if (node.wallet_loader) {
                    auto wallets = node.wallet_loader->getWallets();
                    bool has_key = false;
                    std::string effective_signer_account = account_id;

                    // Check for assignments to get the effective signer
                    {
                        LOCK(cs_main);
                        auto& active_chainstate = chainman.ActiveChainstate();
                        const CCoinsViewCache& view = active_chainstate.CoinsTip();

                        // Get effective signer considering assignments
                        std::array<uint8_t, 20> effective_signer = pocx::assignments::GetEffectiveSigner(*account_id_parsed, height, view);
                        effective_signer_account = HexStr(effective_signer);

                        if (effective_signer_account != account_id) {
                            LogPrintf("PoCX: Plot %s has assignment, checking key for effective signer: %s\n",
                                    account_id.c_str(), effective_signer_account.c_str());
                        }
                    }

                    // Check if we have the key for the effective signer
                    for (auto& wallet : wallets) {
                        if (pocx::mining::HaveAccountKey(effective_signer_account, wallet.get())) {
                            has_key = true;
                            break;
                        }
                    }
                    if (!has_key) {
                        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY,
                            strprintf("No private key available for effective signer %s (plot: %s)",
                                     effective_signer_account, account_id));
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
                uint64_t raw_quality = validation_result.quality;           // Raw quality from disk
                uint64_t deadline_seconds = raw_quality / context.base_target;  // Difficulty-adjusted deadline (seconds)
                uint64_t forge_time = pocx::algorithms::CalculateTimeBendedDeadline(raw_quality, context.base_target, consensusParams.nPowTargetSpacing);  // Time Bended forge time
                
                // Concise success logging with result
                LogPrintLevel(BCLog::POCX, BCLog::Level::Info,
                             "nonce=%llu height=%d gensig=...%s account=...%s seed=...%s raw_quality=%llu deadline=%lus forge_time=%lus -> ACK\n",
                             nonce, height,
                             generation_signature.substr(std::max(0, (int)generation_signature.length()-8)),
                             account_id.substr(std::max(0, (int)account_id.length()-8)),
                             seed.substr(std::max(0, (int)seed.length()-8)),
                             raw_quality, deadline_seconds, forge_time);
                
                // Initialize scheduler and submit for timed forging
                Mining& miner = EnsureMining(node);
                EnsurePoCXScheduler(miner);
                if (!g_pocx_scheduler) {
                    throw JSONRPCError(RPC_INTERNAL_ERROR, "Failed to initialize PoCX scheduler");
                }

                bool queued = g_pocx_scheduler->SubmitNonce(
                    account_id, seed, nonce, raw_quality, compression, height, *submitted_gen_sig
                );

                if (!queued) {
                    throw JSONRPCError(RPC_CLIENT_IN_INITIAL_DOWNLOAD, "Submission queue is full, please try again later");
                }

                result.pushKV("accepted", true);
                result.pushKV("quality", deadline_seconds);  // Difficulty-adjusted deadline (seconds)
                result.pushKV("poc_time", forge_time);  // Time Bended forge time (seconds)
                
                return result;
                
            } catch (const std::exception& e) {
                result.pushKV("accepted", false);
                result.pushKV("error", e.what());
            }
            
            return result;
        },
    };
}

std::span<const CRPCCommand> GetMiningRPCCommands()
{
    static const CRPCCommand commands[]{
        {"mining", &get_mining_info},
        {"mining", &submit_nonce},
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

