// Copyright (c) 2025 The Proof of Capacity Consortium
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pocx/mining/scheduler.h>
#include <pocx/mining/submission.h>
#include <pocx/mining/wallet_signing.h>
#include <pocx/consensus/difficulty.h>
#include <pocx/consensus/signature.h>
#include <pocx/consensus/params.h>
#include <pocx/algorithms/time_bending.h>

#include <chain.h>
#include <logging.h>
#include <node/context.h>
#include <sync.h>
#include <util/check.h>
#include <validation.h>

namespace {
    std::atomic<pocx::mining::PoCXScheduler*> g_pocx_scheduler_instance{nullptr};
}

namespace pocx {
namespace mining {

PoCXScheduler* GetPoCXScheduler() {
    return g_pocx_scheduler_instance.load();
}

PoCXScheduler::PoCXScheduler(interfaces::Mining& mining)
    : m_shutdown(false), m_mining(&mining), m_block_builder(mining) {
    // Register global instance for validation access
    g_pocx_scheduler_instance.store(this);
    // Start persistent worker thread
    m_worker_thread = std::thread(&PoCXScheduler::WorkerThreadFunc, this);
}

PoCXScheduler::~PoCXScheduler() {
    Shutdown();
    g_pocx_scheduler_instance.store(nullptr);
}

bool PoCXScheduler::SubmitNonce(const std::string& account_id,
                                const std::string& seed,
                                uint64_t nonce,
                                uint64_t quality,
                                uint32_t compression,
                                const uint256& block_hash) {

    // Create submission for queue (validation already done in RPC)
    NonceSubmission submission(
        account_id,
        seed,
        nonce,
        quality,
        compression,
        block_hash
    );

    // Add to queue with DoS protection
    {
        std::lock_guard<std::mutex> lock(m_queue_mutex);

        // Reject if queue is full (prevent DoS)
        if (m_submission_queue.size() >= MAX_QUEUE_SIZE) {
            LogPrintf("PoCX: [Scheduler] Submission queue full (%zu entries), rejecting submission\n",
                     MAX_QUEUE_SIZE);
            return false;
        }

        m_submission_queue.push(std::move(submission));
    }
    // Notify worker thread
    m_queue_cv.notify_one();
    return true;
}

void PoCXScheduler::Shutdown() {
    if (m_shutdown.exchange(true)) {
        return; // Already shutdown
    }

    LogPrintf("PoCX: [Scheduler] Shutting down worker thread\n");

    // Wake up worker thread for shutdown
    m_queue_cv.notify_all();

    // Wait for worker thread to finish
    if (m_worker_thread.joinable()) {
        m_worker_thread.join();
    }

    LogPrintf("PoCX: [Scheduler] Shutdown complete\n");
}

bool PoCXScheduler::TryDefensiveForge(const uint256& tip_hash, uint64_t incoming_quality) {
    std::lock_guard<std::mutex> lock(m_forging_mutex);

    if (!m_current_forging) {
        LogPrintf("PoCX: [DefensiveCheck] Incoming quality: %llu, Our best: (none) -> ACCEPTED\n",
                 incoming_quality);
        return false;
    }

    if (m_current_forging->tip_block_hash != tip_hash) {
        LogPrintf("PoCX: [DefensiveCheck] Incoming quality: %llu, Tip mismatch (ours: %s, theirs: %s) -> ACCEPTED\n",
                 incoming_quality,
                 m_current_forging->tip_block_hash.ToString().substr(0, 16).c_str(),
                 tip_hash.ToString().substr(0, 16).c_str());
        return false;
    }

    uint64_t our_quality = m_current_forging->quality;

    if (our_quality >= incoming_quality) {
        // Incoming is equal or better (lower quality value = better)
        LogPrintf("PoCX: [DefensiveCheck] Incoming quality: %llu, Our best: %llu -> ACCEPTED\n",
                 incoming_quality, our_quality);
        return false;
    }

    // Our quality is BETTER (lower is better) - signal defensive forge
    auto now = std::chrono::system_clock::now();
    auto seconds_early = std::chrono::duration_cast<std::chrono::seconds>(
        m_current_forging->forge_time - now).count();

    LogPrintf("PoCX: [DefensiveCheck] Incoming quality: %llu, Our best: %llu -> DEFENDING (%ld sec early)\n",
             incoming_quality, our_quality, seconds_early);

    m_defensive_forge_requested.store(true);
    m_queue_cv.notify_all();  // Wake worker thread

    return true;  // Caller should reject incoming block
}

void PoCXScheduler::WorkerThreadFunc() {

    while (!m_shutdown.load()) {
        try {
            // Check for defensive forge request FIRST (highest priority)
            if (m_defensive_forge_requested.exchange(false)) {
                LogPrintf("PoCX: [Scheduler] RUSHING BLOCK for defensive forging!\n");

                bool should_forge = false;
                {
                    std::lock_guard<std::mutex> lock(m_forging_mutex);
                    should_forge = m_current_forging && !m_current_forging->cancelled.load();
                }

                if (should_forge) {
                    bool success = ForgeBlock(true);  // defensive = true
                    if (success) {
                        LogPrintf("PoCX: [Scheduler] Defensive forge SUCCESS\n");
                    } else {
                        LogPrintf("PoCX: [Scheduler] Defensive forge FAILED\n");
                    }

                    std::lock_guard<std::mutex> lock(m_forging_mutex);
                    m_current_forging.reset();
                } else {
                    LogPrintf("PoCX: [Scheduler] Defensive forge skipped - no valid forging state\n");
                }
                continue;
            }

            NonceSubmission submission;
            bool has_submission = false;

            // Try to get submission from queue (non-blocking check first)
            {
                std::unique_lock<std::mutex> lock(m_queue_mutex);
                if (!m_submission_queue.empty()) {
                    submission = std::move(m_submission_queue.front());
                    m_submission_queue.pop();
                    has_submission = true;
                }
            }

            if (has_submission) {
                // Process the submission immediately
                ProcessSubmission(submission);
                continue; // Check queue again immediately
            }

            // Queue is empty - check if we should wait for deadline or more submissions
            bool should_wait = false;
            {
                std::lock_guard<std::mutex> lock(m_forging_mutex);
                should_wait = m_current_forging && !m_current_forging->cancelled.load();
            }

            if (should_wait) {
                // We have a nonce to forge - wait for deadline OR new submission
                WaitForDeadlineOrNewSubmission();
            } else {
                // No current forging - wait for new submission
                std::unique_lock<std::mutex> lock(m_queue_mutex);
                m_queue_cv.wait_for(lock, std::chrono::seconds(30), [this] {
                    return !m_submission_queue.empty() || m_shutdown.load() ||
                           m_defensive_forge_requested.load();
                });
            }

            if (m_shutdown.load()) {
                break;
            }

        } catch (const std::exception& e) {
            LogPrintf("PoCX: [Scheduler] Exception in worker thread: %s\n", e.what());
            std::lock_guard<std::mutex> lock(m_forging_mutex);
            m_current_forging.reset();
        }
    }

    LogPrintf("PoCX: [Scheduler] Worker thread stopped\n");
}

void PoCXScheduler::ProcessSubmission(const NonceSubmission& submission) {
    // Get current block context and validate submission staleness
    auto* node_context = m_mining->context();
    if (!node_context || !node_context->chainman) {
        return; // No context available - discard silently
    }

    auto current_context = pocx::consensus::GetNewBlockContext(*node_context->chainman);

    // Validate submission staleness (single block_hash comparison)
    if (!SubmissionValidator::ValidateContext(submission, current_context.block_hash)) {
        return; // Stale submission - discard silently
    }

    // Get block time for forge scheduling (context.block_hash already confirmed tip match)
    int64_t block_time = 0;
    {
        LOCK(cs_main);
        auto* tip = node_context->chainman->ActiveChain().Tip();
        if (tip) {
            block_time = tip->nTime;
        }
    }

    // Calculate deadline using Time Bending
    uint64_t deadline_seconds = pocx::algorithms::CalculateTimeBendedDeadline(
        submission.quality, current_context.base_target,
        node_context->chainman->GetParams().GetConsensus().nPowTargetSpacing);

    // Check if better and update state (under lock)
    {
        std::lock_guard<std::mutex> lock(m_forging_mutex);

        // Check if better than current best FOR SAME TIP
        // If tip changed, this is a new competition - accept any valid submission
        std::optional<uint64_t> current_quality;
        if (m_current_forging && m_current_forging->tip_block_hash == current_context.block_hash) {
            current_quality = m_current_forging->quality;
        }
        if (!SubmissionValidator::IsBetterThanCurrent(submission.quality, current_quality)) {
            return; // Not better - discard
        }

        // This is better - cancel current forging if exists
        if (m_current_forging) {
            m_current_forging->cancelled = true;
        }

        // Set new forging state
        m_current_forging = std::make_unique<ForgingState>();
        m_current_forging->account_id = submission.account_id;
        m_current_forging->seed = submission.seed;
        m_current_forging->nonce = submission.nonce;
        m_current_forging->quality = submission.quality;
        m_current_forging->compression = submission.compression;
        m_current_forging->deadline_seconds = deadline_seconds;
        m_current_forging->base_target = current_context.base_target;
        m_current_forging->tip_block_hash = current_context.block_hash;
        m_current_forging->cancelled = false;

        // Store block time and calculate forge time
        m_current_forging->block_time = block_time;
        m_current_forging->forge_time = std::chrono::system_clock::from_time_t(block_time) +
                                       std::chrono::seconds(deadline_seconds);

        LogPrintf("PoCX: [Scheduler] New best solution - tip: %s, quality: %llu, deadline: %llu sec\n",
                 current_context.block_hash.ToString().substr(0, 16).c_str(),
                 submission.quality, deadline_seconds);
    }

    m_queue_cv.notify_all();
}

void PoCXScheduler::WaitForDeadlineOrNewSubmission() {
    std::chrono::system_clock::time_point forge_time;
    uint64_t deadline;

    {
        std::lock_guard<std::mutex> lock(m_forging_mutex);
        if (!m_current_forging) {
            return;
        }
        forge_time = m_current_forging->forge_time;
        deadline = m_current_forging->deadline_seconds;
    }

    // Wait until forge time OR new submission arrives OR defensive forge OR cancellation
    bool deadline_reached = false;
    {
        std::unique_lock<std::mutex> lock(m_queue_mutex);
        bool predicate_true = m_queue_cv.wait_until(lock, forge_time, [this]() {
            if (m_shutdown.load() || m_defensive_forge_requested.load()) {
                return true;
            }
            if (!m_submission_queue.empty()) {
                return true;
            }
            // cancelled is atomic, pointer stable during wait (only worker modifies)
            return m_current_forging && m_current_forging->cancelled.load();
        });

        if (m_shutdown.load() || m_defensive_forge_requested.load()) {
            return; // Let main loop handle
        }

        if (!m_submission_queue.empty()) {
            return; // New submission arrived
        }

        {
            std::lock_guard<std::mutex> flock(m_forging_mutex);
            if (!m_current_forging || m_current_forging->cancelled.load()) {
                return; // Cancelled
            }
        }

        deadline_reached = !predicate_true;
    }

    if (deadline_reached) {
        // Get current block context to validate our forging state
        auto* node_context = m_mining->context();
        if (!node_context || !node_context->chainman) {
            std::lock_guard<std::mutex> lock(m_forging_mutex);
            m_current_forging.reset();
            return;
        }

        auto current_context = pocx::consensus::GetNewBlockContext(*node_context->chainman);

        // Validate under lock
        {
            std::lock_guard<std::mutex> lock(m_forging_mutex);

            if (!m_current_forging) {
                return;
            }

            // Single block_hash comparison detects all staleness (new block, reorg, etc.)
            if (m_current_forging->tip_block_hash != current_context.block_hash) {
                m_current_forging.reset();
                return; // Stale - chain tip changed
            }

            // Edge case: base target changed
            if (m_current_forging->base_target != current_context.base_target) {
                // Recalculate deadline with new base target
                uint64_t new_deadline = pocx::algorithms::CalculateTimeBendedDeadline(
                    m_current_forging->quality, current_context.base_target,
                    node_context->chainman->GetParams().GetConsensus().nPowTargetSpacing);

                m_current_forging->deadline_seconds = new_deadline;
                m_current_forging->base_target = current_context.base_target;

                int64_t block_time = 0;
                {
                    LOCK(cs_main);
                    auto* tip_index = node_context->chainman->ActiveChain().Tip();
                    if (tip_index) {
                        block_time = tip_index->nTime;
                    }
                }
                m_current_forging->forge_time = std::chrono::system_clock::from_time_t(block_time) +
                                               std::chrono::seconds(new_deadline);
                return; // Go back to wait with new deadline
            }
        }

        // All validations passed - forge the block
        bool success = ForgeBlock();

        std::lock_guard<std::mutex> lock(m_forging_mutex);
        LogPrintf("PoCX: [Scheduler] Deadline %lus -> %s\n", deadline, success ? "completed" : "failed");
        m_current_forging.reset();
        if (success) {
            LogPrintf("PoCX: [Scheduler] State reset for new block competition\n");
        }
    }
}

bool PoCXScheduler::ForgeBlock(bool defensive) {
    LogPrintf("PoCX: [Scheduler] ForgeBlock started%s\n", defensive ? " (defensive)" : "");

    // Get forging parameters - no lock needed here because:
    // 1. ForgeBlock is only called from worker thread
    // 2. Only worker thread modifies m_current_forging pointer
    // 3. TryDefensiveForge (validation thread) only reads under mutex
    if (!m_current_forging) {
        LogPrintf("PoCX: [Scheduler] No current forging state, returning false\n");
        return false;
    }

    std::string account_id = m_current_forging->account_id;
    std::string seed = m_current_forging->seed;
    uint64_t nonce = m_current_forging->nonce;
    uint64_t quality = m_current_forging->quality;
    uint32_t compression = m_current_forging->compression;

    // Get node context
    ::node::NodeContext* context = m_mining->context();
    if (!context) {
        LogPrintf("PoCX: [Scheduler] No node context available\n");
        return false;
    }

    // Build block using BlockBuilder with validated quality and compression
    auto block = m_block_builder.BuildBlock(account_id, seed, nonce, quality, compression, context);

    if (!block) {
        LogPrintf("PoCX: [Scheduler] Block building failed\n");
        return false;
    }

    LogPrintf("PoCX: [Scheduler] Block built, starting signing process\n");

    // Adjust timestamp for defensive forging BEFORE signing (signature covers nTime)
    if (defensive) {
        int64_t elapsed = GetTime() - m_current_forging->block_time;
        int64_t drift = static_cast<int64_t>(m_current_forging->deadline_seconds) - elapsed;
        if (drift > 0) {
            block->nTime += drift;
            LogPrintf("PoCX: [Scheduler] Adjusted block timestamp by +%ld seconds for defensive forging\n", drift);
        }
    }

    // Sign block using wallet
    bool signed_successfully = pocx::mining::SignPoCXBlockWithAvailableWallet(
        context,
        *block,
        account_id
    );

    if (!signed_successfully) {
        LogPrintf("PoCX: [Scheduler] Block signing failed\n");
        return false;
    }

    LogPrintf("PoCX: [Scheduler] Block forged with nonce: %llu, quality: %llu, compression: %u\n",
             block->pocxProof.nonce, block->pocxProof.quality, block->pocxProof.compression);

    return SubmitForgedBlock(*block);
}

bool PoCXScheduler::SubmitForgedBlock(const CBlock& block)
{
    ::node::NodeContext* context = m_mining->context();
    if (!context || !context->chainman) {
        LogPrintf("PoCX: [Scheduler] Failed to get chainstate manager for block submission\n");
        return false;
    }

    // Submit block for processing using Bitcoin Core's ProcessNewBlock
    std::shared_ptr<const CBlock> shared_block = std::make_shared<const CBlock>(block);
    LogPrintf("PoCX: [Scheduler] Submitting forged block (hash: %s) to Bitcoin Core\n", block.GetHash().ToString());

    bool new_block = false;
    bool accepted = context->chainman->ProcessNewBlock(shared_block,
                                                      /*force_processing=*/true,
                                                      /*min_pow_checked=*/true,
                                                      &new_block);

    if (accepted) {
        LogPrintf("PoCX: [Scheduler] Block forged and accepted! Hash: %s, New: %s\n",
                 block.GetHash().ToString(),
                 new_block ? "true" : "false");

        // Log the new chain tip to confirm block was added
        auto new_tip = CHECK_NONFATAL(m_mining->getTip()).value();
        LogPrintf("PoCX: [Scheduler] New chain tip - Hash: %s, Height: %d\n",
                 new_tip.hash.ToString(), new_tip.height);
    } else {
        LogPrintf("PoCX: [Scheduler] Block forged but rejected\n");
    }

    return accepted;
}

} // namespace mining
} // namespace pocx
