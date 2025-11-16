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

namespace pocx {
namespace mining {

PoCXScheduler::PoCXScheduler(interfaces::Mining& mining)
    : m_shutdown(false), m_mining(&mining), m_block_builder(mining) {
    // Start persistent worker thread
    m_worker_thread = std::thread(&PoCXScheduler::WorkerThreadFunc, this);
}

PoCXScheduler::~PoCXScheduler() {
    Shutdown();
}

bool PoCXScheduler::SubmitNonce(const std::string& account_id,
                                const std::string& seed,
                                uint64_t nonce,
                                uint64_t quality,
                                uint32_t compression,
                                int height,
                                const uint256& generation_signature) {

    // Create submission for queue (validation already done in RPC)
    NonceSubmission submission(
        account_id,
        seed,
        nonce,
        quality,
        compression,
        height,
        generation_signature
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

void PoCXScheduler::WorkerThreadFunc() {

    while (!m_shutdown.load()) {

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
        if (m_current_forging && !m_current_forging->cancelled.load()) {
            // We have a nonce to forge - wait for deadline OR new submission
            WaitForDeadlineOrNewSubmission();
        } else {
            // No current forging - wait for new submission
            std::unique_lock<std::mutex> lock(m_queue_mutex);
            m_queue_cv.wait_for(lock, std::chrono::seconds(30), [this] {
                return !m_submission_queue.empty() || m_shutdown.load();
            });
        }

        if (m_shutdown.load()) {
            break;
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

    // Get current tip block hash and time for reorg/defensive forging detection
    uint256 current_tip_hash;
    int64_t block_time = 0;
    CBlockIndex* tip = nullptr;
    {
        LOCK(cs_main);
        tip = node_context->chainman->ActiveChain().Tip();
        if (!tip) {
            return; // No tip available
        }
        current_tip_hash = tip->GetBlockHash();
        block_time = tip->nTime;
    }

    // Defensive forging check: if tip changed and we have current forging solution
    if (m_current_forging && m_current_forging->tip_block_hash != current_tip_hash) {
        CheckDefensiveForging(*node_context, *tip);
        m_current_forging.reset();
    }

    auto current_context = pocx::consensus::GetNewBlockContext(*node_context->chainman);

    // Validate submission context (height and generation signature)
    if (!SubmissionValidator::ValidateContext(submission, current_context.height, current_context.generation_signature)) {
        return; // Stale submission - discard silently
    }

    // Check if better than current best
    std::optional<uint64_t> current_quality;
    if (m_current_forging) {
        current_quality = m_current_forging->quality;
    }
    if (!SubmissionValidator::IsBetterThanCurrent(submission.quality, current_quality)) {
        return; // Not better - discard
    }

    // Calculate deadline using Time Bending (for accepted submissions)
    uint64_t deadline_seconds = pocx::algorithms::CalculateTimeBendedDeadline(
        submission.quality, current_context.base_target,
        node_context->chainman->GetParams().GetConsensus().nPowTargetSpacing);

    // This is better - update current forging state
    if (m_current_forging) {
        // Cancel current forging
        m_current_forging->cancelled = true;
        m_queue_cv.notify_all();
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
    m_current_forging->height = current_context.height;
    m_current_forging->generation_sig = current_context.generation_signature;
    m_current_forging->tip_block_hash = current_tip_hash;
    m_current_forging->cancelled = false;

    // Store block time and calculate forge time
    m_current_forging->block_time = block_time;
    m_current_forging->forge_time = std::chrono::system_clock::from_time_t(block_time) +
                                   std::chrono::seconds(deadline_seconds);


    // Don't wait here - let worker thread continue processing queue
    // Waiting happens in main worker loop when queue is empty
}

void PoCXScheduler::WaitForDeadlineOrNewSubmission() {
    if (!m_current_forging) {
        return;
    }

    auto forge_time = m_current_forging->forge_time;
    uint64_t deadline = m_current_forging->deadline_seconds;

    // Wait until forge time OR new submission arrives OR cancellation
    bool deadline_reached = false;
    {
        bool predicate_true;
        size_t final_queue_size;
        {
            std::unique_lock<std::mutex> lock(m_queue_mutex);
            predicate_true = m_queue_cv.wait_until(lock, forge_time, [this]() {
                return m_shutdown.load() || !m_submission_queue.empty() ||
                       (m_current_forging && m_current_forging->cancelled.load());
            });
            final_queue_size = m_submission_queue.size();
        }

        if (m_shutdown.load()) {
            return;
        }

        if (final_queue_size > 0) {
            return; // New submission arrived
        }

        if (m_current_forging && m_current_forging->cancelled.load()) {
            return; // Forging was cancelled
        }

        deadline_reached = !predicate_true;
    }

    if (deadline_reached) {
        // Get current block context to validate our forging state
        auto* node_context = m_mining->context();
        if (!node_context || !node_context->chainman) {
            m_current_forging.reset();
            return;
        }

        auto current_context = pocx::consensus::GetNewBlockContext(*node_context->chainman);

        // Check if height still matches
        if (m_current_forging->height != current_context.height) {
            m_current_forging.reset();
            return; // Stale height
        }

        // Check if generation signature still matches
        if (m_current_forging->generation_sig != current_context.generation_signature) {
            m_current_forging.reset();
            return; // Stale generation signature
        }

        // Edge case: base target changed (same miner forged with different deadline)
        if (m_current_forging->base_target != current_context.base_target) {
            // Recalculate deadline with new base target
            uint64_t new_deadline = pocx::algorithms::CalculateTimeBendedDeadline(
                m_current_forging->quality, current_context.base_target,
                node_context->chainman->GetParams().GetConsensus().nPowTargetSpacing);

            // Update forging state
            m_current_forging->deadline_seconds = new_deadline;
            m_current_forging->base_target = current_context.base_target;

            // Recalculate forge time
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

        // All validations passed - forge the block
        bool success = ForgeBlock();

        if (success) {
            LogPrintf("PoCX: [Scheduler] Deadline %lus -> completed\n", deadline);
            m_current_forging.reset();
            LogPrintf("PoCX: [Scheduler] State reset for new block competition\n");
        } else {
            LogPrintf("PoCX: [Scheduler] Deadline %lus -> failed\n", deadline);
            m_current_forging.reset();
        }
    }
}

bool PoCXScheduler::ForgeBlock() {
    LogPrintf("PoCX: [Scheduler] ForgeBlock started\n");

    // Get forging parameters (no locking needed - worker thread only access)
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

void PoCXScheduler::CheckDefensiveForging(const node::NodeContext& node_context, const CBlockIndex& new_tip) {
    if (new_tip.pprev->GetBlockHash() != m_current_forging->tip_block_hash) {
        return; // Reorg, not same-height competition
    }

    uint64_t arriving_quality = new_tip.pocxProof.quality;

    if (m_current_forging->quality < arriving_quality) {
        LogPrintf("PoCX: Defensive forging - quality %llu beats %llu\n",
                 m_current_forging->quality, arriving_quality);
        ForgeBlock();
    }
}

} // namespace mining
} // namespace pocx
