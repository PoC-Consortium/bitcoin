// Copyright (c) 2025 The Proof of Capacity Consortium
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_POCX_MINING_SCHEDULER_H
#define BITCOIN_POCX_MINING_SCHEDULER_H

#include <pocx/mining/submission.h>
#include <pocx/mining/block_builder.h>

#include <uint256.h>
#include <primitives/block.h>
#include <interfaces/mining.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <queue>
#include <string>
#include <thread>

class CBlockIndex;
namespace node { struct NodeContext; }

namespace pocx {
namespace mining {

/** Forging submission state */
struct ForgingState {
    std::string account_id;         // Miner account ID
    std::string seed;               // Plot seed
    uint64_t nonce;                 // Mining nonce
    uint64_t quality;               // Calculated quality
    uint32_t compression;           // Compression level used
    uint64_t deadline_seconds;      // Deadline in seconds
    uint64_t base_target;           // Base target used for nonce validation
    int64_t block_time;             // Time of the previous block
    uint256 tip_block_hash;         // Hash of chain tip (sole staleness indicator)
    std::chrono::system_clock::time_point forge_time;  // When to forge
    std::atomic<bool> cancelled;    // Cancellation flag

    ForgingState() : base_target(0), block_time(0), cancelled(false) {}
};

/** Queue-based forging scheduler for PoCX mining */
class PoCXScheduler {
private:
    // Submission queue with DoS protection
    static constexpr size_t MAX_QUEUE_SIZE = 1000;
    std::queue<NonceSubmission> m_submission_queue;
    std::mutex m_queue_mutex;
    std::condition_variable m_queue_cv;

    // Current forging state - protected by m_forging_mutex for cross-thread access
    std::unique_ptr<ForgingState> m_current_forging;

    // Single persistent worker thread
    std::thread m_worker_thread;
    std::atomic<bool> m_shutdown;

    interfaces::Mining* m_mining;
    PoCXBlockBuilder m_block_builder;

    // Defensive forging - mutex protects m_current_forging for cross-thread access
    mutable std::mutex m_forging_mutex;
    std::atomic<bool> m_defensive_forge_requested{false};

    void WorkerThreadFunc();
    void ProcessSubmission(const NonceSubmission& submission);
    void WaitForDeadlineOrNewSubmission();
    bool ForgeBlock(bool defensive = false);
    bool SubmitForgedBlock(const CBlock& block);

public:
    explicit PoCXScheduler(interfaces::Mining& mining);
    ~PoCXScheduler();

    /** Queue nonce submission for forging. Returns false if queue full. */
    bool SubmitNonce(const std::string& account_id,
                     const std::string& seed,
                     uint64_t nonce,
                     uint64_t quality,
                     uint32_t compression,
                     const uint256& block_hash);

    void Shutdown();

    /**
     * Attempt defensive forge if we have a better solution.
     * Called by validation when a competing block arrives.
     * Thread-safe, non-blocking - signals worker thread to forge.
     *
     * @param tip_hash The tip both blocks are building on
     * @param incoming_quality The competing block's quality
     * @return true if we have better quality and will forge (caller should reject incoming block)
     *         false if no defense needed (caller should accept incoming block)
     */
    bool TryDefensiveForge(const uint256& tip_hash, uint64_t incoming_quality);
};

/**
 * Get the global PoCX scheduler instance.
 * Returns nullptr if scheduler not initialized (mining not started).
 * Thread-safe.
 */
PoCXScheduler* GetPoCXScheduler();

} // namespace mining
} // namespace pocx

#endif // BITCOIN_POCX_MINING_SCHEDULER_H
