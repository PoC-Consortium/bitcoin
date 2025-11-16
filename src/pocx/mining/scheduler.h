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
    uint256 generation_sig;         // Generation signature for next block
    int height;                     // Height for next block
    uint256 tip_block_hash;         // Hash of chain tip (for reorg detection)
    std::chrono::system_clock::time_point forge_time;  // When to forge
    std::atomic<bool> cancelled;    // Cancellation flag

    ForgingState() : base_target(0), block_time(0), height(0), cancelled(false) {}
};

/** Queue-based forging scheduler for PoCX mining */
class PoCXScheduler {
private:
    // Submission queue with DoS protection
    static constexpr size_t MAX_QUEUE_SIZE = 1000;
    std::queue<NonceSubmission> m_submission_queue;
    std::mutex m_queue_mutex;
    std::condition_variable m_queue_cv;

    // Current forging state (accessed only by worker thread - no mutex needed)
    std::unique_ptr<ForgingState> m_current_forging;

    // Single persistent worker thread
    std::thread m_worker_thread;
    std::atomic<bool> m_shutdown;

    interfaces::Mining* m_mining;
    PoCXBlockBuilder m_block_builder;

    void WorkerThreadFunc();
    void ProcessSubmission(const NonceSubmission& submission);
    void WaitForDeadlineOrNewSubmission();
    bool ForgeBlock();
    bool SubmitForgedBlock(const CBlock& block);

    // Defensive forging
    void CheckDefensiveForging(const node::NodeContext& node_context, const CBlockIndex& new_tip);

public:
    explicit PoCXScheduler(interfaces::Mining& mining);
    ~PoCXScheduler();

    /** Queue nonce submission for forging. Returns false if queue full. */
    bool SubmitNonce(const std::string& account_id,
                     const std::string& seed,
                     uint64_t nonce,
                     uint64_t quality,
                     uint32_t compression,
                     int height,
                     const uint256& generation_signature);

    void Shutdown();
};

} // namespace mining
} // namespace pocx

#endif // BITCOIN_POCX_MINING_SCHEDULER_H
