#pragma once
// ──────────────────────────────────────────────────────────────────
//  AkesoDLP Agent — IncidentQueue
//  Persistent, file-backed queue for reliable incident delivery.
//  Uses SQLite for durability across agent restarts. Supports:
//    • Enqueue with SHA-256 dedup (by policy+file+user+match_count)
//    • Batch drain for upload on reconnect
//    • Max queue size with oldest-evict policy
//    • Atomic operations via SQLite transactions
// ──────────────────────────────────────────────────────────────────

#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "akeso/agent_service.h"

// Forward-declare sqlite3
struct sqlite3;

namespace akeso::dlp {

// ── Queue entry ─────────────────────────────────────────────────
struct QueuedIncident {
    int64_t     rowid{0};
    std::string hash;           // SHA-256 dedup key
    std::string policy_name;
    std::string severity;       // "LOW", "MEDIUM", "HIGH", "CRITICAL"
    std::string channel;        // "USB", "EMAIL", "CLOUD", "PRINT", etc.
    std::string source_type;
    std::string file_name;
    std::string file_path;
    std::string user;
    std::string source_ip;
    int         match_count{0};
    std::string matched_content; // JSON blob
    std::string action_taken;
    int64_t     queued_at{0};   // Unix timestamp
    int         retry_count{0};
};

// ── Queue statistics ────────────────────────────────────────────
struct QueueStats {
    int64_t total_enqueued{0};
    int64_t total_drained{0};
    int64_t total_evicted{0};
    int64_t total_duplicates{0};
    int64_t current_size{0};
};

// ── IncidentQueue ───────────────────────────────────────────────
class IncidentQueue : public IAgentComponent {
public:
    /// @param db_path  Path to the SQLite database file.
    /// @param max_size Maximum incidents to keep (0 = unlimited).
    explicit IncidentQueue(const std::string& db_path,
                           int64_t max_size = 10000);
    ~IncidentQueue() override;

    // Non-copyable
    IncidentQueue(const IncidentQueue&) = delete;
    IncidentQueue& operator=(const IncidentQueue&) = delete;

    // ── IAgentComponent ─────────────────────────────────────────
    std::string Name() const override { return "IncidentQueue"; }
    bool Start() override;
    void Stop() override;
    bool IsHealthy() const override { return db_ != nullptr; }

    // ── Core operations ─────────────────────────────────────────

    /// Enqueue an incident.  Returns true if added, false if
    /// duplicate or queue error.
    bool Enqueue(const QueuedIncident& incident);

    /// Drain up to `limit` oldest incidents from the queue.
    /// Removes them from the database.  Returns the incidents.
    std::vector<QueuedIncident> Drain(int limit = 100);

    /// Peek at up to `limit` oldest incidents without removing.
    std::vector<QueuedIncident> Peek(int limit = 100) const;

    /// Remove a specific incident by rowid (after successful upload).
    bool Remove(int64_t rowid);

    /// Remove a batch of incidents by rowid.
    int RemoveBatch(const std::vector<int64_t>& rowids);

    /// Increment retry count for a specific incident.
    bool IncrementRetry(int64_t rowid);

    /// Current number of queued incidents.
    int64_t Size() const;

    /// Whether the queue is empty.
    bool Empty() const { return Size() == 0; }

    /// Get queue statistics.
    QueueStats Stats() const;

    /// Clear all queued incidents.
    void Clear();

private:
    bool OpenDatabase();
    void CloseDatabase();
    bool CreateSchema();
    bool IsDuplicate(const std::string& hash) const;
    int64_t EvictOldest(int64_t count);

    /// Compute a dedup hash from incident fields.
    static std::string ComputeHash(const QueuedIncident& incident);

    std::string     db_path_;
    int64_t         max_size_;
    sqlite3*        db_{nullptr};
    mutable std::mutex mutex_;

    // Stats (in-memory, reset on restart)
    mutable QueueStats stats_;
};

}  // namespace akeso::dlp
