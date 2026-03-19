/*
 * policy_cache.h
 * SentinelDLP Agent - Policy Cache
 *
 * SQLite-backed persistent cache for policy definitions.
 * Enables offline enforcement when the server is unreachable.
 *
 * Storage model:
 *   - policies table: policy_id, name, serialized protobuf, version
 *   - metadata table: key-value pairs (policy_version, last_sync)
 *   - Atomic version swap via transaction
 */

#pragma once

#include "sentinel/agent_service.h"
#include "sentinel/config.h"

#include <cstdint>
#include <mutex>
#include <string>
#include <vector>

/* Forward declare sqlite3 to avoid exposing the header */
struct sqlite3;

#pragma warning(push)
#pragma warning(disable: 4267)
#include "sentineldlp.pb.h"
#pragma warning(pop)

namespace sentinel::dlp {

/* ------------------------------------------------------------------ */
/*  PolicyCache                                                        */
/* ------------------------------------------------------------------ */

class PolicyCache : public IAgentComponent {
public:
    explicit PolicyCache(const AgentConfig& config);
    ~PolicyCache() override;

    /* Non-copyable */
    PolicyCache(const PolicyCache&) = delete;
    PolicyCache& operator=(const PolicyCache&) = delete;

    /* IAgentComponent interface */
    std::string Name() const override { return "PolicyCache"; }
    bool Start() override;
    void Stop() override;
    bool IsHealthy() const override;

    /*
     * Get the current cached policy version.
     * Returns 0 if no policies are cached.
     */
    int32_t GetVersion() const;

    /*
     * Check if the cache has any policies.
     */
    bool HasPolicies() const;

    /*
     * Load all cached policies into the provided vector.
     * Returns true if policies were loaded successfully.
     */
    bool LoadPolicies(std::vector<sentineldlp::PolicyDefinition>& policies);

    /*
     * Store a complete policy set from the server.
     * This atomically replaces the entire cache:
     *   1. Begin transaction
     *   2. Delete all existing policies
     *   3. Insert new policies
     *   4. Update version metadata
     *   5. Commit
     *
     * On failure, the transaction is rolled back and the
     * existing cache remains intact.
     */
    bool StorePolicies(
        int32_t version,
        const google::protobuf::RepeatedPtrField<sentineldlp::PolicyDefinition>& policies
    );

    /*
     * Store policies from a vector (convenience overload).
     */
    bool StorePolicies(
        int32_t version,
        const std::vector<sentineldlp::PolicyDefinition>& policies
    );

    /*
     * Get the timestamp of the last successful sync.
     * Returns empty string if never synced.
     */
    std::string GetLastSyncTime() const;

    /*
     * Get the number of cached policies.
     */
    int GetPolicyCount() const;

    /*
     * Clear the entire cache.
     */
    bool Clear();

    /*
     * Get the database file path.
     */
    const std::string& GetDbPath() const { return db_path_; }

private:
    /* Database setup */
    bool OpenDatabase();
    bool CreateSchema();
    void CloseDatabase();

    /* Metadata helpers */
    bool SetMetadata(const std::string& key, const std::string& value);
    std::string GetMetadata(const std::string& key) const;

    /* State */
    std::string     db_path_;
    sqlite3*        db_{nullptr};
    mutable std::recursive_mutex  db_mutex_;
};

}  // namespace sentinel::dlp
