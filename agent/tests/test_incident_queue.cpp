// ──────────────────────────────────────────────────────────────────
//  AkesoDLP Agent — IncidentQueue tests
// ──────────────────────────────────────────────────────────────────

#include <gtest/gtest.h>

#include <filesystem>
#include <string>
#include <vector>

#include "akeso/incident_queue.h"

namespace fs = std::filesystem;
using akeso::dlp::IncidentQueue;
using akeso::dlp::QueuedIncident;
using akeso::dlp::QueueStats;

// ── Helper ──────────────────────────────────────────────────────

class IncidentQueueTest : public ::testing::Test {
protected:
    std::string db_path;

    void SetUp() override {
        db_path = (fs::temp_directory_path() /
                   ("test_queue_" + std::to_string(
                       std::chrono::steady_clock::now()
                           .time_since_epoch().count()) + ".db"))
                      .string();
    }

    void TearDown() override {
        fs::remove(db_path);
        // Also remove WAL/SHM files
        fs::remove(db_path + "-wal");
        fs::remove(db_path + "-shm");
    }

    QueuedIncident MakeIncident(const std::string& policy = "PCI-DSS",
                                const std::string& file = "report.xlsx",
                                const std::string& user = "john.doe",
                                int match_count = 5) {
        QueuedIncident qi;
        qi.policy_name    = policy;
        qi.severity       = "HIGH";
        qi.channel        = "USB";
        qi.source_type    = "endpoint";
        qi.file_name      = file;
        qi.file_path      = "C:\\Users\\" + user + "\\" + file;
        qi.user           = user;
        qi.source_ip      = "192.168.1.100";
        qi.match_count    = match_count;
        qi.matched_content = R"({"matches":[{"type":"credit_card"}]})";
        qi.action_taken   = "block";
        return qi;
    }
};

// ── Basic operations ────────────────────────────────────────────

TEST_F(IncidentQueueTest, StartAndStop) {
    IncidentQueue queue(db_path);
    EXPECT_TRUE(queue.Start());
    EXPECT_EQ(queue.Size(), 0);
    EXPECT_TRUE(queue.Empty());
    queue.Stop();
}

TEST_F(IncidentQueueTest, EnqueueAndSize) {
    IncidentQueue queue(db_path);
    queue.Start();

    EXPECT_TRUE(queue.Enqueue(MakeIncident()));
    EXPECT_EQ(queue.Size(), 1);
    EXPECT_FALSE(queue.Empty());

    EXPECT_TRUE(queue.Enqueue(MakeIncident("HIPAA", "patient.pdf")));
    EXPECT_EQ(queue.Size(), 2);

    queue.Stop();
}

TEST_F(IncidentQueueTest, EnqueueWithoutStart) {
    IncidentQueue queue(db_path);
    EXPECT_FALSE(queue.Enqueue(MakeIncident()));
}

// ── Drain ───────────────────────────────────────────────────────

TEST_F(IncidentQueueTest, DrainAll) {
    IncidentQueue queue(db_path);
    queue.Start();

    queue.Enqueue(MakeIncident("PCI", "a.xlsx"));
    queue.Enqueue(MakeIncident("HIPAA", "b.pdf"));
    queue.Enqueue(MakeIncident("GDPR", "c.docx"));

    auto drained = queue.Drain(100);
    EXPECT_EQ(drained.size(), 3u);
    EXPECT_EQ(queue.Size(), 0);
    EXPECT_TRUE(queue.Empty());

    // Verify order (oldest first)
    EXPECT_EQ(drained[0].policy_name, "PCI");
    EXPECT_EQ(drained[1].policy_name, "HIPAA");
    EXPECT_EQ(drained[2].policy_name, "GDPR");

    queue.Stop();
}

TEST_F(IncidentQueueTest, DrainPartial) {
    IncidentQueue queue(db_path);
    queue.Start();

    for (int i = 0; i < 10; i++)
        queue.Enqueue(MakeIncident("Policy" + std::to_string(i),
                                   "file" + std::to_string(i) + ".txt"));

    auto batch1 = queue.Drain(3);
    EXPECT_EQ(batch1.size(), 3u);
    EXPECT_EQ(queue.Size(), 7);

    auto batch2 = queue.Drain(5);
    EXPECT_EQ(batch2.size(), 5u);
    EXPECT_EQ(queue.Size(), 2);

    queue.Stop();
}

TEST_F(IncidentQueueTest, DrainEmpty) {
    IncidentQueue queue(db_path);
    queue.Start();

    auto drained = queue.Drain();
    EXPECT_TRUE(drained.empty());

    queue.Stop();
}

// ── Peek ────────────────────────────────────────────────────────

TEST_F(IncidentQueueTest, PeekDoesNotRemove) {
    IncidentQueue queue(db_path);
    queue.Start();

    queue.Enqueue(MakeIncident());
    queue.Enqueue(MakeIncident("HIPAA", "b.pdf"));

    auto peeked = queue.Peek(10);
    EXPECT_EQ(peeked.size(), 2u);
    EXPECT_EQ(queue.Size(), 2);  // Still there

    // Peek again — same result
    auto peeked2 = queue.Peek(10);
    EXPECT_EQ(peeked2.size(), 2u);

    queue.Stop();
}

// ── Remove / RemoveBatch ────────────────────────────────────────

TEST_F(IncidentQueueTest, RemoveSingle) {
    IncidentQueue queue(db_path);
    queue.Start();

    queue.Enqueue(MakeIncident());
    auto items = queue.Peek(1);
    ASSERT_EQ(items.size(), 1u);

    EXPECT_TRUE(queue.Remove(items[0].rowid));
    EXPECT_EQ(queue.Size(), 0);

    // Remove non-existent
    EXPECT_FALSE(queue.Remove(99999));

    queue.Stop();
}

TEST_F(IncidentQueueTest, RemoveBatch) {
    IncidentQueue queue(db_path);
    queue.Start();

    for (int i = 0; i < 5; i++)
        queue.Enqueue(MakeIncident("P" + std::to_string(i),
                                   "f" + std::to_string(i)));

    auto items = queue.Peek(3);
    std::vector<int64_t> ids;
    for (auto& item : items) ids.push_back(item.rowid);

    int removed = queue.RemoveBatch(ids);
    EXPECT_EQ(removed, 3);
    EXPECT_EQ(queue.Size(), 2);

    queue.Stop();
}

// ── Dedup ───────────────────────────────────────────────────────

TEST_F(IncidentQueueTest, DuplicateSuppressed) {
    IncidentQueue queue(db_path);
    queue.Start();

    auto incident = MakeIncident();
    EXPECT_TRUE(queue.Enqueue(incident));
    EXPECT_FALSE(queue.Enqueue(incident));  // Same fields → same hash
    EXPECT_EQ(queue.Size(), 1);

    auto stats = queue.Stats();
    EXPECT_EQ(stats.total_duplicates, 1);

    queue.Stop();
}

TEST_F(IncidentQueueTest, DifferentFieldsNotDuplicate) {
    IncidentQueue queue(db_path);
    queue.Start();

    EXPECT_TRUE(queue.Enqueue(MakeIncident("PCI", "a.xlsx", "alice")));
    EXPECT_TRUE(queue.Enqueue(MakeIncident("PCI", "a.xlsx", "bob")));  // Diff user
    EXPECT_TRUE(queue.Enqueue(MakeIncident("PCI", "b.xlsx", "alice"))); // Diff file
    EXPECT_TRUE(queue.Enqueue(MakeIncident("HIPAA", "a.xlsx", "alice"))); // Diff policy
    EXPECT_EQ(queue.Size(), 4);

    queue.Stop();
}

TEST_F(IncidentQueueTest, DuplicateAfterDrainAllowed) {
    IncidentQueue queue(db_path);
    queue.Start();

    auto incident = MakeIncident();
    EXPECT_TRUE(queue.Enqueue(incident));
    queue.Drain();  // Remove it
    EXPECT_TRUE(queue.Enqueue(incident));  // Can re-enqueue after drain
    EXPECT_EQ(queue.Size(), 1);

    queue.Stop();
}

// ── Max size / eviction ─────────────────────────────────────────

TEST_F(IncidentQueueTest, MaxSizeEvictsOldest) {
    IncidentQueue queue(db_path, 3);  // Max 3
    queue.Start();

    queue.Enqueue(MakeIncident("P1", "f1.txt"));
    queue.Enqueue(MakeIncident("P2", "f2.txt"));
    queue.Enqueue(MakeIncident("P3", "f3.txt"));
    EXPECT_EQ(queue.Size(), 3);

    // This should evict P1
    queue.Enqueue(MakeIncident("P4", "f4.txt"));
    EXPECT_EQ(queue.Size(), 3);

    auto items = queue.Peek(10);
    EXPECT_EQ(items[0].policy_name, "P2");  // P1 was evicted
    EXPECT_EQ(items[2].policy_name, "P4");

    auto stats = queue.Stats();
    EXPECT_EQ(stats.total_evicted, 1);

    queue.Stop();
}

TEST_F(IncidentQueueTest, MaxSizeZeroUnlimited) {
    IncidentQueue queue(db_path, 0);  // Unlimited
    queue.Start();

    for (int i = 0; i < 100; i++)
        queue.Enqueue(MakeIncident("P" + std::to_string(i),
                                   "f" + std::to_string(i)));

    EXPECT_EQ(queue.Size(), 100);

    queue.Stop();
}

// ── Persistence ─────────────────────────────────────────────────

TEST_F(IncidentQueueTest, SurvivesRestart) {
    // Enqueue, stop, re-open — data should persist
    {
        IncidentQueue queue(db_path);
        queue.Start();
        queue.Enqueue(MakeIncident("PCI", "secret.xlsx"));
        queue.Enqueue(MakeIncident("HIPAA", "patient.pdf"));
        queue.Stop();
    }

    // Re-open
    {
        IncidentQueue queue(db_path);
        queue.Start();
        EXPECT_EQ(queue.Size(), 2);

        auto items = queue.Peek(10);
        EXPECT_EQ(items[0].policy_name, "PCI");
        EXPECT_EQ(items[1].policy_name, "HIPAA");
        queue.Stop();
    }
}

TEST_F(IncidentQueueTest, DrainAfterRestart) {
    {
        IncidentQueue queue(db_path);
        queue.Start();
        queue.Enqueue(MakeIncident("PCI", "secret.xlsx"));
        queue.Stop();
    }

    {
        IncidentQueue queue(db_path);
        queue.Start();
        auto drained = queue.Drain();
        EXPECT_EQ(drained.size(), 1u);
        EXPECT_EQ(drained[0].policy_name, "PCI");
        EXPECT_EQ(drained[0].file_name, "secret.xlsx");
        EXPECT_EQ(queue.Size(), 0);
        queue.Stop();
    }
}

// ── Retry count ─────────────────────────────────────────────────

TEST_F(IncidentQueueTest, IncrementRetry) {
    IncidentQueue queue(db_path);
    queue.Start();

    queue.Enqueue(MakeIncident());
    auto items = queue.Peek(1);
    ASSERT_EQ(items.size(), 1u);
    EXPECT_EQ(items[0].retry_count, 0);

    EXPECT_TRUE(queue.IncrementRetry(items[0].rowid));
    EXPECT_TRUE(queue.IncrementRetry(items[0].rowid));

    items = queue.Peek(1);
    EXPECT_EQ(items[0].retry_count, 2);

    queue.Stop();
}

// ── Clear ───────────────────────────────────────────────────────

TEST_F(IncidentQueueTest, Clear) {
    IncidentQueue queue(db_path);
    queue.Start();

    for (int i = 0; i < 10; i++)
        queue.Enqueue(MakeIncident("P" + std::to_string(i),
                                   "f" + std::to_string(i)));

    EXPECT_EQ(queue.Size(), 10);
    queue.Clear();
    EXPECT_EQ(queue.Size(), 0);
    EXPECT_TRUE(queue.Empty());

    queue.Stop();
}

// ── Stats ───────────────────────────────────────────────────────

TEST_F(IncidentQueueTest, StatsTracking) {
    IncidentQueue queue(db_path, 5);
    queue.Start();

    // Enqueue 6 (1 eviction)
    for (int i = 0; i < 6; i++)
        queue.Enqueue(MakeIncident("P" + std::to_string(i),
                                   "f" + std::to_string(i)));

    // 1 duplicate
    queue.Enqueue(MakeIncident("P5", "f5"));

    // Drain 2
    queue.Drain(2);

    auto stats = queue.Stats();
    EXPECT_EQ(stats.total_enqueued, 6);
    EXPECT_EQ(stats.total_evicted, 1);
    EXPECT_EQ(stats.total_duplicates, 1);
    EXPECT_EQ(stats.total_drained, 2);
    EXPECT_EQ(stats.current_size, 3);

    queue.Stop();
}

// ── Field preservation ──────────────────────────────────────────

TEST_F(IncidentQueueTest, AllFieldsPreserved) {
    IncidentQueue queue(db_path);
    queue.Start();

    QueuedIncident qi;
    qi.policy_name     = "SOX-Compliance";
    qi.severity        = "CRITICAL";
    qi.channel         = "EMAIL";
    qi.source_type     = "gateway";
    qi.file_name       = "financials_q4.xlsx";
    qi.file_path       = "C:\\Reports\\financials_q4.xlsx";
    qi.user            = "cfo@company.com";
    qi.source_ip       = "10.0.0.50";
    qi.match_count     = 42;
    qi.matched_content = R"({"identifiers":["aba_routing","credit_card"]})";
    qi.action_taken    = "quarantine";
    qi.queued_at       = 1700000000;

    queue.Enqueue(qi);

    auto items = queue.Peek(1);
    ASSERT_EQ(items.size(), 1u);
    auto& out = items[0];

    EXPECT_EQ(out.policy_name, "SOX-Compliance");
    EXPECT_EQ(out.severity, "CRITICAL");
    EXPECT_EQ(out.channel, "EMAIL");
    EXPECT_EQ(out.source_type, "gateway");
    EXPECT_EQ(out.file_name, "financials_q4.xlsx");
    EXPECT_EQ(out.file_path, "C:\\Reports\\financials_q4.xlsx");
    EXPECT_EQ(out.user, "cfo@company.com");
    EXPECT_EQ(out.source_ip, "10.0.0.50");
    EXPECT_EQ(out.match_count, 42);
    EXPECT_EQ(out.matched_content,
              R"({"identifiers":["aba_routing","credit_card"]})");
    EXPECT_EQ(out.action_taken, "quarantine");
    EXPECT_EQ(out.queued_at, 1700000000);

    queue.Stop();
}

// ── Name ────────────────────────────────────────────────────────

TEST_F(IncidentQueueTest, ComponentName) {
    IncidentQueue queue(db_path);
    EXPECT_EQ(queue.Name(), "IncidentQueue");
}
