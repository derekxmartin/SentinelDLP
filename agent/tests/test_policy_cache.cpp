/*
 * test_policy_cache.cpp
 * AkesoDLP Agent - PolicyCache tests
 */

#include <filesystem>
#include <gtest/gtest.h>

#include "akeso/policy_cache.h"

using namespace akeso::dlp;

/* ------------------------------------------------------------------ */
/*  Test fixture: creates a temp DB for each test                      */
/* ------------------------------------------------------------------ */

class PolicyCacheTest : public ::testing::Test {
protected:
    void SetUp() override {
        db_path_ = (std::filesystem::temp_directory_path() /
                     ("akeso_test_cache_" + std::to_string(counter_++) + ".db"))
                    .string();

        AgentConfig config;
        config.policy_cache.path = db_path_;
        cache_ = std::make_unique<PolicyCache>(config);
    }

    void TearDown() override {
        cache_->Stop();
        cache_.reset();
        std::filesystem::remove(db_path_);
    }

    /* Helper: create a test policy */
    akesodlp::PolicyDefinition MakePolicy(
        const std::string& id,
        const std::string& name,
        akesodlp::Severity severity = akesodlp::SEVERITY_HIGH
    ) {
        akesodlp::PolicyDefinition p;
        p.set_policy_id(id);
        p.set_name(name);
        p.set_severity(severity);
        p.set_status("active");
        p.set_ttd_fallback("log");
        return p;
    }

    std::string db_path_;
    std::unique_ptr<PolicyCache> cache_;
    static int counter_;
};

int PolicyCacheTest::counter_ = 0;

/* ------------------------------------------------------------------ */
/*  Basic lifecycle                                                    */
/* ------------------------------------------------------------------ */

TEST_F(PolicyCacheTest, StartCreatesDatabase) {
    ASSERT_TRUE(cache_->Start());
    EXPECT_TRUE(cache_->IsHealthy());
    EXPECT_TRUE(std::filesystem::exists(db_path_));
}

TEST_F(PolicyCacheTest, StopClosesDatabase) {
    ASSERT_TRUE(cache_->Start());
    cache_->Stop();
    EXPECT_FALSE(cache_->IsHealthy());
}

TEST_F(PolicyCacheTest, EmptyCacheHasNoPolicies) {
    ASSERT_TRUE(cache_->Start());
    EXPECT_EQ(cache_->GetVersion(), 0);
    EXPECT_FALSE(cache_->HasPolicies());
    EXPECT_EQ(cache_->GetPolicyCount(), 0);
}

/* ------------------------------------------------------------------ */
/*  Store and load                                                     */
/* ------------------------------------------------------------------ */

TEST_F(PolicyCacheTest, StoreSinglePolicy) {
    ASSERT_TRUE(cache_->Start());

    std::vector<akesodlp::PolicyDefinition> policies = {
        MakePolicy("p1", "PCI-DSS")
    };

    ASSERT_TRUE(cache_->StorePolicies(1, policies));

    EXPECT_EQ(cache_->GetVersion(), 1);
    EXPECT_TRUE(cache_->HasPolicies());
    EXPECT_EQ(cache_->GetPolicyCount(), 1);
}

TEST_F(PolicyCacheTest, StoreMultiplePolicies) {
    ASSERT_TRUE(cache_->Start());

    std::vector<akesodlp::PolicyDefinition> policies = {
        MakePolicy("p1", "PCI-DSS", akesodlp::SEVERITY_HIGH),
        MakePolicy("p2", "HIPAA", akesodlp::SEVERITY_HIGH),
        MakePolicy("p3", "GDPR", akesodlp::SEVERITY_MEDIUM),
    };

    ASSERT_TRUE(cache_->StorePolicies(5, policies));

    EXPECT_EQ(cache_->GetVersion(), 5);
    EXPECT_EQ(cache_->GetPolicyCount(), 3);
}

TEST_F(PolicyCacheTest, LoadPoliciesDeserializesCorrectly) {
    ASSERT_TRUE(cache_->Start());

    auto original = MakePolicy("p1", "PCI-DSS", akesodlp::SEVERITY_HIGH);
    original.set_description("Payment Card Industry");
    original.set_ttd_fallback("block");

    std::vector<akesodlp::PolicyDefinition> to_store = { original };
    ASSERT_TRUE(cache_->StorePolicies(1, to_store));

    std::vector<akesodlp::PolicyDefinition> loaded;
    ASSERT_TRUE(cache_->LoadPolicies(loaded));

    ASSERT_EQ(loaded.size(), 1);
    EXPECT_EQ(loaded[0].policy_id(), "p1");
    EXPECT_EQ(loaded[0].name(), "PCI-DSS");
    EXPECT_EQ(loaded[0].severity(), akesodlp::SEVERITY_HIGH);
    EXPECT_EQ(loaded[0].description(), "Payment Card Industry");
    EXPECT_EQ(loaded[0].ttd_fallback(), "block");
    EXPECT_EQ(loaded[0].status(), "active");
}

/* ------------------------------------------------------------------ */
/*  Atomic version swap                                                */
/* ------------------------------------------------------------------ */

TEST_F(PolicyCacheTest, AtomicVersionSwap) {
    ASSERT_TRUE(cache_->Start());

    /* Store version 1 */
    std::vector<akesodlp::PolicyDefinition> v1 = {
        MakePolicy("p1", "Policy-A"),
        MakePolicy("p2", "Policy-B"),
    };
    ASSERT_TRUE(cache_->StorePolicies(1, v1));
    EXPECT_EQ(cache_->GetPolicyCount(), 2);
    EXPECT_EQ(cache_->GetVersion(), 1);

    /* Store version 2 — completely replaces v1 */
    std::vector<akesodlp::PolicyDefinition> v2 = {
        MakePolicy("p3", "Policy-C"),
        MakePolicy("p4", "Policy-D"),
        MakePolicy("p5", "Policy-E"),
    };
    ASSERT_TRUE(cache_->StorePolicies(2, v2));
    EXPECT_EQ(cache_->GetPolicyCount(), 3);
    EXPECT_EQ(cache_->GetVersion(), 2);

    /* Verify v1 policies are gone */
    std::vector<akesodlp::PolicyDefinition> loaded;
    ASSERT_TRUE(cache_->LoadPolicies(loaded));
    ASSERT_EQ(loaded.size(), 3);

    std::set<std::string> names;
    for (const auto& p : loaded) names.insert(p.name());
    EXPECT_TRUE(names.count("Policy-C"));
    EXPECT_TRUE(names.count("Policy-D"));
    EXPECT_TRUE(names.count("Policy-E"));
    EXPECT_FALSE(names.count("Policy-A"));
    EXPECT_FALSE(names.count("Policy-B"));
}

/* ------------------------------------------------------------------ */
/*  Persistence across restart                                         */
/* ------------------------------------------------------------------ */

TEST_F(PolicyCacheTest, PersistsAcrossRestart) {
    /* Store policies */
    ASSERT_TRUE(cache_->Start());
    std::vector<akesodlp::PolicyDefinition> policies = {
        MakePolicy("p1", "PCI-DSS"),
        MakePolicy("p2", "HIPAA"),
    };
    ASSERT_TRUE(cache_->StorePolicies(7, policies));
    cache_->Stop();

    /* Reopen — same DB path */
    AgentConfig config;
    config.policy_cache.path = db_path_;
    auto cache2 = std::make_unique<PolicyCache>(config);
    ASSERT_TRUE(cache2->Start());

    EXPECT_EQ(cache2->GetVersion(), 7);
    EXPECT_EQ(cache2->GetPolicyCount(), 2);

    std::vector<akesodlp::PolicyDefinition> loaded;
    ASSERT_TRUE(cache2->LoadPolicies(loaded));
    ASSERT_EQ(loaded.size(), 2);

    cache2->Stop();
}

/* ------------------------------------------------------------------ */
/*  Clear                                                              */
/* ------------------------------------------------------------------ */

TEST_F(PolicyCacheTest, ClearRemovesEverything) {
    ASSERT_TRUE(cache_->Start());

    std::vector<akesodlp::PolicyDefinition> policies = {
        MakePolicy("p1", "PCI-DSS"),
    };
    ASSERT_TRUE(cache_->StorePolicies(3, policies));
    EXPECT_EQ(cache_->GetPolicyCount(), 1);
    EXPECT_EQ(cache_->GetVersion(), 3);

    ASSERT_TRUE(cache_->Clear());

    EXPECT_EQ(cache_->GetPolicyCount(), 0);
    EXPECT_EQ(cache_->GetVersion(), 0);
    EXPECT_FALSE(cache_->HasPolicies());
}

/* ------------------------------------------------------------------ */
/*  Last sync time                                                     */
/* ------------------------------------------------------------------ */

TEST_F(PolicyCacheTest, LastSyncTimeUpdatedOnStore) {
    ASSERT_TRUE(cache_->Start());

    /* No sync yet */
    EXPECT_TRUE(cache_->GetLastSyncTime().empty());

    /* Store policies */
    std::vector<akesodlp::PolicyDefinition> policies = {
        MakePolicy("p1", "Test"),
    };
    ASSERT_TRUE(cache_->StorePolicies(1, policies));

    std::string sync_time = cache_->GetLastSyncTime();
    EXPECT_FALSE(sync_time.empty());
    /* Should contain a date-like string */
    EXPECT_NE(sync_time.find("2026"), std::string::npos);
}

/* ------------------------------------------------------------------ */
/*  Policy with detection rules                                        */
/* ------------------------------------------------------------------ */

TEST_F(PolicyCacheTest, PolicyWithRulesRoundTrips) {
    ASSERT_TRUE(cache_->Start());

    auto policy = MakePolicy("p1", "Complex Policy");

    /* Add a detection rule with conditions */
    auto* rule = policy.add_detection_rules();
    rule->set_rule_id("r1");
    rule->set_name("SSN Detection");
    rule->set_rule_type("detection");

    auto* cond = rule->add_conditions();
    cond->set_condition_type("data_identifier");
    cond->set_component("body");
    cond->set_config_json("{\"identifier\": \"US SSN\"}");
    cond->set_match_count_min(1);

    /* Add severity thresholds */
    auto* thresh = policy.add_severity_thresholds();
    thresh->set_threshold(3);
    thresh->set_severity(akesodlp::SEVERITY_MEDIUM);

    auto* thresh2 = policy.add_severity_thresholds();
    thresh2->set_threshold(10);
    thresh2->set_severity(akesodlp::SEVERITY_HIGH);

    std::vector<akesodlp::PolicyDefinition> to_store = { policy };
    ASSERT_TRUE(cache_->StorePolicies(1, to_store));

    /* Load and verify */
    std::vector<akesodlp::PolicyDefinition> loaded;
    ASSERT_TRUE(cache_->LoadPolicies(loaded));
    ASSERT_EQ(loaded.size(), 1);

    const auto& p = loaded[0];
    EXPECT_EQ(p.detection_rules_size(), 1);
    EXPECT_EQ(p.detection_rules(0).name(), "SSN Detection");
    EXPECT_EQ(p.detection_rules(0).conditions_size(), 1);
    EXPECT_EQ(p.detection_rules(0).conditions(0).condition_type(), "data_identifier");

    EXPECT_EQ(p.severity_thresholds_size(), 2);
    EXPECT_EQ(p.severity_thresholds(0).threshold(), 3);
    EXPECT_EQ(p.severity_thresholds(1).severity(), akesodlp::SEVERITY_HIGH);
}

/* ------------------------------------------------------------------ */
/*  Empty store is valid                                               */
/* ------------------------------------------------------------------ */

TEST_F(PolicyCacheTest, StoreEmptyPolicySet) {
    ASSERT_TRUE(cache_->Start());

    /* First store some policies */
    std::vector<akesodlp::PolicyDefinition> policies = {
        MakePolicy("p1", "Test"),
    };
    ASSERT_TRUE(cache_->StorePolicies(1, policies));
    EXPECT_EQ(cache_->GetPolicyCount(), 1);

    /* Store empty set — removes all */
    std::vector<akesodlp::PolicyDefinition> empty;
    ASSERT_TRUE(cache_->StorePolicies(2, empty));
    EXPECT_EQ(cache_->GetPolicyCount(), 0);
    EXPECT_EQ(cache_->GetVersion(), 2);
}

/* ------------------------------------------------------------------ */
/*  Database not started                                               */
/* ------------------------------------------------------------------ */

TEST_F(PolicyCacheTest, OperationsFailWhenNotStarted) {
    /* Don't call Start() */
    EXPECT_EQ(cache_->GetVersion(), 0);
    EXPECT_EQ(cache_->GetPolicyCount(), 0);
    EXPECT_FALSE(cache_->HasPolicies());

    std::vector<akesodlp::PolicyDefinition> policies;
    EXPECT_FALSE(cache_->LoadPolicies(policies));
    EXPECT_FALSE(cache_->StorePolicies(1, policies));
    EXPECT_FALSE(cache_->Clear());
}
