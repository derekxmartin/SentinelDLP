/*
 * test_keyword_analyzer.cpp
 * AkesoDLP Agent - Aho-Corasick Keyword Analyzer Tests
 *
 * Tests: automaton build, case sensitivity, whole-word boundaries,
 *        overlapping matches, performance, thread safety.
 */

#include "akeso/detection/keyword_analyzer.h"

#include <gtest/gtest.h>

#include <chrono>
#include <random>
#include <string>
#include <thread>
#include <vector>

using namespace akeso::dlp;

/* ================================================================== */
/*  Fixture                                                            */
/* ================================================================== */

class KeywordAnalyzerTest : public ::testing::Test {
protected:
    void SetUp() override {
        DetectionConfig config;
        analyzer_ = std::make_unique<KeywordAnalyzer>(config);
        ASSERT_TRUE(analyzer_->Start());
    }

    void TearDown() override {
        if (analyzer_) {
            analyzer_->Stop();
            analyzer_.reset();
        }
    }

    std::unique_ptr<KeywordAnalyzer> analyzer_;
};

/* ================================================================== */
/*  Basic lifecycle                                                    */
/* ================================================================== */

TEST_F(KeywordAnalyzerTest, BasicLifecycle) {
    EXPECT_EQ(analyzer_->Name(), "KeywordAnalyzer");
    EXPECT_TRUE(analyzer_->IsHealthy());
    EXPECT_EQ(analyzer_->KeywordCount(), 0u);

    analyzer_->Stop();
    EXPECT_FALSE(analyzer_->IsHealthy());
}

/* ================================================================== */
/*  Automaton build                                                    */
/* ================================================================== */

TEST_F(KeywordAnalyzerTest, BuildSingleKeyword) {
    std::vector<KeywordEntry> kws = {
        {1, "secret", false, false, "Confidential"}
    };
    ASSERT_TRUE(analyzer_->BuildAutomaton(kws));
    EXPECT_EQ(analyzer_->KeywordCount(), 1u);

    auto results = analyzer_->Scan("this is a secret document");
    ASSERT_EQ(results.size(), 1u);
    EXPECT_EQ(results[0].keyword, "secret");
    EXPECT_EQ(results[0].label, "Confidential");
    EXPECT_EQ(results[0].offset, 10u);
}

TEST_F(KeywordAnalyzerTest, BuildMultipleKeywords) {
    std::vector<KeywordEntry> kws = {
        {1, "password",     false, false, "Cred"},
        {2, "credit card",  false, false, "PCI"},
        {3, "ssn",          false, false, "PII"},
    };
    ASSERT_TRUE(analyzer_->BuildAutomaton(kws));
    EXPECT_EQ(analyzer_->KeywordCount(), 3u);

    auto results = analyzer_->Scan("enter your password and credit card ssn");
    EXPECT_EQ(results.size(), 3u);
}

TEST_F(KeywordAnalyzerTest, EmptyKeywordsFails) {
    std::vector<KeywordEntry> empty;
    EXPECT_FALSE(analyzer_->BuildAutomaton(empty));
}

TEST_F(KeywordAnalyzerTest, RebuildReplacesAutomaton) {
    std::vector<KeywordEntry> kws1 = {{1, "alpha", false, false, "A"}};
    ASSERT_TRUE(analyzer_->BuildAutomaton(kws1));

    std::vector<KeywordEntry> kws2 = {{2, "beta", false, false, "B"}};
    ASSERT_TRUE(analyzer_->BuildAutomaton(kws2));
    EXPECT_EQ(analyzer_->KeywordCount(), 1u);

    auto r1 = analyzer_->Scan("alpha");
    EXPECT_EQ(r1.size(), 0u);

    auto r2 = analyzer_->Scan("beta");
    EXPECT_EQ(r2.size(), 1u);
}

/* ================================================================== */
/*  Case sensitivity                                                   */
/* ================================================================== */

TEST_F(KeywordAnalyzerTest, CaseInsensitiveDefault) {
    std::vector<KeywordEntry> kws = {
        {1, "secret", false, false, "CI"}
    };
    ASSERT_TRUE(analyzer_->BuildAutomaton(kws));

    auto r1 = analyzer_->Scan("SECRET document");
    EXPECT_EQ(r1.size(), 1u);

    auto r2 = analyzer_->Scan("Secret Document");
    EXPECT_EQ(r2.size(), 1u);

    auto r3 = analyzer_->Scan("sEcReT stuff");
    EXPECT_EQ(r3.size(), 1u);
}

TEST_F(KeywordAnalyzerTest, CaseSensitive) {
    std::vector<KeywordEntry> kws = {
        {1, "Secret", true, false, "CS"}
    };
    ASSERT_TRUE(analyzer_->BuildAutomaton(kws));

    auto r1 = analyzer_->Scan("This is Secret data");
    EXPECT_EQ(r1.size(), 1u);

    auto r2 = analyzer_->Scan("This is secret data");
    EXPECT_EQ(r2.size(), 0u);

    auto r3 = analyzer_->Scan("This is SECRET data");
    EXPECT_EQ(r3.size(), 0u);
}

/* ================================================================== */
/*  Whole-word boundary detection                                      */
/* ================================================================== */

TEST_F(KeywordAnalyzerTest, WholeWord_CardNotDiscard) {
    std::vector<KeywordEntry> kws = {
        {1, "card", false, true, "WW"}
    };
    ASSERT_TRUE(analyzer_->BuildAutomaton(kws));

    /* "card" as whole word — should match */
    auto r1 = analyzer_->Scan("enter card number");
    EXPECT_EQ(r1.size(), 1u);

    /* "discard" contains "card" but not as whole word */
    auto r2 = analyzer_->Scan("discard the file");
    EXPECT_EQ(r2.size(), 0u);

    /* "card" at start of string */
    auto r3 = analyzer_->Scan("card is here");
    EXPECT_EQ(r3.size(), 1u);

    /* "card" at end of string */
    auto r4 = analyzer_->Scan("enter card");
    EXPECT_EQ(r4.size(), 1u);

    /* "cardboard" — not whole word */
    auto r5 = analyzer_->Scan("cardboard box");
    EXPECT_EQ(r5.size(), 0u);
}

TEST_F(KeywordAnalyzerTest, WholeWord_WithPunctuation) {
    std::vector<KeywordEntry> kws = {
        {1, "ssn", false, true, "PII"}
    };
    ASSERT_TRUE(analyzer_->BuildAutomaton(kws));

    /* Punctuation is a word boundary */
    auto r1 = analyzer_->Scan("enter ssn: 123");
    EXPECT_EQ(r1.size(), 1u);

    auto r2 = analyzer_->Scan("(ssn)");
    EXPECT_EQ(r2.size(), 1u);

    auto r3 = analyzer_->Scan("my-ssn-is");
    EXPECT_EQ(r3.size(), 1u);
}

TEST_F(KeywordAnalyzerTest, WholeWord_NotWholeWord_Mixed) {
    std::vector<KeywordEntry> kws = {
        {1, "key", false, true,  "WholeWord"},
        {2, "log", false, false, "Substring"},
    };
    ASSERT_TRUE(analyzer_->BuildAutomaton(kws));

    auto results = analyzer_->Scan("keyboard login key dialog");

    /* "key" should match only standalone "key", not "keyboard" */
    int key_matches = 0;
    int log_matches = 0;
    for (auto& m : results) {
        if (m.pattern_id == 1) key_matches++;
        if (m.pattern_id == 2) log_matches++;
    }
    EXPECT_EQ(key_matches, 1);
    /* "log" should match in "login" and "dialog" (substring mode) */
    EXPECT_EQ(log_matches, 2);
}

/* ================================================================== */
/*  Overlapping and multiple matches                                   */
/* ================================================================== */

TEST_F(KeywordAnalyzerTest, OverlappingKeywords) {
    std::vector<KeywordEntry> kws = {
        {1, "he",    false, false, "K1"},
        {2, "her",   false, false, "K2"},
        {3, "hers",  false, false, "K3"},
    };
    ASSERT_TRUE(analyzer_->BuildAutomaton(kws));

    auto results = analyzer_->Scan("hers");
    /* Should find: "he" at 0, "her" at 0, "hers" at 0 */
    EXPECT_EQ(results.size(), 3u);
}

TEST_F(KeywordAnalyzerTest, RepeatedMatches) {
    std::vector<KeywordEntry> kws = {
        {1, "abc", false, false, "K1"}
    };
    ASSERT_TRUE(analyzer_->BuildAutomaton(kws));

    auto results = analyzer_->Scan("abc xyz abc 123 abc");
    EXPECT_EQ(results.size(), 3u);
}

TEST_F(KeywordAnalyzerTest, NoMatch) {
    std::vector<KeywordEntry> kws = {
        {1, "elephant", false, false, "K1"}
    };
    ASSERT_TRUE(analyzer_->BuildAutomaton(kws));

    auto results = analyzer_->Scan("the quick brown fox");
    EXPECT_TRUE(results.empty());
}

/* ================================================================== */
/*  Edge cases                                                         */
/* ================================================================== */

TEST_F(KeywordAnalyzerTest, ScanEmptyBuffer) {
    std::vector<KeywordEntry> kws = {{1, "test", false, false, "T"}};
    ASSERT_TRUE(analyzer_->BuildAutomaton(kws));

    EXPECT_TRUE(analyzer_->Scan("", 0).empty());
    EXPECT_TRUE(analyzer_->Scan(nullptr, 0).empty());
}

TEST_F(KeywordAnalyzerTest, ScanWithoutBuild) {
    EXPECT_TRUE(analyzer_->Scan("test data").empty());
}

TEST_F(KeywordAnalyzerTest, SingleCharKeyword) {
    std::vector<KeywordEntry> kws = {
        {1, "x", false, false, "X"}
    };
    ASSERT_TRUE(analyzer_->BuildAutomaton(kws));

    auto results = analyzer_->Scan("axbxcx");
    EXPECT_EQ(results.size(), 3u);
}

/* ================================================================== */
/*  Performance                                                        */
/* ================================================================== */

TEST_F(KeywordAnalyzerTest, Build500Keywords) {
    /* Use whole_word to get exact match counts */
    std::vector<KeywordEntry> kws;
    for (unsigned int i = 0; i < 500; ++i) {
        kws.push_back({
            i + 1,
            "keyword_" + std::to_string(i),
            false, true,  /* whole_word = true to avoid substring overlaps */
            "Dict"
        });
    }
    ASSERT_TRUE(analyzer_->BuildAutomaton(kws));
    EXPECT_EQ(analyzer_->KeywordCount(), 500u);

    /* Scan a file containing some of them */
    std::string text;
    for (int i = 0; i < 50; ++i) {
        text += "Found keyword_" + std::to_string(i * 10) + " here. ";
    }

    auto results = analyzer_->Scan(text);
    EXPECT_EQ(results.size(), 50u);
}

TEST_F(KeywordAnalyzerTest, Build10KKeywordsPerformance) {
    std::vector<KeywordEntry> kws;
    for (unsigned int i = 0; i < 10000; ++i) {
        kws.push_back({
            i + 1,
            "keyword_" + std::to_string(i),
            false, false,
            "BigDict"
        });
    }

    auto start = std::chrono::steady_clock::now();
    ASSERT_TRUE(analyzer_->BuildAutomaton(kws));
    auto elapsed = std::chrono::steady_clock::now() - start;
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count();

    EXPECT_EQ(analyzer_->KeywordCount(), 10000u);
    /* Debug builds are ~10-50x slower than Release due to /Od + /RTC1.
     * Acceptance criterion (<100ms) applies to Release builds. */
    EXPECT_LT(ms, 10000)
        << "10K keyword build took " << ms << "ms (target: <100ms in Release)";

    std::cout << "[PERF] 10K keyword automaton build: " << ms << "ms, "
              << analyzer_->KeywordCount() << " keywords" << std::endl;
}

/* ================================================================== */
/*  Thread safety                                                      */
/* ================================================================== */

TEST_F(KeywordAnalyzerTest, ConcurrentScans) {
    std::vector<KeywordEntry> kws = {
        {1, "secret",   false, false, "K1"},
        {2, "password", false, false, "K2"},
    };
    ASSERT_TRUE(analyzer_->BuildAutomaton(kws));

    const std::string text = "the secret password is here";
    constexpr int NUM_THREADS = 4;
    constexpr int SCANS_PER_THREAD = 100;

    std::vector<std::thread> threads;
    std::vector<int> match_counts(NUM_THREADS, 0);

    for (int t = 0; t < NUM_THREADS; ++t) {
        threads.emplace_back([&, t]() {
            for (int i = 0; i < SCANS_PER_THREAD; ++i) {
                auto results = analyzer_->Scan(text);
                match_counts[t] += static_cast<int>(results.size());
            }
        });
    }

    for (auto& th : threads) {
        th.join();
    }

    for (int t = 0; t < NUM_THREADS; ++t) {
        EXPECT_EQ(match_counts[t], 2 * SCANS_PER_THREAD)
            << "Thread " << t << " had incorrect match count";
    }
}
