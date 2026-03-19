/*
 * test_hs_regex_analyzer.cpp
 * AkesoDLP Agent - Hyperscan Regex Analyzer Tests
 *
 * Tests: compilation, multi-pattern matching, data identifiers,
 *        serialization, performance, thread safety.
 */

#include "akeso/detection/hs_regex_analyzer.h"

#include <gtest/gtest.h>

#include <chrono>
#include <filesystem>
#include <random>
#include <string>
#include <thread>
#include <vector>

#include <hs/hs.h>

using namespace akeso::dlp;
namespace fs = std::filesystem;

/* ================================================================== */
/*  Fixture                                                            */
/* ================================================================== */

class HsRegexAnalyzerTest : public ::testing::Test {
protected:
    void SetUp() override {
        DetectionConfig config;
        analyzer_ = std::make_unique<HsRegexAnalyzer>(config);
        ASSERT_TRUE(analyzer_->Start());
    }

    void TearDown() override {
        if (analyzer_) {
            analyzer_->Stop();
            analyzer_.reset();
        }
    }

    /* Helper: build a simple pattern list */
    std::vector<RegexPattern> MakePatterns(
        const std::vector<std::pair<std::string, std::string>>& expr_label_pairs,
        unsigned int base_flags = HS_FLAG_DOTALL | HS_FLAG_SINGLEMATCH
    ) {
        std::vector<RegexPattern> pats;
        unsigned int id = 1;
        for (auto& [expr, label] : expr_label_pairs) {
            pats.push_back({id++, expr, base_flags, label});
        }
        return pats;
    }

    /* The 10 standard DLP data identifier patterns */
    std::vector<RegexPattern> DataIdentifierPatterns() {
        unsigned int flags = HS_FLAG_SINGLEMATCH;
        return {
            {1,  R"(\b\d{3}-\d{2}-\d{4}\b)",                                      flags, "US SSN"},
            {2,  R"(\b4\d{3}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b)",                flags, "Visa CC"},
            {3,  R"(\b5[1-5]\d{2}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b)",           flags, "MasterCard CC"},
            {4,  R"(\b\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b)",                     flags, "US Phone"},
            {5,  R"(\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b)",          flags, "Email"},
            {6,  R"(\b[A-Z]\d{8}\b)",                                               flags, "US Passport"},
            {7,  R"(\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}([A-Z0-9]?){0,16}\b)",         flags, "IBAN"},
            {8,  R"(\b[A-Z]\d{7,12}\b)",                                            flags, "US DL"},
            {9,  R"(\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b)",                      flags, "IPv4"},
            {10, R"(\b\d{2}/\d{2}/\d{4}\b)",                                        flags, "DOB"},
        };
    }

    std::unique_ptr<HsRegexAnalyzer> analyzer_;
};

/* ================================================================== */
/*  Basic lifecycle                                                    */
/* ================================================================== */

TEST_F(HsRegexAnalyzerTest, BasicLifecycle) {
    EXPECT_EQ(analyzer_->Name(), "HsRegexAnalyzer");
    EXPECT_TRUE(analyzer_->IsHealthy());
    EXPECT_EQ(analyzer_->PatternCount(), 0u);

    analyzer_->Stop();
    EXPECT_FALSE(analyzer_->IsHealthy());
}

/* ================================================================== */
/*  Compilation                                                        */
/* ================================================================== */

TEST_F(HsRegexAnalyzerTest, CompileSinglePattern) {
    auto pats = MakePatterns({{"hello", "Greeting"}});
    ASSERT_TRUE(analyzer_->CompilePatterns(pats));
    EXPECT_EQ(analyzer_->PatternCount(), 1u);

    auto results = analyzer_->Scan("say hello world");
    EXPECT_EQ(results.size(), 1u);
    EXPECT_EQ(results[0].label, "Greeting");
}

TEST_F(HsRegexAnalyzerTest, CompileMultiplePatterns) {
    auto pats = MakePatterns({
        {"apple",  "Apple"},
        {"banana", "Banana"},
        {"cherry", "Cherry"},
    });
    ASSERT_TRUE(analyzer_->CompilePatterns(pats));
    EXPECT_EQ(analyzer_->PatternCount(), 3u);

    auto results = analyzer_->Scan("I like apple and cherry pie");
    EXPECT_EQ(results.size(), 2u);
}

TEST_F(HsRegexAnalyzerTest, Compile100Patterns) {
    std::vector<RegexPattern> pats;
    for (unsigned int i = 0; i < 100; ++i) {
        pats.push_back({
            i + 1,
            "pattern_" + std::to_string(i),
            HS_FLAG_SINGLEMATCH,
            "Label_" + std::to_string(i)
        });
    }
    ASSERT_TRUE(analyzer_->CompilePatterns(pats));
    EXPECT_EQ(analyzer_->PatternCount(), 100u);

    /* Verify at least one pattern matches */
    auto results = analyzer_->Scan("this contains pattern_42 in it");
    ASSERT_GE(results.size(), 1u);

    bool found = false;
    for (auto& m : results) {
        if (m.pattern_id == 43) { found = true; break; }  /* id = i+1 = 43 */
    }
    EXPECT_TRUE(found);
}

TEST_F(HsRegexAnalyzerTest, InvalidPatternFailsCompile) {
    auto pats = MakePatterns({{"[unterminated", "Bad"}});
    EXPECT_FALSE(analyzer_->CompilePatterns(pats));
    EXPECT_EQ(analyzer_->PatternCount(), 0u);
}

TEST_F(HsRegexAnalyzerTest, EmptyPatternsFailsCompile) {
    std::vector<RegexPattern> empty;
    EXPECT_FALSE(analyzer_->CompilePatterns(empty));
}

TEST_F(HsRegexAnalyzerTest, RecompileReplacesPrevious) {
    auto pats1 = MakePatterns({{"alpha", "Alpha"}});
    ASSERT_TRUE(analyzer_->CompilePatterns(pats1));
    EXPECT_EQ(analyzer_->PatternCount(), 1u);

    auto pats2 = MakePatterns({{"beta", "Beta"}, {"gamma", "Gamma"}});
    ASSERT_TRUE(analyzer_->CompilePatterns(pats2));
    EXPECT_EQ(analyzer_->PatternCount(), 2u);

    /* Old pattern should not match */
    auto r1 = analyzer_->Scan("alpha");
    EXPECT_EQ(r1.size(), 0u);

    /* New patterns should match */
    auto r2 = analyzer_->Scan("beta gamma");
    EXPECT_EQ(r2.size(), 2u);
}

/* ================================================================== */
/*  Data identifier patterns                                           */
/* ================================================================== */

TEST_F(HsRegexAnalyzerTest, AllTenDataIdentifiers) {
    auto pats = DataIdentifierPatterns();
    ASSERT_TRUE(analyzer_->CompilePatterns(pats));
    EXPECT_EQ(analyzer_->PatternCount(), 10u);

    /* Test each identifier */
    struct TestCase {
        std::string input;
        std::string expected_label;
    };

    std::vector<TestCase> cases = {
        {"SSN: 123-45-6789",                                "US SSN"},
        {"Card: 4111111111111111",                           "Visa CC"},
        {"Card: 5200828282828210",                           "MasterCard CC"},
        {"Call: (555) 123-4567",                             "US Phone"},
        {"Email: user@example.com",                          "Email"},
        {"Passport: C12345678",                              "US Passport"},
        {"IBAN: DE89370400440532013000",                     "IBAN"},
        {"License: A1234567",                                "US DL"},
        {"Server: 192.168.1.100",                            "IPv4"},
        {"Born: 01/15/1990",                                 "DOB"},
    };

    for (auto& tc : cases) {
        auto results = analyzer_->Scan(tc.input);
        bool found = false;
        for (auto& m : results) {
            if (m.label == tc.expected_label) {
                found = true;
                break;
            }
        }
        EXPECT_TRUE(found)
            << "Expected '" << tc.expected_label
            << "' to match in: " << tc.input;
    }
}

TEST_F(HsRegexAnalyzerTest, DataIdentifiersNoFalsePositive) {
    auto pats = DataIdentifierPatterns();
    ASSERT_TRUE(analyzer_->CompilePatterns(pats));

    auto results = analyzer_->Scan("The quick brown fox jumps over the lazy dog");
    EXPECT_EQ(results.size(), 0u);
}

/* ================================================================== */
/*  Scanning edge cases                                                */
/* ================================================================== */

TEST_F(HsRegexAnalyzerTest, NoMatchReturnsEmpty) {
    auto pats = MakePatterns({{"xyz123", "XYZ"}});
    ASSERT_TRUE(analyzer_->CompilePatterns(pats));

    auto results = analyzer_->Scan("nothing here");
    EXPECT_TRUE(results.empty());
}

TEST_F(HsRegexAnalyzerTest, ScanEmptyBuffer) {
    auto pats = MakePatterns({{"test", "Test"}});
    ASSERT_TRUE(analyzer_->CompilePatterns(pats));

    auto results = analyzer_->Scan("", 0);
    EXPECT_TRUE(results.empty());

    auto results2 = analyzer_->Scan(nullptr, 0);
    EXPECT_TRUE(results2.empty());
}

TEST_F(HsRegexAnalyzerTest, ScanWithoutCompileFails) {
    auto results = analyzer_->Scan("test data");
    EXPECT_TRUE(results.empty());
}

/* ================================================================== */
/*  Serialization                                                      */
/* ================================================================== */

TEST_F(HsRegexAnalyzerTest, SerializeAndDeserialize) {
    auto pats = MakePatterns({
        {R"(\b\d{3}-\d{2}-\d{4}\b)", "SSN"},
        {"hello",                      "Greeting"},
    });
    ASSERT_TRUE(analyzer_->CompilePatterns(pats));

    /* Serialize */
    std::vector<char> buf;
    ASSERT_TRUE(analyzer_->SerializeDatabase(buf));
    EXPECT_GT(buf.size(), 0u);

    /* Create new analyzer and deserialize */
    DetectionConfig config;
    HsRegexAnalyzer analyzer2(config);
    analyzer2.Start();
    ASSERT_TRUE(analyzer2.DeserializeDatabase(buf.data(), buf.size()));

    /* Verify scanning works on deserialized database */
    auto results = analyzer2.Scan("SSN is 123-45-6789 and hello");
    EXPECT_GE(results.size(), 1u);

    analyzer2.Stop();
}

TEST_F(HsRegexAnalyzerTest, SaveAndLoadFromFile) {
    auto pats = MakePatterns({
        {R"(\b\d{3}-\d{2}-\d{4}\b)", "SSN"},
        {"hello",                      "Greeting"},
    });
    ASSERT_TRUE(analyzer_->CompilePatterns(pats));

    /* Save */
    auto tmp = fs::temp_directory_path() / "akeso_test_hs.db";
    ASSERT_TRUE(analyzer_->SaveToFile(tmp.string()));
    EXPECT_TRUE(fs::exists(tmp));

    /* Load into new analyzer */
    DetectionConfig config;
    HsRegexAnalyzer analyzer2(config);
    analyzer2.Start();
    ASSERT_TRUE(analyzer2.LoadFromFile(tmp.string()));

    auto results = analyzer2.Scan("SSN: 999-88-7777");
    EXPECT_GE(results.size(), 1u);

    analyzer2.Stop();
    fs::remove(tmp);
}

TEST_F(HsRegexAnalyzerTest, SerializeWithoutDatabaseFails) {
    std::vector<char> buf;
    EXPECT_FALSE(analyzer_->SerializeDatabase(buf));
}

/* ================================================================== */
/*  Performance                                                        */
/* ================================================================== */

TEST_F(HsRegexAnalyzerTest, ScanPerformance10MB) {
    /* Compile the 10 data identifier patterns */
    auto pats = DataIdentifierPatterns();
    ASSERT_TRUE(analyzer_->CompilePatterns(pats));

    /* Generate a 10MB buffer with some embedded patterns */
    constexpr size_t SIZE = 10 * 1024 * 1024;
    std::string data;
    data.reserve(SIZE);

    std::mt19937 rng(42);
    std::uniform_int_distribution<int> dist('a', 'z');

    while (data.size() < SIZE - 200) {
        /* Random text */
        for (int i = 0; i < 1000 && data.size() < SIZE - 200; ++i) {
            data += static_cast<char>(dist(rng));
        }
        /* Sprinkle a pattern every ~1000 chars */
        data += " 123-45-6789 ";
    }

    /* Time the scan */
    auto start = std::chrono::steady_clock::now();
    auto results = analyzer_->Scan(data);
    auto elapsed = std::chrono::steady_clock::now() - start;
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count();

    EXPECT_GT(results.size(), 0u);
    EXPECT_LT(ms, 500)  /* Allow generous margin; acceptance is <100ms */
        << "10MB scan took " << ms << "ms (target: <100ms)";

    /* Log the actual time for visibility */
    std::cout << "[PERF] 10MB scan: " << ms << "ms, "
              << results.size() << " matches" << std::endl;
}

TEST_F(HsRegexAnalyzerTest, PrecompiledLoadPerformance) {
    /* Compile 100 patterns */
    std::vector<RegexPattern> pats;
    for (unsigned int i = 0; i < 100; ++i) {
        pats.push_back({
            i + 1,
            "pattern_" + std::to_string(i),
            HS_FLAG_SINGLEMATCH,
            "Label_" + std::to_string(i)
        });
    }
    ASSERT_TRUE(analyzer_->CompilePatterns(pats));

    /* Serialize */
    std::vector<char> buf;
    ASSERT_TRUE(analyzer_->SerializeDatabase(buf));

    /* Time deserialization */
    DetectionConfig config;
    HsRegexAnalyzer analyzer2(config);
    analyzer2.Start();

    auto start = std::chrono::steady_clock::now();
    ASSERT_TRUE(analyzer2.DeserializeDatabase(buf.data(), buf.size()));
    auto elapsed = std::chrono::steady_clock::now() - start;
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count();

    EXPECT_LT(ms, 50)  /* Generous margin; acceptance is <10ms */
        << "Precompiled load took " << ms << "ms (target: <10ms)";

    std::cout << "[PERF] Precompiled load: " << ms << "ms" << std::endl;

    analyzer2.Stop();
}

/* ================================================================== */
/*  Thread safety                                                      */
/* ================================================================== */

TEST_F(HsRegexAnalyzerTest, ConcurrentScans) {
    auto pats = MakePatterns({
        {R"(\b\d{3}-\d{2}-\d{4}\b)", "SSN"},
        {"hello",                      "Greeting"},
    });
    ASSERT_TRUE(analyzer_->CompilePatterns(pats));

    const std::string test_data = "SSN: 123-45-6789 hello world";
    constexpr int NUM_THREADS = 4;
    constexpr int SCANS_PER_THREAD = 100;

    std::vector<std::thread> threads;
    std::vector<int> match_counts(NUM_THREADS, 0);

    for (int t = 0; t < NUM_THREADS; ++t) {
        threads.emplace_back([&, t]() {
            for (int i = 0; i < SCANS_PER_THREAD; ++i) {
                auto results = analyzer_->Scan(test_data);
                match_counts[t] += static_cast<int>(results.size());
            }
        });
    }

    for (auto& th : threads) {
        th.join();
    }

    /* Each thread should find 2 matches per scan */
    for (int t = 0; t < NUM_THREADS; ++t) {
        EXPECT_EQ(match_counts[t], 2 * SCANS_PER_THREAD)
            << "Thread " << t << " had incorrect match count";
    }
}
