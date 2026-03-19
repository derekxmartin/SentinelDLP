/*
 * hs_regex_analyzer.h
 * AkesoDLP Agent - Hyperscan Regex Analyzer
 *
 * Compiles all regex patterns from policy into a single Hyperscan
 * block-mode database for multi-pattern simultaneous matching.
 * Supports serialization for precompiled pattern reload.
 *
 * Thread safety: Scan() is thread-safe via scratch cloning.
 */

#pragma once

#ifdef HAS_HYPERSCAN

#include "akeso/agent_service.h"
#include "akeso/config.h"

#include <cstdint>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

/* Forward-declare Hyperscan types */
struct hs_database;
typedef struct hs_database hs_database_t;
struct hs_scratch;
typedef struct hs_scratch hs_scratch_t;

namespace akeso::dlp {

/* ------------------------------------------------------------------ */
/*  Types                                                              */
/* ------------------------------------------------------------------ */

struct RegexPattern {
    unsigned int id;           /* Unique pattern ID (Hyperscan match ID) */
    std::string  expression;   /* The regex string */
    unsigned int flags;        /* HS_FLAG_CASELESS, HS_FLAG_DOTALL, etc. */
    std::string  label;        /* Human-readable name (e.g. "US SSN") */
};

struct MatchResult {
    unsigned int       pattern_id;
    std::string        label;
    unsigned long long from;   /* Start offset (0 unless SOM enabled) */
    unsigned long long to;     /* End offset */
};

/* ------------------------------------------------------------------ */
/*  HsRegexAnalyzer                                                    */
/* ------------------------------------------------------------------ */

class HsRegexAnalyzer : public IAgentComponent {
public:
    explicit HsRegexAnalyzer(const DetectionConfig& config);
    ~HsRegexAnalyzer() override;

    /* Non-copyable */
    HsRegexAnalyzer(const HsRegexAnalyzer&) = delete;
    HsRegexAnalyzer& operator=(const HsRegexAnalyzer&) = delete;

    /* IAgentComponent */
    std::string Name() const override { return "HsRegexAnalyzer"; }
    bool Start() override;
    void Stop() override;
    bool IsHealthy() const override;

    /* --- Pattern management --- */

    /*
     * Compile a set of patterns into a single Hyperscan block-mode database.
     * Returns false if any pattern fails validation or compilation fails.
     */
    bool CompilePatterns(const std::vector<RegexPattern>& patterns);

    /* Number of compiled patterns */
    size_t PatternCount() const;

    /* --- Scanning --- */

    /*
     * Scan a buffer. Returns all matches. Thread-safe.
     */
    std::vector<MatchResult> Scan(const char* data, size_t length) const;
    std::vector<MatchResult> Scan(const std::string& data) const;

    /* --- Serialization --- */

    /* Serialize compiled database to a byte buffer */
    bool SerializeDatabase(std::vector<char>& out) const;

    /* Deserialize a previously compiled database */
    bool DeserializeDatabase(const char* data, size_t length);

    /* Save compiled database to file */
    bool SaveToFile(const std::string& path) const;

    /* Load compiled database from file */
    bool LoadFromFile(const std::string& path);

private:
    void FreeDatabase();
    void FreeScratch();
    bool AllocateScratch();

    /* Hyperscan match callback (C-linkage compatible) */
    static int OnMatch(unsigned int id, unsigned long long from,
                       unsigned long long to, unsigned int flags, void* context);

    DetectionConfig                          config_;
    hs_database_t*                           database_{nullptr};
    hs_scratch_t*                            scratch_{nullptr};
    std::vector<RegexPattern>                patterns_;
    std::unordered_map<unsigned int, size_t> id_to_index_;
    mutable std::mutex                       mutex_;
    bool                                     running_{false};
};

}  // namespace akeso::dlp

#endif  /* HAS_HYPERSCAN */
