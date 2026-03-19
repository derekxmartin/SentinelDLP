/*
 * keyword_analyzer.h
 * AkesoDLP Agent - Aho-Corasick Keyword Analyzer
 *
 * Builds an Aho-Corasick automaton from keyword dictionaries for
 * multi-pattern simultaneous matching. Supports case-sensitive and
 * case-insensitive modes, and whole-word boundary detection.
 */

#pragma once

#include "akeso/agent_service.h"
#include "akeso/config.h"

#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace akeso::dlp {

/* ------------------------------------------------------------------ */
/*  Types                                                              */
/* ------------------------------------------------------------------ */

struct KeywordEntry {
    unsigned int id;           /* Unique keyword ID */
    std::string  keyword;      /* The keyword string */
    bool         case_sensitive = false;
    bool         whole_word     = false;
    std::string  label;        /* Human-readable label (e.g. dictionary name) */
};

struct KeywordMatch {
    unsigned int pattern_id;
    std::string  label;
    std::string  keyword;      /* The keyword that matched */
    size_t       offset;       /* Start position in scanned text */
};

/* ------------------------------------------------------------------ */
/*  Aho-Corasick internals (forward declared)                          */
/* ------------------------------------------------------------------ */

struct AcNode;

/* ------------------------------------------------------------------ */
/*  KeywordAnalyzer                                                    */
/* ------------------------------------------------------------------ */

class KeywordAnalyzer : public IAgentComponent {
public:
    explicit KeywordAnalyzer(const DetectionConfig& config);
    ~KeywordAnalyzer() override;

    /* Non-copyable */
    KeywordAnalyzer(const KeywordAnalyzer&) = delete;
    KeywordAnalyzer& operator=(const KeywordAnalyzer&) = delete;

    /* IAgentComponent */
    std::string Name() const override { return "KeywordAnalyzer"; }
    bool Start() override;
    void Stop() override;
    bool IsHealthy() const override;

    /* --- Dictionary management --- */

    /*
     * Build the Aho-Corasick automaton from a set of keywords.
     * Returns false if the keyword list is empty.
     */
    bool BuildAutomaton(const std::vector<KeywordEntry>& keywords);

    /* Number of keywords in the automaton */
    size_t KeywordCount() const;

    /* --- Scanning --- */

    /*
     * Scan a buffer for all keyword matches. Thread-safe.
     */
    std::vector<KeywordMatch> Scan(const char* data, size_t length) const;
    std::vector<KeywordMatch> Scan(const std::string& data) const;

private:
    /* Automaton construction */
    void InsertKeyword(size_t keyword_idx);
    void BuildFailureLinks();

    /* Whole-word boundary check */
    static bool IsWordBoundary(const char* data, size_t length,
                               size_t match_start, size_t match_len);
    static bool IsWordChar(char c);

    DetectionConfig                   config_;
    std::vector<AcNode>               nodes_;
    std::vector<KeywordEntry>         keywords_;
    bool                              running_{false};
    bool                              built_{false};
    mutable std::mutex                mutex_;
};

}  // namespace akeso::dlp
