/*
 * keyword_analyzer.cpp
 * AkesoDLP Agent - Aho-Corasick Keyword Analyzer
 *
 * Classic Aho-Corasick multi-pattern string matching with:
 *   - Case-insensitive mode (lowercased trie + lowercased scan)
 *   - Whole-word boundary detection
 *   - Dictionary suffix links for overlapping matches
 */

#include "akeso/detection/keyword_analyzer.h"

#include <algorithm>
#include <cctype>
#include <queue>

/* Conditional spdlog */
#ifdef HAS_SPDLOG
#include <spdlog/spdlog.h>
#define LOG_INFO(...)  spdlog::info(__VA_ARGS__)
#define LOG_WARN(...)  spdlog::warn(__VA_ARGS__)
#define LOG_ERROR(...) spdlog::error(__VA_ARGS__)
#else
#define LOG_INFO(...)  (void)0
#define LOG_WARN(...)  (void)0
#define LOG_ERROR(...) (void)0
#endif

namespace akeso::dlp {

/* ================================================================== */
/*  Aho-Corasick node                                                  */
/* ================================================================== */

struct AcNode {
    std::unordered_map<char, int> children;
    int  fail{0};               /* Failure link (index into nodes_) */
    int  dict_suffix{-1};       /* Dictionary suffix link */
    int  keyword_index{-1};     /* Index into keywords_ (-1 if not terminal) */
};

/* ================================================================== */
/*  Lifecycle                                                          */
/* ================================================================== */

KeywordAnalyzer::KeywordAnalyzer(const DetectionConfig& config)
    : config_(config)
{
}

KeywordAnalyzer::~KeywordAnalyzer() {
    Stop();
}

bool KeywordAnalyzer::Start() {
    std::lock_guard lock(mutex_);
    running_ = true;
    LOG_INFO("[KeywordAnalyzer] Started");
    return true;
}

void KeywordAnalyzer::Stop() {
    std::lock_guard lock(mutex_);
    if (!running_) return;
    nodes_.clear();
    keywords_.clear();
    built_ = false;
    running_ = false;
    LOG_INFO("[KeywordAnalyzer] Stopped");
}

bool KeywordAnalyzer::IsHealthy() const {
    return running_;
}

/* ================================================================== */
/*  Automaton construction                                             */
/* ================================================================== */

bool KeywordAnalyzer::BuildAutomaton(const std::vector<KeywordEntry>& keywords) {
    std::lock_guard lock(mutex_);

    if (keywords.empty()) {
        LOG_WARN("[KeywordAnalyzer] No keywords to build");
        return false;
    }

    /* Reset */
    nodes_.clear();
    keywords_ = keywords;
    built_ = false;

    /* Root node (index 0) */
    nodes_.emplace_back();

    /* Insert all keywords */
    for (size_t i = 0; i < keywords_.size(); ++i) {
        InsertKeyword(i);
    }

    /* Build failure and dictionary suffix links */
    BuildFailureLinks();

    built_ = true;
    LOG_INFO("[KeywordAnalyzer] Built automaton with {} keywords, {} nodes",
             keywords_.size(), nodes_.size());
    return true;
}

void KeywordAnalyzer::InsertKeyword(size_t keyword_idx) {
    const auto& entry = keywords_[keyword_idx];
    int cur = 0;

    for (char ch : entry.keyword) {
        /* Always store lowercase in trie — case-sensitive validation
         * is done during the scan output phase */
        ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));

        auto it = nodes_[cur].children.find(ch);
        if (it == nodes_[cur].children.end()) {
            nodes_[cur].children[ch] = static_cast<int>(nodes_.size());
            nodes_.emplace_back();
            cur = static_cast<int>(nodes_.size()) - 1;
        } else {
            cur = it->second;
        }
    }

    nodes_[cur].keyword_index = static_cast<int>(keyword_idx);
}

void KeywordAnalyzer::BuildFailureLinks() {
    std::queue<int> bfs;

    /* Root's children fail to root */
    for (auto& [ch, child_idx] : nodes_[0].children) {
        nodes_[child_idx].fail = 0;
        nodes_[child_idx].dict_suffix = (nodes_[0].keyword_index >= 0) ? 0 : -1;
        bfs.push(child_idx);
    }

    while (!bfs.empty()) {
        int u = bfs.front();
        bfs.pop();

        for (auto& [ch, v] : nodes_[u].children) {
            /* Compute fail link for v */
            int f = nodes_[u].fail;
            while (f != 0 && nodes_[f].children.find(ch) == nodes_[f].children.end()) {
                f = nodes_[f].fail;
            }

            auto it = nodes_[f].children.find(ch);
            if (it != nodes_[f].children.end() && it->second != v) {
                nodes_[v].fail = it->second;
            } else {
                nodes_[v].fail = 0;
            }

            /* Dictionary suffix link: nearest ancestor (via fail) that is a terminal */
            if (nodes_[nodes_[v].fail].keyword_index >= 0) {
                nodes_[v].dict_suffix = nodes_[v].fail;
            } else {
                nodes_[v].dict_suffix = nodes_[nodes_[v].fail].dict_suffix;
            }

            bfs.push(v);
        }
    }
}

size_t KeywordAnalyzer::KeywordCount() const {
    std::lock_guard lock(mutex_);
    return keywords_.size();
}

/* ================================================================== */
/*  Scanning                                                           */
/* ================================================================== */

std::vector<KeywordMatch> KeywordAnalyzer::Scan(const char* data, size_t length) const {
    std::vector<KeywordMatch> results;

    if (!data || length == 0) return results;

    std::lock_guard lock(mutex_);

    if (!built_ || nodes_.empty()) return results;

    int cur = 0;

    for (size_t i = 0; i < length; ++i) {
        char ch = data[i];

        /* We need to handle mixed case-sensitive/insensitive keywords.
         * Since case-insensitive keywords are stored lowercased in the trie,
         * we search with lowercase. Case-sensitive keywords are stored as-is.
         * For simplicity, we run with lowercase and validate case-sensitive
         * matches in the output phase. */
        char lch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));

        /* Follow failure links until we find a match or reach root */
        while (cur != 0 && nodes_[cur].children.find(lch) == nodes_[cur].children.end()) {
            cur = nodes_[cur].fail;
        }

        auto it = nodes_[cur].children.find(lch);
        if (it != nodes_[cur].children.end()) {
            cur = it->second;
        } else {
            cur = 0;
        }

        /* Check current node and all dictionary suffix links for matches */
        int check = cur;
        while (check > 0) {
            int kw_idx = -1;
            if (nodes_[check].keyword_index >= 0) {
                kw_idx = nodes_[check].keyword_index;
            }

            if (kw_idx >= 0) {
                const auto& entry = keywords_[kw_idx];
                size_t kw_len = entry.keyword.size();
                size_t match_start = i + 1 - kw_len;

                bool valid = true;

                /* Case-sensitive validation: compare original text */
                if (entry.case_sensitive) {
                    for (size_t j = 0; j < kw_len && valid; ++j) {
                        if (data[match_start + j] != entry.keyword[j]) {
                            valid = false;
                        }
                    }
                }

                /* Whole-word boundary check */
                if (valid && entry.whole_word) {
                    if (!IsWordBoundary(data, length, match_start, kw_len)) {
                        valid = false;
                    }
                }

                if (valid) {
                    KeywordMatch m;
                    m.pattern_id = entry.id;
                    m.label = entry.label;
                    m.keyword = entry.keyword;
                    m.offset = match_start;
                    results.push_back(std::move(m));
                }
            }

            /* Follow dictionary suffix link */
            check = nodes_[check].dict_suffix;
        }
    }

    return results;
}

std::vector<KeywordMatch> KeywordAnalyzer::Scan(const std::string& data) const {
    return Scan(data.data(), data.size());
}

/* ================================================================== */
/*  Word boundary helpers                                              */
/* ================================================================== */

bool KeywordAnalyzer::IsWordChar(char c) {
    auto uc = static_cast<unsigned char>(c);
    return std::isalnum(uc) || c == '_';
}

bool KeywordAnalyzer::IsWordBoundary(const char* data, size_t length,
                                     size_t match_start, size_t match_len) {
    /* Check character before match */
    if (match_start > 0 && IsWordChar(data[match_start - 1])) {
        return false;
    }
    /* Check character after match */
    size_t match_end = match_start + match_len;
    if (match_end < length && IsWordChar(data[match_end])) {
        return false;
    }
    return true;
}

}  // namespace akeso::dlp
