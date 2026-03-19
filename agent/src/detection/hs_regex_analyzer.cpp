/*
 * hs_regex_analyzer.cpp
 * AkesoDLP Agent - Hyperscan Regex Analyzer
 *
 * Intel Hyperscan / Vectorscan block-mode multi-pattern matching.
 */

#ifdef HAS_HYPERSCAN

#include "akeso/detection/hs_regex_analyzer.h"

#pragma warning(push)
#pragma warning(disable: 4100 4267 4244)
#include <hs/hs.h>
#pragma warning(pop)

#include <algorithm>
#include <chrono>
#include <fstream>

/* Conditional spdlog */
#ifdef HAS_SPDLOG
#include <spdlog/spdlog.h>
#define LOG_INFO(...)  spdlog::info(__VA_ARGS__)
#define LOG_WARN(...)  spdlog::warn(__VA_ARGS__)
#define LOG_ERROR(...) spdlog::error(__VA_ARGS__)
#define LOG_DEBUG(...) spdlog::debug(__VA_ARGS__)
#else
#define LOG_INFO(...)  (void)0
#define LOG_WARN(...)  (void)0
#define LOG_ERROR(...) (void)0
#define LOG_DEBUG(...) (void)0
#endif

namespace akeso::dlp {

/* ================================================================== */
/*  Match callback context                                             */
/* ================================================================== */

struct ScanContext {
    std::vector<MatchResult>*                          results;
    const std::vector<RegexPattern>*                   patterns;
    const std::unordered_map<unsigned int, size_t>*    id_to_index;
};

/* ================================================================== */
/*  Lifecycle                                                          */
/* ================================================================== */

HsRegexAnalyzer::HsRegexAnalyzer(const DetectionConfig& config)
    : config_(config)
{
}

HsRegexAnalyzer::~HsRegexAnalyzer() {
    Stop();
}

bool HsRegexAnalyzer::Start() {
    std::lock_guard lock(mutex_);
    running_ = true;
    LOG_INFO("[HsRegexAnalyzer] Started");
    return true;
}

void HsRegexAnalyzer::Stop() {
    std::lock_guard lock(mutex_);
    if (!running_) return;
    FreeDatabase();
    running_ = false;
    LOG_INFO("[HsRegexAnalyzer] Stopped");
}

bool HsRegexAnalyzer::IsHealthy() const {
    return running_;
}

/* ================================================================== */
/*  Pattern compilation                                                */
/* ================================================================== */

bool HsRegexAnalyzer::CompilePatterns(const std::vector<RegexPattern>& patterns) {
    std::lock_guard lock(mutex_);

    if (patterns.empty()) {
        LOG_WARN("[HsRegexAnalyzer] No patterns to compile");
        return false;
    }

    /* Free any existing database */
    FreeDatabase();

    /* Build parallel arrays for hs_compile_multi */
    const size_t count = patterns.size();
    std::vector<const char*> expressions(count);
    std::vector<unsigned int> flags(count);
    std::vector<unsigned int> ids(count);

    for (size_t i = 0; i < count; ++i) {
        expressions[i] = patterns[i].expression.c_str();
        flags[i] = patterns[i].flags;
        ids[i] = patterns[i].id;
    }

    hs_compile_error_t* compile_err = nullptr;
    hs_error_t rc = hs_compile_multi(
        expressions.data(),
        flags.data(),
        ids.data(),
        static_cast<unsigned int>(count),
        HS_MODE_BLOCK,
        nullptr,  /* platform info - use current */
        &database_,
        &compile_err
    );

    if (rc != HS_SUCCESS) {
        if (compile_err) {
            LOG_ERROR("[HsRegexAnalyzer] Compile failed: {} (pattern index {})",
                      compile_err->message, compile_err->expression);
            hs_free_compile_error(compile_err);
        } else {
            LOG_ERROR("[HsRegexAnalyzer] Compile failed with code {}", rc);
        }
        database_ = nullptr;
        return false;
    }

    /* Allocate scratch space */
    if (!AllocateScratch()) {
        FreeDatabase();
        return false;
    }

    /* Store pattern metadata for match labeling */
    patterns_ = patterns;
    id_to_index_.clear();
    for (size_t i = 0; i < patterns_.size(); ++i) {
        id_to_index_[patterns_[i].id] = i;
    }

    LOG_INFO("[HsRegexAnalyzer] Compiled {} patterns", count);
    return true;
}

size_t HsRegexAnalyzer::PatternCount() const {
    std::lock_guard lock(mutex_);
    return patterns_.size();
}

/* ================================================================== */
/*  Scanning                                                           */
/* ================================================================== */

int HsRegexAnalyzer::OnMatch(unsigned int id, unsigned long long from,
                              unsigned long long to, unsigned int /*flags*/,
                              void* context) {
    auto* ctx = static_cast<ScanContext*>(context);

    MatchResult m;
    m.pattern_id = id;
    m.from = from;
    m.to = to;

    auto it = ctx->id_to_index->find(id);
    if (it != ctx->id_to_index->end()) {
        m.label = (*ctx->patterns)[it->second].label;
    }

    ctx->results->push_back(std::move(m));
    return 0;  /* Continue scanning */
}

std::vector<MatchResult> HsRegexAnalyzer::Scan(const char* data, size_t length) const {
    std::vector<MatchResult> results;

    if (!data || length == 0) return results;

    /* Lock to protect scratch cloning and database pointer */
    std::lock_guard lock(mutex_);

    if (!database_ || !scratch_) return results;

    /* Clone scratch for this scan (thread-safe) */
    hs_scratch_t* local_scratch = nullptr;
    if (hs_clone_scratch(scratch_, &local_scratch) != HS_SUCCESS) {
        LOG_ERROR("[HsRegexAnalyzer] Failed to clone scratch");
        return results;
    }

    ScanContext ctx;
    ctx.results = &results;
    ctx.patterns = &patterns_;
    ctx.id_to_index = &id_to_index_;

    hs_error_t rc = hs_scan(
        database_,
        data,
        static_cast<unsigned int>(length),
        0,  /* flags */
        local_scratch,
        OnMatch,
        &ctx
    );

    hs_free_scratch(local_scratch);

    if (rc != HS_SUCCESS && rc != HS_SCAN_TERMINATED) {
        LOG_ERROR("[HsRegexAnalyzer] Scan failed with code {}", rc);
    }

    return results;
}

std::vector<MatchResult> HsRegexAnalyzer::Scan(const std::string& data) const {
    return Scan(data.data(), data.size());
}

/* ================================================================== */
/*  Serialization                                                      */
/* ================================================================== */

bool HsRegexAnalyzer::SerializeDatabase(std::vector<char>& out) const {
    std::lock_guard lock(mutex_);

    if (!database_) {
        LOG_WARN("[HsRegexAnalyzer] No database to serialize");
        return false;
    }

    char* bytes = nullptr;
    size_t length = 0;

    if (hs_serialize_database(database_, &bytes, &length) != HS_SUCCESS) {
        LOG_ERROR("[HsRegexAnalyzer] Failed to serialize database");
        return false;
    }

    out.assign(bytes, bytes + length);
    /* hs_serialize_database uses hs_misc_alloc internally; must free with hs-provided free */
    std::free(bytes);

    LOG_DEBUG("[HsRegexAnalyzer] Serialized database ({} bytes)", length);
    return true;
}

bool HsRegexAnalyzer::DeserializeDatabase(const char* data, size_t length) {
    std::lock_guard lock(mutex_);

    FreeDatabase();

    if (hs_deserialize_database(data, length, &database_) != HS_SUCCESS) {
        LOG_ERROR("[HsRegexAnalyzer] Failed to deserialize database");
        database_ = nullptr;
        return false;
    }

    if (!AllocateScratch()) {
        FreeDatabase();
        return false;
    }

    LOG_INFO("[HsRegexAnalyzer] Deserialized database ({} bytes)", length);
    return true;
}

bool HsRegexAnalyzer::SaveToFile(const std::string& path) const {
    std::vector<char> buf;
    if (!SerializeDatabase(buf)) return false;

    std::ofstream ofs(path, std::ios::binary);
    if (!ofs) {
        LOG_ERROR("[HsRegexAnalyzer] Cannot open file for writing: {}", path);
        return false;
    }

    ofs.write(buf.data(), static_cast<std::streamsize>(buf.size()));
    if (!ofs) {
        LOG_ERROR("[HsRegexAnalyzer] Write failed: {}", path);
        return false;
    }

    LOG_INFO("[HsRegexAnalyzer] Saved database to {} ({} bytes)", path, buf.size());
    return true;
}

bool HsRegexAnalyzer::LoadFromFile(const std::string& path) {
    std::ifstream ifs(path, std::ios::binary | std::ios::ate);
    if (!ifs) {
        LOG_ERROR("[HsRegexAnalyzer] Cannot open file: {}", path);
        return false;
    }

    auto size = ifs.tellg();
    if (size <= 0) {
        LOG_ERROR("[HsRegexAnalyzer] Empty or invalid file: {}", path);
        return false;
    }

    std::vector<char> buf(static_cast<size_t>(size));
    ifs.seekg(0);
    ifs.read(buf.data(), size);

    if (!ifs) {
        LOG_ERROR("[HsRegexAnalyzer] Read failed: {}", path);
        return false;
    }

    return DeserializeDatabase(buf.data(), buf.size());
}

/* ================================================================== */
/*  Internal helpers                                                   */
/* ================================================================== */

bool HsRegexAnalyzer::AllocateScratch() {
    FreeScratch();
    if (hs_alloc_scratch(database_, &scratch_) != HS_SUCCESS) {
        LOG_ERROR("[HsRegexAnalyzer] Failed to allocate scratch");
        scratch_ = nullptr;
        return false;
    }
    return true;
}

void HsRegexAnalyzer::FreeDatabase() {
    FreeScratch();
    if (database_) {
        hs_free_database(database_);
        database_ = nullptr;
    }
    patterns_.clear();
    id_to_index_.clear();
}

void HsRegexAnalyzer::FreeScratch() {
    if (scratch_) {
        hs_free_scratch(scratch_);
        scratch_ = nullptr;
    }
}

}  // namespace akeso::dlp

#endif  /* HAS_HYPERSCAN */
