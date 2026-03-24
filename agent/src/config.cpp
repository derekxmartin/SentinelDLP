/*
 * config.cpp
 * AkesoDLP Agent - Configuration loader implementation
 */

#include "akeso/config.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>

#include <fstream>
#include <sstream>

#ifdef HAS_SPDLOG
#include <spdlog/spdlog.h>
#endif

#include <yaml-cpp/yaml.h>

namespace akeso::dlp {

/* ------------------------------------------------------------------ */
/*  Helper: safely read a YAML node with a default value               */
/* ------------------------------------------------------------------ */

template <typename T>
static T ReadOr(const YAML::Node& node, const std::string& key, const T& default_val) {
    if (node[key] && !node[key].IsNull()) {
        try {
            return node[key].as<T>();
        } catch (const YAML::Exception&) {
            return default_val;
        }
    }
    return default_val;
}

/* ------------------------------------------------------------------ */
/*  Parse individual sections                                          */
/* ------------------------------------------------------------------ */

static void ParseTls(const YAML::Node& node, TlsConfig& cfg) {
    if (!node || !node.IsMap()) return;
    cfg.enabled     = ReadOr<bool>(node, "enabled", cfg.enabled);
    cfg.ca_cert     = ReadOr<std::string>(node, "ca_cert", cfg.ca_cert);
    cfg.client_cert = ReadOr<std::string>(node, "client_cert", cfg.client_cert);
    cfg.client_key  = ReadOr<std::string>(node, "client_key", cfg.client_key);
}

static void ParseServer(const YAML::Node& node, ServerConfig& cfg) {
    if (!node || !node.IsMap()) return;
    cfg.host = ReadOr<std::string>(node, "host", cfg.host);
    cfg.port = static_cast<uint16_t>(ReadOr<int>(node, "port", static_cast<int>(cfg.port)));
    ParseTls(node["tls"], cfg.tls);
}

static void ParseDriver(const YAML::Node& node, DriverConfig& cfg) {
    if (!node || !node.IsMap()) return;
    cfg.port_name           = ReadOr<std::string>(node, "port_name", cfg.port_name);
    cfg.max_connections     = ReadOr<int>(node, "max_connections", cfg.max_connections);
    cfg.message_buffer_size = ReadOr<int>(node, "message_buffer_size", cfg.message_buffer_size);
}

static void ParseDetection(const YAML::Node& node, DetectionConfig& cfg) {
    if (!node || !node.IsMap()) return;
    cfg.pattern_rebuild_interval = ReadOr<int>(node, "pattern_rebuild_interval", cfg.pattern_rebuild_interval);
    cfg.max_scan_size   = ReadOr<int64_t>(node, "max_scan_size", cfg.max_scan_size);
    cfg.ttd_timeout     = ReadOr<int>(node, "ttd_timeout", cfg.ttd_timeout);
    cfg.ttd_fallback    = ReadOr<std::string>(node, "ttd_fallback", cfg.ttd_fallback);
}

static void ParseMonitoring(const YAML::Node& node, MonitoringConfig& cfg) {
    if (!node || !node.IsMap()) return;
    cfg.usb             = ReadOr<bool>(node, "usb", cfg.usb);
    cfg.network_shares  = ReadOr<bool>(node, "network_shares", cfg.network_shares);
    cfg.clipboard       = ReadOr<bool>(node, "clipboard", cfg.clipboard);
    cfg.browser_upload  = ReadOr<bool>(node, "browser_upload", cfg.browser_upload);
    cfg.print_monitor   = ReadOr<bool>(node, "print", cfg.print_monitor);
    cfg.max_scan_size   = ReadOr<int64_t>(node, "max_scan_size", cfg.max_scan_size);
    cfg.browser_upload_cooldown_seconds = ReadOr<int>(node, "browser_upload_cooldown", cfg.browser_upload_cooldown_seconds);
}

static void ParsePolicyCache(const YAML::Node& node, PolicyCacheConfig& cfg) {
    if (!node || !node.IsMap()) return;
    cfg.path = ReadOr<std::string>(node, "path", cfg.path);
}

static void ParseIncidentQueue(const YAML::Node& node, IncidentQueueConfig& cfg) {
    if (!node || !node.IsMap()) return;
    cfg.path        = ReadOr<std::string>(node, "path", cfg.path);
    cfg.max_entries = ReadOr<int>(node, "max_entries", cfg.max_entries);
}

static void ParseRecovery(const YAML::Node& node, RecoveryConfig& cfg) {
    if (!node || !node.IsMap()) return;
    cfg.path = ReadOr<std::string>(node, "path", cfg.path);
}

static void ParseLogging(const YAML::Node& node, LoggingConfig& cfg) {
    if (!node || !node.IsMap()) return;
    cfg.level       = ReadOr<std::string>(node, "level", cfg.level);
    cfg.file        = ReadOr<std::string>(node, "file", cfg.file);
    cfg.max_size_mb = ReadOr<int>(node, "max_size_mb", cfg.max_size_mb);
    cfg.max_files   = ReadOr<int>(node, "max_files", cfg.max_files);
}

static void ParseHeartbeat(const YAML::Node& node, HeartbeatConfig& cfg) {
    if (!node || !node.IsMap()) return;
    cfg.interval_seconds    = ReadOr<int>(node, "interval_seconds", cfg.interval_seconds);
    cfg.backoff_max_seconds = ReadOr<int>(node, "backoff_max_seconds", cfg.backoff_max_seconds);
}

static void ParseDiscover(const YAML::Node& node, DiscoverConfig& cfg) {
    if (!node || !node.IsMap()) return;
    cfg.enabled = ReadOr<bool>(node, "enabled", cfg.enabled);
    cfg.max_file_size = ReadOr<int64_t>(node, "max_file_size", cfg.max_file_size);
    cfg.scan_interval_seconds = ReadOr<int>(node, "scan_interval_seconds", cfg.scan_interval_seconds);

    if (node["target_directories"] && node["target_directories"].IsSequence()) {
        cfg.target_directories.clear();
        for (const auto& item : node["target_directories"])
            cfg.target_directories.push_back(item.as<std::string>());
    }
    if (node["file_extensions"] && node["file_extensions"].IsSequence()) {
        cfg.file_extensions.clear();
        for (const auto& item : node["file_extensions"])
            cfg.file_extensions.push_back(item.as<std::string>());
    }
    if (node["path_exclusions"] && node["path_exclusions"].IsSequence()) {
        cfg.path_exclusions.clear();
        for (const auto& item : node["path_exclusions"])
            cfg.path_exclusions.push_back(item.as<std::string>());
    }
}

static void ParseTamperProtection(const YAML::Node& node, TamperProtectionConfig& cfg) {
    if (!node || !node.IsMap()) return;
    cfg.enabled             = ReadOr<bool>(node, "enabled", cfg.enabled);
    cfg.harden_service_dacl = ReadOr<bool>(node, "harden_service_dacl", cfg.harden_service_dacl);
    cfg.harden_process_dacl = ReadOr<bool>(node, "harden_process_dacl", cfg.harden_process_dacl);
    cfg.uninstall_key_path  = ReadOr<std::string>(node, "uninstall_key_path", cfg.uninstall_key_path);
}

/* ------------------------------------------------------------------ */
/*  Core parse function                                                */
/* ------------------------------------------------------------------ */

static bool ParseYaml(
    const YAML::Node& root,
    AgentConfig& config,
    std::string& error_msg
) {
    try {
        if (!root || !root.IsMap()) {
            error_msg = "YAML root is not a map";
            return false;
        }

        ParseServer(root["server"], config.server);
        ParseDriver(root["driver"], config.driver);
        ParseDetection(root["detection"], config.detection);
        ParseMonitoring(root["monitoring"], config.monitoring);
        ParsePolicyCache(root["policy_cache"], config.policy_cache);
        ParseIncidentQueue(root["incident_queue"], config.incident_queue);
        ParseRecovery(root["recovery"], config.recovery);
        ParseLogging(root["logging"], config.logging);
        ParseHeartbeat(root["heartbeat"], config.heartbeat);
        ParseTamperProtection(root["tamper_protection"], config.tamper_protection);
        ParseDiscover(root["discover"], config.discover);

        return true;
    } catch (const YAML::Exception& e) {
        error_msg = std::string("YAML parse error: ") + e.what();
        return false;
    }
}

/* ------------------------------------------------------------------ */
/*  Public API                                                         */
/* ------------------------------------------------------------------ */

bool ConfigLoader::Load(
    const std::filesystem::path& path,
    AgentConfig& config,
    std::string& error_msg
) {
    if (!std::filesystem::exists(path)) {
        error_msg = "Config file not found: " + path.string();
        return false;
    }

    try {
        YAML::Node root = YAML::LoadFile(path.string());
        return ParseYaml(root, config, error_msg);
    } catch (const YAML::Exception& e) {
        error_msg = std::string("Failed to load YAML: ") + e.what();
        return false;
    } catch (const std::exception& e) {
        error_msg = std::string("Unexpected error: ") + e.what();
        return false;
    }
}

bool ConfigLoader::LoadFromString(
    const std::string& yaml_content,
    AgentConfig& config,
    std::string& error_msg
) {
    try {
        YAML::Node root = YAML::Load(yaml_content);
        return ParseYaml(root, config, error_msg);
    } catch (const YAML::Exception& e) {
        error_msg = std::string("Failed to parse YAML: ") + e.what();
        return false;
    }
}

std::filesystem::path ConfigLoader::FindConfigFile(
    const std::string& explicit_path
) {
    /* 1. Explicit path */
    if (!explicit_path.empty()) {
        std::filesystem::path p(explicit_path);
        if (std::filesystem::exists(p)) return p;
    }

    /* 2. Same directory as executable */
    {
        wchar_t exe_path[MAX_PATH] = { 0 };
        if (GetModuleFileNameW(NULL, exe_path, MAX_PATH) > 0) {
            auto dir = std::filesystem::path(exe_path).parent_path();
            auto p = dir / "config.yaml";
            if (std::filesystem::exists(p)) return p;
        }
    }

    /* 3. Standard install location */
    {
        std::filesystem::path p("C:\\AkesoDLP\\config.yaml");
        if (std::filesystem::exists(p)) return p;
    }

    /* 4. ProgramData */
    {
        const char* pd = std::getenv("PROGRAMDATA");
        if (pd) {
            auto p = std::filesystem::path(pd) / "AkesoDLP" / "config.yaml";
            if (std::filesystem::exists(p)) return p;
        }
    }

    return {};  /* Not found */
}

}  // namespace akeso::dlp
