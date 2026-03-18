/*
 * config.h
 * SentinelDLP Agent - Configuration
 *
 * Loads and validates agent configuration from YAML files.
 * Provides typed access to all configuration sections.
 */

#pragma once

#include <cstdint>
#include <string>
#include <filesystem>

namespace sentinel::dlp {

/* ------------------------------------------------------------------ */
/*  Configuration structures                                           */
/* ------------------------------------------------------------------ */

struct TlsConfig {
    bool        enabled         = true;
    std::string ca_cert         = "certs/ca.pem";
    std::string client_cert     = "certs/agent.pem";
    std::string client_key      = "certs/agent-key.pem";
};

struct ServerConfig {
    std::string host            = "localhost";
    uint16_t    port            = 50051;
    TlsConfig   tls;
};

struct DriverConfig {
    std::string port_name       = "\\\\SentinelDLPPort";
    int         max_connections  = 4;
    int         message_buffer_size = 65536;
};

struct DetectionConfig {
    int         pattern_rebuild_interval = 300;
    int64_t     max_scan_size   = 52428800;  /* 50 MB */
    int         ttd_timeout     = 30;
    std::string ttd_fallback    = "log";     /* allow | block | log */
};

struct MonitoringConfig {
    bool usb                    = true;
    bool network_shares         = true;
    bool clipboard              = true;
    bool browser_upload         = true;
    bool print_monitor          = false;
};

struct PolicyCacheConfig {
    std::string path            = "C:\\SentinelDLP\\cache\\policies.db";
};

struct IncidentQueueConfig {
    std::string path            = "C:\\SentinelDLP\\queue\\incidents.mmap";
    int         max_entries     = 1000;
};

struct RecoveryConfig {
    std::string path            = "C:\\SentinelDLP\\Recovery";
};

struct LoggingConfig {
    std::string level           = "info";
    std::string file            = "C:\\SentinelDLP\\logs\\agent.log";
    int         max_size_mb     = 50;
    int         max_files       = 5;
};

struct HeartbeatConfig {
    int         interval_seconds    = 60;
    int         backoff_max_seconds = 300;
};

/* ------------------------------------------------------------------ */
/*  Top-level agent configuration                                      */
/* ------------------------------------------------------------------ */

struct AgentConfig {
    ServerConfig        server;
    DriverConfig        driver;
    DetectionConfig     detection;
    MonitoringConfig    monitoring;
    PolicyCacheConfig   policy_cache;
    IncidentQueueConfig incident_queue;
    RecoveryConfig      recovery;
    LoggingConfig       logging;
    HeartbeatConfig     heartbeat;
};

/* ------------------------------------------------------------------ */
/*  Configuration loader                                               */
/* ------------------------------------------------------------------ */

class ConfigLoader {
public:
    /*
     * Load configuration from a YAML file.
     * Returns true on success. On failure, returns false and
     * populates error_msg with the reason.
     */
    static bool Load(
        const std::filesystem::path& path,
        AgentConfig& config,
        std::string& error_msg
    );

    /*
     * Load configuration from a YAML string (for testing).
     */
    static bool LoadFromString(
        const std::string& yaml_content,
        AgentConfig& config,
        std::string& error_msg
    );

    /*
     * Get the default configuration search paths.
     * Searches in order:
     *   1. Explicit path (if provided)
     *   2. Same directory as executable
     *   3. C:\SentinelDLP\config.yaml
     *   4. %PROGRAMDATA%\SentinelDLP\config.yaml
     */
    static std::filesystem::path FindConfigFile(
        const std::string& explicit_path = ""
    );
};

}  // namespace sentinel::dlp
