/*
 * test_config.cpp
 * SentinelDLP Agent - Config loader tests
 */

#include <fstream>
#include <gtest/gtest.h>
#include "sentinel/config.h"

using namespace sentinel::dlp;

/* ------------------------------------------------------------------ */
/*  Default values                                                     */
/* ------------------------------------------------------------------ */

TEST(ConfigTest, DefaultValues) {
    AgentConfig config;

    EXPECT_EQ(config.server.host, "localhost");
    EXPECT_EQ(config.server.port, 50051);
    EXPECT_TRUE(config.server.tls.enabled);
    EXPECT_EQ(config.detection.ttd_timeout, 30);
    EXPECT_EQ(config.detection.ttd_fallback, "log");
    EXPECT_EQ(config.detection.max_scan_size, 52428800);
    EXPECT_TRUE(config.monitoring.usb);
    EXPECT_TRUE(config.monitoring.network_shares);
    EXPECT_TRUE(config.monitoring.clipboard);
    EXPECT_FALSE(config.monitoring.print_monitor);
    EXPECT_EQ(config.heartbeat.interval_seconds, 60);
    EXPECT_EQ(config.heartbeat.backoff_max_seconds, 300);
    EXPECT_EQ(config.incident_queue.max_entries, 10000);
    EXPECT_EQ(config.logging.level, "info");
    EXPECT_EQ(config.logging.max_files, 5);
}

/* ------------------------------------------------------------------ */
/*  Full config parse                                                  */
/* ------------------------------------------------------------------ */

TEST(ConfigTest, LoadFromString_FullConfig) {
    const std::string yaml = R"(
server:
  host: "10.0.0.1"
  port: 9090
  tls:
    enabled: false
    ca_cert: "/etc/ca.pem"
    client_cert: "/etc/client.pem"
    client_key: "/etc/client-key.pem"

driver:
  port_name: "\\CustomPort"
  max_connections: 8
  message_buffer_size: 131072

detection:
  pattern_rebuild_interval: 600
  max_scan_size: 104857600
  ttd_timeout: 15
  ttd_fallback: "block"

monitoring:
  usb: false
  network_shares: true
  clipboard: false
  browser_upload: true
  print: true

policy_cache:
  path: "D:\\DLP\\cache.db"

incident_queue:
  path: "D:\\DLP\\queue.mmap"
  max_entries: 500

recovery:
  path: "D:\\DLP\\Recovery"

logging:
  level: "debug"
  file: "D:\\DLP\\logs\\agent.log"
  max_size_mb: 100
  max_files: 10

heartbeat:
  interval_seconds: 30
  backoff_max_seconds: 600
)";

    AgentConfig config;
    std::string error;
    ASSERT_TRUE(ConfigLoader::LoadFromString(yaml, config, error)) << error;

    /* Server */
    EXPECT_EQ(config.server.host, "10.0.0.1");
    EXPECT_EQ(config.server.port, 9090);
    EXPECT_FALSE(config.server.tls.enabled);
    EXPECT_EQ(config.server.tls.ca_cert, "/etc/ca.pem");

    /* Driver */
    EXPECT_EQ(config.driver.port_name, "\\CustomPort");
    EXPECT_EQ(config.driver.max_connections, 8);
    EXPECT_EQ(config.driver.message_buffer_size, 131072);

    /* Detection */
    EXPECT_EQ(config.detection.pattern_rebuild_interval, 600);
    EXPECT_EQ(config.detection.max_scan_size, 104857600);
    EXPECT_EQ(config.detection.ttd_timeout, 15);
    EXPECT_EQ(config.detection.ttd_fallback, "block");

    /* Monitoring */
    EXPECT_FALSE(config.monitoring.usb);
    EXPECT_TRUE(config.monitoring.network_shares);
    EXPECT_FALSE(config.monitoring.clipboard);
    EXPECT_TRUE(config.monitoring.browser_upload);
    EXPECT_TRUE(config.monitoring.print_monitor);

    /* Policy cache */
    EXPECT_EQ(config.policy_cache.path, "D:\\DLP\\cache.db");

    /* Incident queue */
    EXPECT_EQ(config.incident_queue.path, "D:\\DLP\\queue.mmap");
    EXPECT_EQ(config.incident_queue.max_entries, 500);

    /* Recovery */
    EXPECT_EQ(config.recovery.path, "D:\\DLP\\Recovery");

    /* Logging */
    EXPECT_EQ(config.logging.level, "debug");
    EXPECT_EQ(config.logging.file, "D:\\DLP\\logs\\agent.log");
    EXPECT_EQ(config.logging.max_size_mb, 100);
    EXPECT_EQ(config.logging.max_files, 10);

    /* Heartbeat */
    EXPECT_EQ(config.heartbeat.interval_seconds, 30);
    EXPECT_EQ(config.heartbeat.backoff_max_seconds, 600);
}

/* ------------------------------------------------------------------ */
/*  Partial config (missing sections use defaults)                     */
/* ------------------------------------------------------------------ */

TEST(ConfigTest, LoadFromString_PartialConfig) {
    const std::string yaml = R"(
server:
  host: "myserver.local"
  port: 50051

logging:
  level: "warn"
)";

    AgentConfig config;
    std::string error;
    ASSERT_TRUE(ConfigLoader::LoadFromString(yaml, config, error)) << error;

    /* Specified values */
    EXPECT_EQ(config.server.host, "myserver.local");
    EXPECT_EQ(config.logging.level, "warn");

    /* Defaults for unspecified sections */
    EXPECT_TRUE(config.server.tls.enabled);
    EXPECT_EQ(config.detection.ttd_timeout, 30);
    EXPECT_TRUE(config.monitoring.usb);
    EXPECT_EQ(config.heartbeat.interval_seconds, 60);
}

/* ------------------------------------------------------------------ */
/*  Empty config (all defaults)                                        */
/* ------------------------------------------------------------------ */

TEST(ConfigTest, LoadFromString_EmptyConfig) {
    const std::string yaml = "{}";

    AgentConfig config;
    std::string error;
    ASSERT_TRUE(ConfigLoader::LoadFromString(yaml, config, error)) << error;

    /* All defaults */
    EXPECT_EQ(config.server.host, "localhost");
    EXPECT_EQ(config.server.port, 50051);
    EXPECT_EQ(config.detection.ttd_fallback, "log");
}

/* ------------------------------------------------------------------ */
/*  Invalid YAML                                                       */
/* ------------------------------------------------------------------ */

TEST(ConfigTest, LoadFromString_InvalidYaml) {
    const std::string yaml = "{{{{invalid yaml garbage";

    AgentConfig config;
    std::string error;
    EXPECT_FALSE(ConfigLoader::LoadFromString(yaml, config, error));
    EXPECT_FALSE(error.empty());
}

/* ------------------------------------------------------------------ */
/*  Non-map root                                                       */
/* ------------------------------------------------------------------ */

TEST(ConfigTest, LoadFromString_NonMapRoot) {
    const std::string yaml = "- item1\n- item2\n";

    AgentConfig config;
    std::string error;
    EXPECT_FALSE(ConfigLoader::LoadFromString(yaml, config, error));
    EXPECT_NE(error.find("not a map"), std::string::npos);
}

/* ------------------------------------------------------------------ */
/*  Wrong types use defaults (resilient parsing)                       */
/* ------------------------------------------------------------------ */

TEST(ConfigTest, LoadFromString_WrongTypesUseDefaults) {
    const std::string yaml = R"(
server:
  host: 12345
  port: "not_a_number"

heartbeat:
  interval_seconds: "sixty"
)";

    AgentConfig config;
    std::string error;
    ASSERT_TRUE(ConfigLoader::LoadFromString(yaml, config, error)) << error;

    /* Wrong types fall back to defaults */
    EXPECT_EQ(config.server.port, 50051);       /* "not_a_number" -> default */
    EXPECT_EQ(config.heartbeat.interval_seconds, 60); /* "sixty" -> default */
}

/* ------------------------------------------------------------------ */
/*  File not found                                                     */
/* ------------------------------------------------------------------ */

TEST(ConfigTest, Load_FileNotFound) {
    AgentConfig config;
    std::string error;
    EXPECT_FALSE(ConfigLoader::Load("nonexistent_config.yaml", config, error));
    EXPECT_NE(error.find("not found"), std::string::npos);
}

/* ------------------------------------------------------------------ */
/*  Load from actual file                                              */
/* ------------------------------------------------------------------ */

TEST(ConfigTest, Load_FromTempFile) {
    /* Write a temp YAML file */
    auto temp = std::filesystem::temp_directory_path() / "sentinel_test_config.yaml";
    {
        std::ofstream f(temp);
        f << "server:\n  host: \"from-file\"\n  port: 12345\n";
    }

    AgentConfig config;
    std::string error;
    ASSERT_TRUE(ConfigLoader::Load(temp, config, error)) << error;

    EXPECT_EQ(config.server.host, "from-file");
    EXPECT_EQ(config.server.port, 12345);

    /* Cleanup */
    std::filesystem::remove(temp);
}

/* ------------------------------------------------------------------ */
/*  FindConfigFile with explicit path                                  */
/* ------------------------------------------------------------------ */

TEST(ConfigTest, FindConfigFile_ExplicitPath) {
    auto temp = std::filesystem::temp_directory_path() / "sentinel_find_test.yaml";
    {
        std::ofstream f(temp);
        f << "server:\n  host: test\n";
    }

    auto found = ConfigLoader::FindConfigFile(temp.string());
    EXPECT_EQ(found, temp);

    std::filesystem::remove(temp);
}

TEST(ConfigTest, FindConfigFile_ExplicitPathNotFound) {
    auto found = ConfigLoader::FindConfigFile("definitely_not_a_real_file.yaml");
    /* Should fall through to other search paths; may or may not find anything */
    /* Just verify it doesn't crash */
    (void)found;
}
