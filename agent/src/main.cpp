/*
 * main.cpp
 * AkesoDLP Agent - Entry point
 *
 * Supports two modes:
 *   1. Windows Service (default): registered with SCM
 *   2. Console mode (--console): for debugging
 *
 * Usage:
 *   akeso-dlp-agent.exe                    # Run as service
 *   akeso-dlp-agent.exe --console          # Console mode
 *   akeso-dlp-agent.exe --config path.yaml # Custom config
 *   akeso-dlp-agent.exe --install          # Install service
 *   akeso-dlp-agent.exe --uninstall        # Remove service
 */

#include "akeso/agent_service.h"
#include "akeso/browser_upload_monitor.h"
#include "akeso/clipboard_monitor.h"
#include "akeso/config.h"
#include "akeso/detection/pipeline.h"
#include "akeso/detection/policy_evaluator.h"
#include "akeso/driver_comm.h"
#include "akeso/grpc_client.h"
#include "akeso/incident_queue.h"
#include "akeso/policy_cache.h"
#include "akeso/discover_scanner.h"
#include "akeso/tamper_protection.h"

#include <iostream>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#ifdef HAS_SPDLOG
#include <spdlog/spdlog.h>
#include <spdlog/sinks/rotating_file_sink.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#endif

namespace akeso::dlp {

constexpr const char* kVersion = "0.1.0";

/* ------------------------------------------------------------------ */
/*  Logging setup                                                      */
/* ------------------------------------------------------------------ */

static void InitializeLogging(const LoggingConfig& cfg, bool console_mode) {
#ifdef HAS_SPDLOG
    std::vector<spdlog::sink_ptr> sinks;

    if (console_mode) {
        sinks.push_back(std::make_shared<spdlog::sinks::stdout_color_sink_mt>());
    }

    /* Rotating file sink */
    try {
        auto file_sink = std::make_shared<spdlog::sinks::rotating_file_sink_mt>(
            cfg.file,
            static_cast<size_t>(cfg.max_size_mb) * 1024 * 1024,
            cfg.max_files
        );
        sinks.push_back(file_sink);
    } catch (const spdlog::spdlog_ex& ex) {
        if (console_mode) {
            std::cerr << "Warning: Could not open log file: " << ex.what()
                      << std::endl;
        }
    }

    auto logger = std::make_shared<spdlog::logger>("akeso", sinks.begin(), sinks.end());

    /* Set log level */
    if (cfg.level == "trace")       logger->set_level(spdlog::level::trace);
    else if (cfg.level == "debug")  logger->set_level(spdlog::level::debug);
    else if (cfg.level == "info")   logger->set_level(spdlog::level::info);
    else if (cfg.level == "warn")   logger->set_level(spdlog::level::warn);
    else if (cfg.level == "error")  logger->set_level(spdlog::level::err);
    else                            logger->set_level(spdlog::level::info);

    logger->set_pattern("[%Y-%m-%d %H:%M:%S.%e] [%^%l%$] [%t] %v");
    spdlog::set_default_logger(logger);
    spdlog::flush_every(std::chrono::seconds(3));
#else
    (void)cfg;
    (void)console_mode;
#endif
}

/* ------------------------------------------------------------------ */
/*  Service install / uninstall                                        */
/* ------------------------------------------------------------------ */

static bool InstallService() {
    wchar_t path[MAX_PATH];
    if (!GetModuleFileNameW(NULL, path, MAX_PATH)) {
        std::cerr << "GetModuleFileName failed: " << GetLastError() << std::endl;
        return false;
    }

    SC_HANDLE scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
    if (!scm) {
        std::cerr << "OpenSCManager failed: " << GetLastError()
                  << " (run as Administrator)" << std::endl;
        return false;
    }

    SC_HANDLE svc = CreateServiceW(
        scm,
        AgentService::kServiceName,
        AgentService::kDisplayName,
        SERVICE_ALL_ACCESS,
        SERVICE_WIN32_OWN_PROCESS,
        SERVICE_AUTO_START,
        SERVICE_ERROR_NORMAL,
        path,
        NULL, NULL, NULL, NULL, NULL
    );

    if (!svc) {
        DWORD err = GetLastError();
        if (err == ERROR_SERVICE_EXISTS) {
            std::cout << "Service already installed." << std::endl;
        } else {
            std::cerr << "CreateService failed: " << err << std::endl;
        }
        CloseServiceHandle(scm);
        return err == ERROR_SERVICE_EXISTS;
    }

    /* Set description */
    SERVICE_DESCRIPTIONW desc;
    desc.lpDescription = const_cast<LPWSTR>(AgentService::kDescription);
    ChangeServiceConfig2W(svc, SERVICE_CONFIG_DESCRIPTION, &desc);

    /* Configure recovery: restart on all failures */
    SC_ACTION actions[3] = {
        { SC_ACTION_RESTART, 5000 },   /* First failure: restart after 5s */
        { SC_ACTION_RESTART, 15000 },  /* Second failure: restart after 15s */
        { SC_ACTION_RESTART, 30000 }   /* Third+: restart after 30s */
    };
    SERVICE_FAILURE_ACTIONSW failActions = {};
    failActions.dwResetPeriod = 86400;  /* Reset failure count after 24h */
    failActions.cActions = 3;
    failActions.lpsaActions = actions;
    ChangeServiceConfig2W(svc, SERVICE_CONFIG_FAILURE_ACTIONS, &failActions);

    /* Ensure recovery fires even on non-crash exits with error code */
    SERVICE_FAILURE_ACTIONS_FLAG flag = {};
    flag.fFailureActionsOnNonCrashFailures = TRUE;
    ChangeServiceConfig2W(svc, SERVICE_CONFIG_FAILURE_ACTIONS_FLAG, &flag);

    CloseServiceHandle(svc);
    CloseServiceHandle(scm);

    std::cout << "Service installed successfully." << std::endl;
    return true;
}

static bool UninstallService() {
    SC_HANDLE scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (!scm) {
        std::cerr << "OpenSCManager failed: " << GetLastError() << std::endl;
        return false;
    }

    SC_HANDLE svc = OpenServiceW(scm, AgentService::kServiceName,
                                  SERVICE_STOP | DELETE);
    if (!svc) {
        std::cerr << "OpenService failed: " << GetLastError() << std::endl;
        CloseServiceHandle(scm);
        return false;
    }

    /* Stop the service if running */
    SERVICE_STATUS status;
    ControlService(svc, SERVICE_CONTROL_STOP, &status);
    Sleep(1000);

    if (!DeleteService(svc)) {
        std::cerr << "DeleteService failed: " << GetLastError() << std::endl;
        CloseServiceHandle(svc);
        CloseServiceHandle(scm);
        return false;
    }

    CloseServiceHandle(svc);
    CloseServiceHandle(scm);

    std::cout << "Service uninstalled successfully." << std::endl;
    return true;
}

/* ------------------------------------------------------------------ */
/*  Command-line parsing                                               */
/* ------------------------------------------------------------------ */

struct CmdArgs {
    bool console              = false;
    bool install              = false;
    bool uninstall            = false;
    bool version              = false;
    bool test_policy          = false;
    bool set_uninstall_pw     = false;
    std::string config_path;
    std::string uninstall_password;
    std::string new_uninstall_password;
};

static CmdArgs ParseArgs(int argc, char* argv[]) {
    CmdArgs args;
    for (int i = 1; i < argc; ++i) {
        std::string arg(argv[i]);
        if (arg == "--console" || arg == "-c")          args.console = true;
        else if (arg == "--install")                     args.install = true;
        else if (arg == "--uninstall" || arg == "--remove") args.uninstall = true;
        else if (arg == "--version" || arg == "-v")      args.version = true;
        else if (arg == "--test-policy")                 args.test_policy = true;
        else if (arg == "--set-uninstall-password" && i + 1 < argc)
        {
            args.set_uninstall_pw = true;
            args.new_uninstall_password = argv[++i];
        }
        else if (arg == "--uninstall-password" && i + 1 < argc)
            args.uninstall_password = argv[++i];
        else if ((arg == "--config" || arg == "-f") && i + 1 < argc)
            args.config_path = argv[++i];
    }
    return args;
}

/*
 * Create a demo policy for testing the block response flow.
 * Matches SSN patterns (XXX-XX-XXXX) and credit card numbers
 * (4XXX-XXXX-XXXX-XXXX) and blocks the file write.
 */
static std::vector<Policy> CreateTestPolicies() {
    std::vector<Policy> policies;

    /* Policy 1: SSN Detection — Block */
    {
        Policy p;
        p.id = 1;
        p.name = "PII Protection - SSN";
        p.active = true;
        p.default_severity = Severity::High;
        p.response = ResponseAction::Block;

        DetectionRule rule;
        rule.name = "SSN Pattern";
        RuleCondition cond;
        cond.type = ConditionType::Regex;
        cond.pattern_label = "\\b\\d{3}-\\d{2}-\\d{4}\\b";
        cond.match_count_min = 1;
        rule.conditions.push_back(cond);
        p.detection_rules.push_back(rule);

        policies.push_back(p);
    }

    /* Policy 2: Credit Card Detection — Block */
    {
        Policy p;
        p.id = 2;
        p.name = "PCI-DSS - Credit Cards";
        p.active = true;
        p.default_severity = Severity::Critical;
        p.response = ResponseAction::Block;

        DetectionRule rule;
        rule.name = "Credit Card Pattern";
        RuleCondition cond;
        cond.type = ConditionType::Regex;
        cond.pattern_label = "\\b4\\d{3}[- ]?\\d{4}[- ]?\\d{4}[- ]?\\d{4}\\b";
        cond.match_count_min = 1;
        rule.conditions.push_back(cond);
        p.detection_rules.push_back(rule);

        policies.push_back(p);
    }

    /* Policy 3: Confidential Document — UserCancel (requires justification) */
    {
        Policy p;
        p.id = 3;
        p.name = "Confidential Document Control";
        p.active = true;
        p.default_severity = Severity::Medium;
        p.response = ResponseAction::UserCancel;

        DetectionRule rule;
        rule.name = "Confidential Marker";
        RuleCondition cond;
        cond.type = ConditionType::Keyword;
        cond.pattern_label = "CONFIDENTIAL";
        cond.match_count_min = 1;
        rule.conditions.push_back(cond);
        p.detection_rules.push_back(rule);

        policies.push_back(p);
    }

    /* Policy 4: Internal Only — Notify */
    {
        Policy p;
        p.id = 4;
        p.name = "Internal Document Tracking";
        p.active = true;
        p.default_severity = Severity::Low;
        p.response = ResponseAction::Notify;

        DetectionRule rule;
        rule.name = "Internal Only Marker";
        RuleCondition cond;
        cond.type = ConditionType::Keyword;
        cond.pattern_label = "INTERNAL ONLY";
        cond.match_count_min = 1;
        rule.conditions.push_back(cond);
        p.detection_rules.push_back(rule);

        policies.push_back(p);
    }

    return policies;
}

}  // namespace akeso::dlp

/* ================================================================== */
/*  main                                                               */
/* ================================================================== */

int main(int argc, char* argv[]) {
    using namespace akeso::dlp;

    auto args = ParseArgs(argc, argv);

    if (args.version) {
        std::cout << "AkesoDLPAgent v" << kVersion << std::endl;
        return 0;
    }

    if (args.install) {
        return InstallService() ? 0 : 1;
    }

    /* Set uninstall password */
    if (args.set_uninstall_pw) {
        AgentConfig cfg;
        auto cfg_path = ConfigLoader::FindConfigFile(args.config_path);
        if (!cfg_path.empty()) {
            std::string err;
            ConfigLoader::Load(cfg_path, cfg, err);
        }
        if (TamperProtection::SetUninstallPassword(
                args.new_uninstall_password,
                cfg.tamper_protection.uninstall_key_path)) {
            std::cout << "Uninstall password set successfully." << std::endl;
            return 0;
        }
        std::cerr << "Failed to set uninstall password." << std::endl;
        return 1;
    }

    if (args.uninstall) {
        /* Verify uninstall password if configured */
        AgentConfig cfg;
        auto cfg_path = ConfigLoader::FindConfigFile(args.config_path);
        if (!cfg_path.empty()) {
            std::string err;
            ConfigLoader::Load(cfg_path, cfg, err);
        }
        if (TamperProtection::HasUninstallPassword(
                cfg.tamper_protection.uninstall_key_path)) {
            if (args.uninstall_password.empty()) {
                std::cerr << "Uninstall password required. Use --uninstall-password <pw>"
                          << std::endl;
                return 1;
            }
            if (!TamperProtection::VerifyUninstallPassword(
                    args.uninstall_password,
                    cfg.tamper_protection.uninstall_key_path)) {
                std::cerr << "Incorrect uninstall password." << std::endl;
                return 1;
            }
        }
        return UninstallService() ? 0 : 1;
    }

    if (args.console) {
        /* Console mode: load config and run interactively */
        AgentConfig config;
        auto config_path = ConfigLoader::FindConfigFile(args.config_path);

        if (!config_path.empty()) {
            std::string error;
            if (!ConfigLoader::Load(config_path, config, error)) {
                std::cerr << "Warning: " << error << " (using defaults)" << std::endl;
            } else {
                std::cout << "Config loaded: " << config_path << std::endl;
            }
        } else {
            std::cout << "No config file found, using defaults." << std::endl;
        }

        InitializeLogging(config.logging, true);

        AgentService service;

        /* Register tamper protection FIRST (hardens DACLs before anything else) */
        auto tamper = std::make_shared<TamperProtection>(config.tamper_protection);
        service.RegisterComponent(tamper);

        /* Register incident queue (starts before gRPC so queued incidents are ready) */
        auto incident_queue = std::make_shared<IncidentQueue>(
            config.incident_queue.path,
            config.incident_queue.max_entries);
        service.RegisterComponent(incident_queue);

        /* Register gRPC client component */
        auto grpc_client = std::make_shared<GrpcClient>(config);
        service.RegisterComponent(grpc_client);

        /* Register policy cache */
        auto policy_cache = std::make_shared<PolicyCache>(config);
        service.RegisterComponent(policy_cache);

        /* Register driver communication (connects to minifilter) */
        auto driver_comm = std::make_shared<DriverComm>(config.driver);
        service.RegisterComponent(driver_comm);

        /* Wire driver health into heartbeat */
        grpc_client->SetDriverStatusCallback([driver_comm]() {
            return driver_comm->IsHealthy();
        });

        /* Register clipboard monitor (P4-T10) */
        auto clipboard_monitor = std::make_shared<ClipboardMonitor>(
            config.monitoring.clipboard);
        service.RegisterComponent(clipboard_monitor);

        /* Register browser upload monitor (P4-T11) */
        auto browser_monitor = std::make_shared<BrowserUploadMonitor>(
            config.monitoring.browser_upload,
            config.monitoring.max_scan_size,
            config.monitoring.browser_upload_cooldown_seconds);
        service.RegisterComponent(browser_monitor);

        /* Register discover scanner (P7-T1) */
        auto discover_scanner = std::make_shared<DiscoverScanner>(config.discover);
        service.RegisterComponent(discover_scanner);

        /* Register detection pipeline (wires driver + clipboard + browser + discover -> detection -> verdict) */
        auto pipeline = std::make_shared<DetectionPipeline>(
            config, driver_comm, grpc_client, incident_queue, policy_cache,
            clipboard_monitor, browser_monitor, discover_scanner);
        service.RegisterComponent(pipeline);

        /* Wire server command handling (P8-T1) */
        grpc_client->SetCommandCallback(
            [discover_scanner, grpc_client](const akesodlp::AgentCommand& cmd) {
                if (cmd.command_type() == "run_discover") {
                    const auto& params = cmd.parameters();
                    auto it_id = params.find("discover_id");
                    auto it_path = params.find("scan_path");
                    if (it_id == params.end() || it_path == params.end()) {
                        spdlog::warn("run_discover command missing discover_id or scan_path");
                        return;
                    }

                    DiscoverScanner::RemoteScanParams rp;
                    rp.discover_id = it_id->second;
                    rp.scan_path = it_path->second;

                    /* Parse optional comma-separated extensions */
                    auto it_ext = params.find("file_extensions");
                    if (it_ext != params.end() && !it_ext->second.empty()) {
                        std::istringstream ss(it_ext->second);
                        std::string ext;
                        while (std::getline(ss, ext, ',')) {
                            if (!ext.empty()) rp.file_extensions.push_back(ext);
                        }
                    }

                    /* Run scan in background thread to avoid blocking heartbeat */
                    std::thread([discover_scanner, grpc_client, rp]() {
                        auto stats = discover_scanner->RunRemoteScan(rp);

                        /* Report results back to server */
                        akesodlp::ReportDiscoverResultsRequest req;
                        req.set_agent_id(grpc_client->GetAgentId());
                        req.set_discover_id(rp.discover_id);
                        req.set_files_examined(stats.files_examined);
                        req.set_files_scanned(stats.files_scanned);
                        req.set_duration_ms(0);  /* TODO: track actual ms */
                        grpc_client->ReportDiscoverResults(req);
                    }).detach();
                }
            });

        /* Seed test policies if requested */
        if (args.test_policy) {
            auto test_policies = CreateTestPolicies();
            pipeline->UpdatePolicies(test_policies);
            spdlog::info("Loaded {} test policies (--test-policy mode)",
                         test_policies.size());
        }

        return service.RunConsole(config) ? 0 : 1;
    }

    /* Default: try to run as a Windows service */
    if (!AgentService::RunAsService()) {
        /* Not launched by SCM — show usage */
        std::cout << "AkesoDLPAgent v" << kVersion << "\n\n"
                  << "Usage:\n"
                  << "  akeso-dlp-agent --console              Run in console mode\n"
                  << "  akeso-dlp-agent --install              Install as Windows service\n"
                  << "  akeso-dlp-agent --uninstall            Remove Windows service\n"
                  << "  akeso-dlp-agent --version              Show version\n"
                  << "  akeso-dlp-agent --config FILE          Specify config file\n"
                  << "  akeso-dlp-agent --set-uninstall-password PW  Set uninstall password\n"
                  << "  akeso-dlp-agent --uninstall --uninstall-password PW  Uninstall with password\n"
                  << std::endl;
        return 1;
    }

    return 0;
}
