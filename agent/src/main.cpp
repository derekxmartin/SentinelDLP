/*
 * main.cpp
 * SentinelDLP Agent - Entry point
 *
 * Supports two modes:
 *   1. Windows Service (default): registered with SCM
 *   2. Console mode (--console): for debugging
 *
 * Usage:
 *   sentinel-dlp-agent.exe                    # Run as service
 *   sentinel-dlp-agent.exe --console          # Console mode
 *   sentinel-dlp-agent.exe --config path.yaml # Custom config
 *   sentinel-dlp-agent.exe --install          # Install service
 *   sentinel-dlp-agent.exe --uninstall        # Remove service
 */

#include "sentinel/agent_service.h"
#include "sentinel/config.h"
#include "sentinel/driver_comm.h"
#include "sentinel/grpc_client.h"
#include "sentinel/incident_queue.h"

#include <iostream>
#include <string>
#include <vector>

#ifdef HAS_SPDLOG
#include <spdlog/spdlog.h>
#include <spdlog/sinks/rotating_file_sink.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#endif

namespace sentinel::dlp {

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

    auto logger = std::make_shared<spdlog::logger>("sentinel", sinks.begin(), sinks.end());

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

    /* Configure recovery: restart on first two failures */
    SC_ACTION actions[3] = {
        { SC_ACTION_RESTART, 5000 },   /* First failure: restart after 5s */
        { SC_ACTION_RESTART, 15000 },  /* Second failure: restart after 15s */
        { SC_ACTION_NONE, 0 }         /* Third+: do nothing */
    };
    SERVICE_FAILURE_ACTIONSW failActions = {};
    failActions.dwResetPeriod = 86400;  /* Reset failure count after 24h */
    failActions.cActions = 3;
    failActions.lpsaActions = actions;
    ChangeServiceConfig2W(svc, SERVICE_CONFIG_FAILURE_ACTIONS, &failActions);

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
    bool console        = false;
    bool install        = false;
    bool uninstall      = false;
    bool version        = false;
    std::string config_path;
};

static CmdArgs ParseArgs(int argc, char* argv[]) {
    CmdArgs args;
    for (int i = 1; i < argc; ++i) {
        std::string arg(argv[i]);
        if (arg == "--console" || arg == "-c")          args.console = true;
        else if (arg == "--install")                     args.install = true;
        else if (arg == "--uninstall" || arg == "--remove") args.uninstall = true;
        else if (arg == "--version" || arg == "-v")      args.version = true;
        else if ((arg == "--config" || arg == "-f") && i + 1 < argc)
            args.config_path = argv[++i];
    }
    return args;
}

}  // namespace sentinel::dlp

/* ================================================================== */
/*  main                                                               */
/* ================================================================== */

int main(int argc, char* argv[]) {
    using namespace sentinel::dlp;

    auto args = ParseArgs(argc, argv);

    if (args.version) {
        std::cout << "SentinelDLPAgent v" << kVersion << std::endl;
        return 0;
    }

    if (args.install) {
        return InstallService() ? 0 : 1;
    }

    if (args.uninstall) {
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

        /* Register incident queue (starts before gRPC so queued incidents are ready) */
        auto incident_queue = std::make_shared<IncidentQueue>(
            config.incident_queue.path,
            config.incident_queue.max_entries);
        service.RegisterComponent(incident_queue);

        /* Register driver communication (non-fatal if driver not loaded) */
        auto driver_comm = std::make_shared<DriverComm>();
        service.RegisterComponent(driver_comm);

        /* Register gRPC client component */
        auto grpc_client = std::make_shared<GrpcClient>(config);
        service.RegisterComponent(grpc_client);

        return service.RunConsole(config) ? 0 : 1;
    }

    /* Default: try to run as a Windows service */
    if (!AgentService::RunAsService()) {
        /* Not launched by SCM -show usage */
        std::cout << "SentinelDLPAgent v" << kVersion << "\n\n"
                  << "Usage:\n"
                  << "  sentinel-dlp-agent --console     Run in console mode\n"
                  << "  sentinel-dlp-agent --install     Install as Windows service\n"
                  << "  sentinel-dlp-agent --uninstall   Remove Windows service\n"
                  << "  sentinel-dlp-agent --version     Show version\n"
                  << "  sentinel-dlp-agent --config FILE Specify config file\n"
                  << std::endl;
        return 1;
    }

    return 0;
}
