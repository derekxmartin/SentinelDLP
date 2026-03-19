/*
 * agent_service.cpp
 * AkesoDLP Agent - Windows Service implementation
 *
 * Startup sequence:
 *   1. Load config
 *   2. Load policy cache (if exists → enforce, else → log-only)
 *   3. Connect to minifilter driver
 *   4. Initialize detection engine
 *   5. Connect to server (gRPC)
 *   6. Start heartbeat
 *
 * Graceful shutdown reverses the order.
 */

#include "akeso/agent_service.h"

#include <iostream>

#ifdef HAS_SPDLOG
#include <spdlog/spdlog.h>
#define LOG_INFO(...)    spdlog::info(__VA_ARGS__)
#define LOG_WARN(...)    spdlog::warn(__VA_ARGS__)
#define LOG_ERROR(...)   spdlog::error(__VA_ARGS__)
#else
#include <iostream>
#define LOG_INFO(...)    (void)0
#define LOG_WARN(...)    (void)0
#define LOG_ERROR(...)   (void)0
#endif

namespace akeso::dlp {

/* Singleton instance for SCM callbacks */
AgentService* AgentService::instance_ = nullptr;

/* ================================================================== */
/*  Constructor / Destructor                                           */
/* ================================================================== */

AgentService::AgentService() {
    instance_ = this;
    stop_event_ = CreateEventW(NULL, TRUE, FALSE, NULL);
}

AgentService::~AgentService() {
    if (stop_event_) {
        CloseHandle(stop_event_);
        stop_event_ = nullptr;
    }
    instance_ = nullptr;
}

/* ================================================================== */
/*  Run as Windows Service                                             */
/* ================================================================== */

bool AgentService::RunAsService() {
    SERVICE_TABLE_ENTRYW serviceTable[] = {
        { const_cast<LPWSTR>(kServiceName), ServiceMain },
        { NULL, NULL }
    };

    if (!StartServiceCtrlDispatcherW(serviceTable)) {
        DWORD err = GetLastError();
        if (err == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT) {
            /* Not running as a service — caller should use RunConsole */
            return false;
        }
        LOG_ERROR("StartServiceCtrlDispatcher failed: {}", err);
        return false;
    }

    return true;
}

/* ================================================================== */
/*  SCM: ServiceMain                                                   */
/* ================================================================== */

void WINAPI AgentService::ServiceMain(
    [[maybe_unused]] DWORD argc,
    [[maybe_unused]] LPWSTR* argv
) {
    auto* self = instance_;
    if (!self) return;

    /* Register the control handler */
    self->status_handle_ = RegisterServiceCtrlHandlerW(
        kServiceName,
        ServiceCtrlHandler
    );

    if (!self->status_handle_) {
        LOG_ERROR("RegisterServiceCtrlHandler failed: {}", GetLastError());
        return;
    }

    /* Report SERVICE_START_PENDING */
    self->ReportServiceStatus(SERVICE_START_PENDING, 0, 3000);
    self->state_ = AgentState::Starting;

    /* Load configuration */
    auto config_path = ConfigLoader::FindConfigFile();
    AgentConfig config;

    if (!config_path.empty()) {
        std::string error;
        if (!ConfigLoader::Load(config_path, config, error)) {
            LOG_WARN("Config load failed ({}), using defaults", error);
        }
    } else {
        LOG_WARN("No config file found, using defaults");
    }

    /* Initialize */
    if (!self->Initialize(config)) {
        self->ReportServiceStatus(SERVICE_STOPPED, ERROR_SERVICE_SPECIFIC_ERROR, 0);
        return;
    }

    /* Start components */
    if (!self->StartComponents()) {
        LOG_ERROR("Failed to start one or more components");
        self->StopComponents();
        self->ReportServiceStatus(SERVICE_STOPPED, ERROR_SERVICE_SPECIFIC_ERROR, 0);
        return;
    }

    /* Report SERVICE_RUNNING */
    self->ReportServiceStatus(SERVICE_RUNNING);
    LOG_INFO("AkesoDLP Agent service started successfully");

    /* Block until stop event is signaled */
    WaitForSingleObject(self->stop_event_, INFINITE);

    /* Shutdown */
    self->Shutdown();
    self->ReportServiceStatus(SERVICE_STOPPED);
    LOG_INFO("AkesoDLP Agent service stopped");
}

/* ================================================================== */
/*  SCM: Control Handler                                               */
/* ================================================================== */

void WINAPI AgentService::ServiceCtrlHandler(DWORD control) {
    auto* self = instance_;
    if (!self) return;

    switch (control) {
    case SERVICE_CONTROL_STOP:
    case SERVICE_CONTROL_SHUTDOWN:
        self->ReportServiceStatus(SERVICE_STOP_PENDING, 0, 5000);
        self->state_ = AgentState::Stopping;
        SetEvent(self->stop_event_);
        break;

    case SERVICE_CONTROL_INTERROGATE:
        /* Report current status */
        self->ReportServiceStatus(self->service_status_.dwCurrentState);
        break;

    default:
        break;
    }
}

/* ================================================================== */
/*  Console mode (for debugging)                                       */
/* ================================================================== */

bool AgentService::RunConsole(const AgentConfig& config) {
    SetConsoleCtrlHandler(ConsoleCtrlHandler, TRUE);

    state_ = AgentState::Starting;

    if (!Initialize(config)) {
        return false;
    }

    if (!StartComponents()) {
        StopComponents();
        return false;
    }

    std::cout << "AkesoDLP Agent running in console mode. Press Ctrl+C to stop."
              << std::endl;

    /* Block until stop */
    WaitForSingleObject(stop_event_, INFINITE);

    Shutdown();
    return true;
}

BOOL WINAPI AgentService::ConsoleCtrlHandler(DWORD ctrlType) {
    if (ctrlType == CTRL_C_EVENT ||
        ctrlType == CTRL_BREAK_EVENT ||
        ctrlType == CTRL_CLOSE_EVENT) {
        auto* self = instance_;
        if (self) {
            self->state_ = AgentState::Stopping;
            SetEvent(self->stop_event_);
        }
        return TRUE;
    }
    return FALSE;
}

/* ================================================================== */
/*  Lifecycle                                                          */
/* ================================================================== */

bool AgentService::Initialize(const AgentConfig& config) {
    config_ = config;

    LOG_INFO("AkesoDLP Agent v{} initializing", "0.1.0");
    LOG_INFO("Server: {}:{}", config_.server.host, config_.server.port);
    LOG_INFO("TLS: {}", config_.server.tls.enabled ? "enabled" : "disabled");
    LOG_INFO("TTD timeout: {}s, fallback: {}",
             config_.detection.ttd_timeout,
             config_.detection.ttd_fallback);

    /*
     * Determine initial mode based on policy cache.
     * If we have cached policies, start in enforcing mode.
     * Otherwise, start in log-only mode (allow everything, log events).
     */
    auto cache_path = std::filesystem::path(config_.policy_cache.path);
    if (std::filesystem::exists(cache_path)) {
        LOG_INFO("Policy cache found — starting in ENFORCING mode");
        state_ = AgentState::Enforcing;
    } else {
        LOG_WARN("No policy cache — starting in LOG-ONLY mode");
        state_ = AgentState::LogOnly;
    }

    return true;
}

bool AgentService::StartComponents() {
    std::lock_guard<std::mutex> lock(components_mutex_);

    for (auto& component : components_) {
        LOG_INFO("Starting component: {}", component->Name());
        if (!component->Start()) {
            LOG_ERROR("Failed to start component: {}", component->Name());
            return false;
        }
    }

    /* Start the watchdog thread */
    watchdog_running_ = true;
    watchdog_thread_ = std::thread(&AgentService::WatchdogThread, this);

    return true;
}

void AgentService::StopComponents() {
    /* Stop watchdog first */
    watchdog_running_ = false;
    if (watchdog_thread_.joinable()) {
        watchdog_thread_.join();
    }

    /* Stop components in reverse order */
    std::lock_guard<std::mutex> lock(components_mutex_);
    for (auto it = components_.rbegin(); it != components_.rend(); ++it) {
        LOG_INFO("Stopping component: {}", (*it)->Name());
        (*it)->Stop();
    }
}

void AgentService::Shutdown() {
    state_ = AgentState::Stopping;
    StopComponents();
    state_ = AgentState::Stopped;

    /* Flush all log buffers before exit */
#ifdef HAS_SPDLOG
    spdlog::shutdown();
#endif
}

/* ================================================================== */
/*  Component management                                               */
/* ================================================================== */

void AgentService::RegisterComponent(std::shared_ptr<IAgentComponent> component) {
    std::lock_guard<std::mutex> lock(components_mutex_);
    components_.push_back(std::move(component));
}

void AgentService::TransitionToEnforcing() {
    auto prev = state_.exchange(AgentState::Enforcing);
    if (prev != AgentState::Enforcing) {
        LOG_INFO("Transitioned from {} to ENFORCING",
                 prev == AgentState::LogOnly ? "LOG-ONLY" : "other");
    }
}

void AgentService::TransitionToLogOnly() {
    auto prev = state_.exchange(AgentState::LogOnly);
    if (prev != AgentState::LogOnly) {
        LOG_WARN("Transitioned from ENFORCING to LOG-ONLY");
    }
}

/* ================================================================== */
/*  Service status reporting                                           */
/* ================================================================== */

void AgentService::ReportServiceStatus(
    DWORD state,
    DWORD exitCode,
    DWORD waitHint
) {
    static DWORD checkPoint = 1;

    service_status_.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    service_status_.dwCurrentState = state;
    service_status_.dwWin32ExitCode = exitCode;
    service_status_.dwWaitHint = waitHint;

    if (state == SERVICE_START_PENDING) {
        service_status_.dwControlsAccepted = 0;
    } else {
        service_status_.dwControlsAccepted =
            SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
    }

    if (state == SERVICE_RUNNING || state == SERVICE_STOPPED) {
        service_status_.dwCheckPoint = 0;
    } else {
        service_status_.dwCheckPoint = checkPoint++;
    }

    if (status_handle_) {
        SetServiceStatus(status_handle_, &service_status_);
    }
}

/* ================================================================== */
/*  Watchdog thread                                                    */
/* ================================================================== */

void AgentService::WatchdogThread() {
    LOG_INFO("Watchdog thread started");

    while (watchdog_running_) {
        /* Check every 10 seconds */
        for (int i = 0; i < 10 && watchdog_running_; ++i) {
            Sleep(1000);
        }

        if (!watchdog_running_) break;

        /* Check component health */
        std::lock_guard<std::mutex> lock(components_mutex_);
        for (auto& component : components_) {
            if (!component->IsHealthy()) {
                LOG_WARN("Component unhealthy: {}, attempting restart",
                         component->Name());

                component->Stop();
                if (!component->Start()) {
                    LOG_ERROR("Failed to restart component: {}",
                              component->Name());
                    /*
                     * If a critical component can't restart,
                     * transition to log-only mode rather than crashing.
                     */
                    TransitionToLogOnly();
                }
            }
        }
    }

    LOG_INFO("Watchdog thread stopped");
}

}  // namespace akeso::dlp
