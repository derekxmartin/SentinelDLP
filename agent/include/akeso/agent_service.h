/*
 * agent_service.h
 * AkesoDLP Agent - Windows Service
 *
 * Manages the agent lifecycle as a Windows service registered
 * with the Service Control Manager (SCM).
 */

#pragma once

#include "akeso/config.h"

#include <atomic>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>

namespace akeso::dlp {

/* ------------------------------------------------------------------ */
/*  Service state                                                      */
/* ------------------------------------------------------------------ */

enum class AgentState {
    Stopped,
    Starting,
    Running,
    Stopping,
    Error,
    LogOnly,        /* Offline mode: no policy cache, log everything */
    Enforcing,      /* Online mode: policies loaded, enforcing */
};

/* ------------------------------------------------------------------ */
/*  Component interface                                                */
/* ------------------------------------------------------------------ */

/*
 * Abstract interface for agent components (gRPC client, detection
 * engine, policy cache, etc.) that participate in the startup/
 * shutdown lifecycle.
 */
class IAgentComponent {
public:
    virtual ~IAgentComponent() = default;
    virtual std::string Name() const = 0;
    virtual bool Start() = 0;
    virtual void Stop() = 0;
    virtual bool IsHealthy() const = 0;
};

/* ------------------------------------------------------------------ */
/*  Agent Service                                                      */
/* ------------------------------------------------------------------ */

class AgentService {
public:
    static constexpr const wchar_t* kServiceName = L"AkesoDLPAgent";
    static constexpr const wchar_t* kDisplayName = L"AkesoDLP Agent";
    static constexpr const wchar_t* kDescription =
        L"AkesoDLP Data Loss Prevention endpoint agent";

    AgentService();
    ~AgentService();

    /* Non-copyable */
    AgentService(const AgentService&) = delete;
    AgentService& operator=(const AgentService&) = delete;

    /*
     * Run as a Windows service (called from main).
     * This registers with SCM and blocks until the service stops.
     */
    static bool RunAsService();

    /*
     * Run in console mode (for debugging).
     * Blocks until Ctrl+C is pressed.
     */
    bool RunConsole(const AgentConfig& config);

    /*
     * Register a component for lifecycle management.
     * Components are started in registration order and
     * stopped in reverse order.
     */
    void RegisterComponent(std::shared_ptr<IAgentComponent> component);

    /* State accessors */
    AgentState GetState() const { return state_.load(); }
    const AgentConfig& GetConfig() const { return config_; }
    bool IsRunning() const {
        auto s = state_.load();
        return s == AgentState::Running ||
               s == AgentState::LogOnly ||
               s == AgentState::Enforcing;
    }

    /*
     * Transition to enforcement mode (called when policies are synced).
     */
    void TransitionToEnforcing();

    /*
     * Transition to log-only mode (called on policy cache miss).
     */
    void TransitionToLogOnly();

private:
    /* SCM callbacks (static, forwarded to singleton) */
    static void WINAPI ServiceMain(DWORD argc, LPWSTR* argv);
    static void WINAPI ServiceCtrlHandler(DWORD control);
    static BOOL WINAPI ConsoleCtrlHandler(DWORD ctrlType);

    /* Internal lifecycle */
    bool Initialize(const AgentConfig& config);
    bool StartComponents();
    void StopComponents();
    void Shutdown();

    /* Service status helpers */
    void ReportServiceStatus(DWORD state, DWORD exitCode = 0, DWORD waitHint = 0);

    /* Watchdog */
    void WatchdogThread();

    /* State */
    std::atomic<AgentState>     state_{AgentState::Stopped};
    AgentConfig                 config_;
    SERVICE_STATUS_HANDLE       status_handle_{nullptr};
    SERVICE_STATUS              service_status_{};
    HANDLE                      stop_event_{nullptr};

    /* Components */
    std::vector<std::shared_ptr<IAgentComponent>> components_;
    std::mutex                  components_mutex_;

    /* Watchdog */
    std::thread                 watchdog_thread_;
    std::atomic<bool>           watchdog_running_{false};

    /* Singleton for SCM callbacks */
    static AgentService*        instance_;
};

}  // namespace akeso::dlp
