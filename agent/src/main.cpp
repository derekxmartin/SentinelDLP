#include <iostream>
#include <string>

namespace sentinel::dlp {

constexpr const char* kVersion = "0.1.0";
constexpr const char* kServiceName = "SentinelDLPAgent";

int Run([[maybe_unused]] int argc, [[maybe_unused]] char* argv[]) {
    std::cout << kServiceName << " v" << kVersion << std::endl;

    // TODO: Initialize components:
    //   - DriverComm (FilterConnectCommunicationPort)
    //   - ContentInspector
    //   - DetectionEngine (Hyperscan, Aho-Corasick)
    //   - PolicyEvaluator
    //   - ResponseExecutor
    //   - ClipboardMonitor
    //   - BrowserMonitor
    //   - PolicyCache (SQLite)
    //   - IncidentQueue
    //   - GrpcClient
    //   - Watchdog

    std::cout << "Agent initialized. Waiting for events..." << std::endl;
    return 0;
}

}  // namespace sentinel::dlp

int main(int argc, char* argv[]) {
    return sentinel::dlp::Run(argc, argv);
}
