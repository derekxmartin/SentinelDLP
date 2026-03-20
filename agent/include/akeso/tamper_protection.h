/*
 * tamper_protection.h
 * AkesoDLP Agent - Tamper Protection (P4-T12)
 *
 * Hardens the agent against termination and unauthorized
 * service control by modifying service and process DACLs.
 * Also gates uninstall behind a password hash.
 */

#pragma once

#include "akeso/agent_service.h"
#include "akeso/config.h"

#include <atomic>
#include <string>

namespace akeso::dlp {

/* ------------------------------------------------------------------ */
/*  TamperProtection component                                         */
/* ------------------------------------------------------------------ */

class TamperProtection : public IAgentComponent {
public:
    explicit TamperProtection(const TamperProtectionConfig& config);
    ~TamperProtection() override = default;

    /* IAgentComponent */
    std::string Name() const override { return "TamperProtection"; }
    bool Start() override;
    void Stop() override;
    bool IsHealthy() const override;

    /* ------------------------------------------------------------ */
    /*  Uninstall password management                                */
    /* ------------------------------------------------------------ */

    /*
     * Set the uninstall password. Generates a random salt, hashes
     * salt+password with SHA-256, and writes to the key file.
     * Returns true on success.
     */
    static bool SetUninstallPassword(
        const std::string& password,
        const std::string& key_path);

    /*
     * Verify a password against the stored hash.
     * Returns true if the password matches, or if no key file exists
     * (uninstall password not configured).
     */
    static bool VerifyUninstallPassword(
        const std::string& password,
        const std::string& key_path);

    /*
     * Check if an uninstall password is configured.
     */
    static bool HasUninstallPassword(const std::string& key_path);

private:
    /* DACL hardening */
    bool HardenServiceDacl();
    bool HardenProcessDacl();

    /* Hashing helpers */
    static std::string GenerateSalt(size_t bytes = 16);
    static std::string HashPassword(const std::string& salt,
                                    const std::string& password);

    TamperProtectionConfig config_;
    std::atomic<bool> applied_{false};
};

}  // namespace akeso::dlp
