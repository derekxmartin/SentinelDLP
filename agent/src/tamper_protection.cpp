/*
 * tamper_protection.cpp
 * AkesoDLP Agent - Tamper Protection (P4-T12)
 *
 * Implements service DACL hardening (deny SERVICE_STOP to
 * non-SYSTEM), process DACL hardening (deny PROCESS_TERMINATE
 * to standard users), and uninstall password verification.
 */

#include "akeso/tamper_protection.h"

#ifdef HAS_SPDLOG
#include <spdlog/spdlog.h>
#define LOG_INFO(...)  spdlog::info(__VA_ARGS__)
#define LOG_WARN(...)  spdlog::warn(__VA_ARGS__)
#define LOG_ERROR(...) spdlog::error(__VA_ARGS__)
#else
#define LOG_INFO(...)
#define LOG_WARN(...)
#define LOG_ERROR(...)
#endif

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>
#include <AclAPI.h>
#include <sddl.h>
#include <bcrypt.h>
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "bcrypt.lib")
#endif

#include <filesystem>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <vector>

namespace akeso::dlp {

/* ================================================================== */
/*  Constructor                                                        */
/* ================================================================== */

TamperProtection::TamperProtection(const TamperProtectionConfig& config)
    : config_(config)
{
}

/* ================================================================== */
/*  IAgentComponent lifecycle                                          */
/* ================================================================== */

bool TamperProtection::Start()
{
    if (!config_.enabled) {
        LOG_INFO("TamperProtection: disabled by config");
        return true;
    }

#ifdef _WIN32
    bool ok = true;

    if (config_.harden_service_dacl) {
        if (HardenServiceDacl()) {
            LOG_INFO("TamperProtection: service DACL hardened (sc stop denied to non-SYSTEM)");
        } else {
            LOG_WARN("TamperProtection: service DACL hardening skipped (console mode or insufficient access)");
            /* Not fatal — may be running in console mode */
        }
    }

    if (config_.harden_process_dacl) {
        if (HardenProcessDacl()) {
            LOG_INFO("TamperProtection: process DACL hardened (taskkill denied to standard users)");
        } else {
            LOG_WARN("TamperProtection: process DACL hardening failed");
            ok = false;
        }
    }

    applied_ = ok;
#else
    LOG_WARN("TamperProtection: not implemented on this platform");
    applied_ = true;
#endif

    return true;  /* Non-fatal: always let the agent start */
}

void TamperProtection::Stop()
{
    /* DACLs persist for the process lifetime, nothing to undo */
}

bool TamperProtection::IsHealthy() const
{
    return true;  /* Tamper protection is fire-and-forget */
}

/* ================================================================== */
/*  Service DACL hardening                                             */
/* ================================================================== */

#ifdef _WIN32

bool TamperProtection::HardenServiceDacl()
{
    /*
     * Deny SERVICE_STOP, SERVICE_PAUSE_CONTINUE, and DELETE
     * to BUILTIN\Users (S-1-5-32-545). SYSTEM and Administrators
     * retain full control via the default service DACL.
     */

    /* Open the SCM */
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) {
        LOG_WARN("TamperProtection: OpenSCManager failed (error={})", GetLastError());
        return false;
    }

    /* Open our own service with DACL write access */
    SC_HANDLE svc = OpenServiceW(scm, AgentService::kServiceName,
                                  READ_CONTROL | WRITE_DAC);
    if (!svc) {
        DWORD err = GetLastError();
        CloseServiceHandle(scm);
        /* ERROR_SERVICE_DOES_NOT_EXIST is expected in console mode */
        if (err == ERROR_SERVICE_DOES_NOT_EXIST) {
            return false;  /* Not installed as service, skip silently */
        }
        LOG_WARN("TamperProtection: OpenService failed (error={})", err);
        return false;
    }

    /* Get the current security descriptor */
    DWORD bytes_needed = 0;
    QueryServiceObjectSecurity(svc, DACL_SECURITY_INFORMATION,
                                nullptr, 0, &bytes_needed);

    std::vector<BYTE> sd_buf(bytes_needed);
    auto* sd = reinterpret_cast<PSECURITY_DESCRIPTOR>(sd_buf.data());

    if (!QueryServiceObjectSecurity(svc, DACL_SECURITY_INFORMATION,
                                     sd, bytes_needed, &bytes_needed)) {
        LOG_ERROR("TamperProtection: QueryServiceObjectSecurity failed (error={})",
                  GetLastError());
        CloseServiceHandle(svc);
        CloseServiceHandle(scm);
        return false;
    }

    /* Extract existing DACL */
    PACL existing_dacl = nullptr;
    BOOL dacl_present = FALSE, dacl_defaulted = FALSE;
    GetSecurityDescriptorDacl(sd, &dacl_present, &existing_dacl, &dacl_defaulted);

    /* Build DENY ACE for BUILTIN\Users */
    EXPLICIT_ACCESS_W deny_access = {};
    deny_access.grfAccessPermissions = SERVICE_STOP | SERVICE_PAUSE_CONTINUE | DELETE;
    deny_access.grfAccessMode = DENY_ACCESS;
    deny_access.grfInheritance = NO_INHERITANCE;
    deny_access.Trustee.TrusteeForm = TRUSTEE_IS_SID;
    deny_access.Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;

    /* Create BUILTIN\Users SID (S-1-5-32-545) */
    SID_IDENTIFIER_AUTHORITY nt_authority = SECURITY_NT_AUTHORITY;
    PSID users_sid = nullptr;
    if (!AllocateAndInitializeSid(&nt_authority, 2,
            SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_USERS,
            0, 0, 0, 0, 0, 0, &users_sid)) {
        LOG_ERROR("TamperProtection: AllocateAndInitializeSid failed (error={})",
                  GetLastError());
        CloseServiceHandle(svc);
        CloseServiceHandle(scm);
        return false;
    }

    deny_access.Trustee.ptstrName = reinterpret_cast<LPWSTR>(users_sid);

    /* Merge DENY ACE with existing DACL */
    PACL new_dacl = nullptr;
    DWORD result = SetEntriesInAclW(1, &deny_access, existing_dacl, &new_dacl);
    FreeSid(users_sid);

    if (result != ERROR_SUCCESS) {
        LOG_ERROR("TamperProtection: SetEntriesInAcl failed (error={})", result);
        CloseServiceHandle(svc);
        CloseServiceHandle(scm);
        return false;
    }

    /* Build new security descriptor */
    SECURITY_DESCRIPTOR new_sd;
    InitializeSecurityDescriptor(&new_sd, SECURITY_DESCRIPTOR_REVISION);
    SetSecurityDescriptorDacl(&new_sd, TRUE, new_dacl, FALSE);

    /* Apply to the service */
    bool success = SetServiceObjectSecurity(
        svc, DACL_SECURITY_INFORMATION, &new_sd) != FALSE;

    if (!success) {
        LOG_ERROR("TamperProtection: SetServiceObjectSecurity failed (error={})",
                  GetLastError());
    }

    LocalFree(new_dacl);
    CloseServiceHandle(svc);
    CloseServiceHandle(scm);

    return success;
}

/* ================================================================== */
/*  Process DACL hardening                                             */
/* ================================================================== */

bool TamperProtection::HardenProcessDacl()
{
    /*
     * Deny PROCESS_TERMINATE and PROCESS_SUSPEND_RESUME to
     * BUILTIN\Users (S-1-5-32-545). SYSTEM and elevated admins
     * with SeDebugPrivilege can still terminate (by design).
     */

    HANDLE proc = GetCurrentProcess();

    /* Get current DACL */
    PACL existing_dacl = nullptr;
    PSECURITY_DESCRIPTOR sd = nullptr;
    DWORD result = GetSecurityInfo(proc, SE_KERNEL_OBJECT,
                                    DACL_SECURITY_INFORMATION,
                                    nullptr, nullptr,
                                    &existing_dacl, nullptr, &sd);
    if (result != ERROR_SUCCESS) {
        LOG_ERROR("TamperProtection: GetSecurityInfo failed (error={})", result);
        return false;
    }

    /* Build DENY ACE for BUILTIN\Users */
    EXPLICIT_ACCESS_W deny_access = {};
    deny_access.grfAccessPermissions = PROCESS_TERMINATE | PROCESS_SUSPEND_RESUME;
    deny_access.grfAccessMode = DENY_ACCESS;
    deny_access.grfInheritance = NO_INHERITANCE;
    deny_access.Trustee.TrusteeForm = TRUSTEE_IS_SID;
    deny_access.Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;

    /* Create BUILTIN\Users SID */
    SID_IDENTIFIER_AUTHORITY nt_authority = SECURITY_NT_AUTHORITY;
    PSID users_sid = nullptr;
    if (!AllocateAndInitializeSid(&nt_authority, 2,
            SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_USERS,
            0, 0, 0, 0, 0, 0, &users_sid)) {
        LOG_ERROR("TamperProtection: AllocateAndInitializeSid failed (error={})",
                  GetLastError());
        LocalFree(sd);
        return false;
    }

    deny_access.Trustee.ptstrName = reinterpret_cast<LPWSTR>(users_sid);

    /* Merge DENY ACE into existing DACL */
    PACL new_dacl = nullptr;
    result = SetEntriesInAclW(1, &deny_access, existing_dacl, &new_dacl);
    FreeSid(users_sid);

    if (result != ERROR_SUCCESS) {
        LOG_ERROR("TamperProtection: SetEntriesInAcl (process) failed (error={})",
                  result);
        LocalFree(sd);
        return false;
    }

    /* Apply new DACL to our process */
    result = SetSecurityInfo(proc, SE_KERNEL_OBJECT,
                              DACL_SECURITY_INFORMATION,
                              nullptr, nullptr, new_dacl, nullptr);

    bool success = (result == ERROR_SUCCESS);
    if (!success) {
        LOG_ERROR("TamperProtection: SetSecurityInfo (process) failed (error={})",
                  result);
    }

    LocalFree(new_dacl);
    LocalFree(sd);

    return success;
}

#else
/* Non-Windows stubs */
bool TamperProtection::HardenServiceDacl() { return false; }
bool TamperProtection::HardenProcessDacl() { return false; }
#endif

/* ================================================================== */
/*  Password hashing                                                   */
/* ================================================================== */

std::string TamperProtection::GenerateSalt(size_t bytes)
{
#ifdef _WIN32
    std::vector<BYTE> buf(bytes);
    NTSTATUS status = BCryptGenRandom(nullptr, buf.data(),
                                       static_cast<ULONG>(bytes),
                                       BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (!BCRYPT_SUCCESS(status)) {
        return {};
    }

    std::ostringstream oss;
    for (auto b : buf) {
        oss << std::hex << std::setfill('0') << std::setw(2)
            << static_cast<int>(b);
    }
    return oss.str();
#else
    (void)bytes;
    return {};
#endif
}

std::string TamperProtection::HashPassword(
    const std::string& salt,
    const std::string& password)
{
#ifdef _WIN32
    std::string input = salt + password;

    BCRYPT_ALG_HANDLE alg = nullptr;
    NTSTATUS status = BCryptOpenAlgorithmProvider(
        &alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
    if (!BCRYPT_SUCCESS(status)) return {};

    DWORD hash_len = 0, result_len = 0;
    BCryptGetProperty(alg, BCRYPT_HASH_LENGTH,
                      reinterpret_cast<PUCHAR>(&hash_len),
                      sizeof(hash_len), &result_len, 0);

    BCRYPT_HASH_HANDLE hash = nullptr;
    status = BCryptCreateHash(alg, &hash, nullptr, 0, nullptr, 0, 0);
    if (!BCRYPT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(alg, 0);
        return {};
    }

    BCryptHashData(hash,
                   reinterpret_cast<PUCHAR>(const_cast<char*>(input.data())),
                   static_cast<ULONG>(input.size()), 0);

    std::vector<BYTE> hash_buf(hash_len);
    BCryptFinishHash(hash, hash_buf.data(), hash_len, 0);

    BCryptDestroyHash(hash);
    BCryptCloseAlgorithmProvider(alg, 0);

    std::ostringstream oss;
    for (DWORD i = 0; i < hash_len; ++i) {
        oss << std::hex << std::setfill('0') << std::setw(2)
            << static_cast<int>(hash_buf[i]);
    }
    return oss.str();
#else
    (void)salt;
    (void)password;
    return {};
#endif
}

/* ================================================================== */
/*  Uninstall password management                                      */
/* ================================================================== */

bool TamperProtection::SetUninstallPassword(
    const std::string& password,
    const std::string& key_path)
{
    if (password.empty()) {
        LOG_ERROR("TamperProtection: password cannot be empty");
        return false;
    }

    /* Generate random salt */
    std::string salt = GenerateSalt(16);
    if (salt.empty()) {
        LOG_ERROR("TamperProtection: failed to generate salt");
        return false;
    }

    /* Hash salt+password */
    std::string hash = HashPassword(salt, password);
    if (hash.empty()) {
        LOG_ERROR("TamperProtection: failed to hash password");
        return false;
    }

    /* Ensure parent directory exists */
    std::filesystem::path path(key_path);
    std::filesystem::create_directories(path.parent_path());

    /* Write salt:hash to file */
    std::ofstream ofs(key_path, std::ios::trunc);
    if (!ofs) {
        LOG_ERROR("TamperProtection: cannot write key file: {}", key_path);
        return false;
    }
    ofs << salt << ":" << hash << std::endl;
    ofs.close();

    LOG_INFO("TamperProtection: uninstall password set (key={})", key_path);
    return true;
}

bool TamperProtection::VerifyUninstallPassword(
    const std::string& password,
    const std::string& key_path)
{
    if (!HasUninstallPassword(key_path)) {
        return true;  /* No password configured — allow uninstall */
    }

    /* Read salt:hash from file */
    std::ifstream ifs(key_path);
    if (!ifs) {
        return true;  /* Can't read file — allow (fail open) */
    }

    std::string line;
    std::getline(ifs, line);
    ifs.close();

    /* Parse salt:hash */
    auto colon = line.find(':');
    if (colon == std::string::npos) {
        LOG_ERROR("TamperProtection: malformed key file");
        return false;
    }

    std::string stored_salt = line.substr(0, colon);
    std::string stored_hash = line.substr(colon + 1);

    /* Trim whitespace */
    while (!stored_hash.empty() && (stored_hash.back() == '\n' ||
           stored_hash.back() == '\r' || stored_hash.back() == ' ')) {
        stored_hash.pop_back();
    }

    /* Recompute and compare */
    std::string computed = HashPassword(stored_salt, password);
    return !computed.empty() && computed == stored_hash;
}

bool TamperProtection::HasUninstallPassword(const std::string& key_path)
{
    return std::filesystem::exists(key_path) &&
           std::filesystem::file_size(key_path) > 0;
}

}  // namespace akeso::dlp
