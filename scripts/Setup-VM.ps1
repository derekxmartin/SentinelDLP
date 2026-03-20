#Requires -RunAsAdministrator
<#
.SYNOPSIS
    AkesoDLP VM Setup Script — prepares a Windows VM for minifilter driver development and testing.

.DESCRIPTION
    This script automates the full setup of a Windows test VM:
      1. Enables test signing (reboot required)
      2. Installs Visual Studio Build Tools 2022 (if not present)
      3. Installs Windows Driver Kit (WDK)
      4. Installs CMake + Ninja
      5. Installs and bootstraps vcpkg
      6. Creates a test-signing certificate
      7. Builds the user-mode agent (CMake + vcpkg)
      8. Builds and signs the minifilter driver
      9. Installs the driver via INF
     10. Verifies the full stack

.PARAMETER RepoPath
    Path to the AkesoDLP repo on the VM. Default: C:\AkesoDLP

.PARAMETER SkipBuild
    Skip the agent and driver build steps (useful for re-running after a failed build).

.PARAMETER SkipInstall
    Skip tool installation steps (useful when tools are already installed).

.EXAMPLE
    .\Setup-VM.ps1
    .\Setup-VM.ps1 -RepoPath D:\Projects\AkesoDLP
    .\Setup-VM.ps1 -SkipInstall

.NOTES
    Requires: Windows 10/11 or Server 2019+, admin privileges, internet access.
    Related: P3-T2 (minifilter), P3-T3 (volume classification), P3-T4 (driver comm)
#>

[CmdletBinding()]
param(
    [string]$RepoPath = "C:\AkesoDLP",
    [switch]$SkipBuild,
    [switch]$SkipInstall
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"  # Speed up Invoke-WebRequest

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

function Write-Step {
    param([string]$Message)
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "  $Message" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
}

function Write-Ok {
    param([string]$Message)
    Write-Host "  [OK] $Message" -ForegroundColor Green
}

function Write-Warn {
    param([string]$Message)
    Write-Host "  [WARN] $Message" -ForegroundColor Yellow
}

function Write-Fail {
    param([string]$Message)
    Write-Host "  [FAIL] $Message" -ForegroundColor Red
}

function Test-CommandExists {
    param([string]$Command)
    $null -ne (Get-Command $Command -ErrorAction SilentlyContinue)
}

$TempDir = Join-Path $env:TEMP "AkesoDLP-Setup"
if (-not (Test-Path $TempDir)) { New-Item -ItemType Directory -Path $TempDir -Force | Out-Null }

# ---------------------------------------------------------------------------
# Step 0: Validate prerequisites
# ---------------------------------------------------------------------------

Write-Step "Step 0: Validating prerequisites"

if (-not (Test-Path $RepoPath)) {
    Write-Fail "Repo not found at $RepoPath"
    Write-Host "  Transfer the repo to the VM first, then re-run this script." -ForegroundColor Yellow
    Write-Host "  Example: Copy-Item -Recurse \\devhost\share\claude-dlp $RepoPath" -ForegroundColor Yellow
    exit 1
}
Write-Ok "Repo found at $RepoPath"

$AgentDir = Join-Path $RepoPath "agent"
$DriverDir = Join-Path $AgentDir "driver"
if (-not (Test-Path $DriverDir)) {
    Write-Fail "Driver source not found at $DriverDir"
    exit 1
}
Write-Ok "Driver source found at $DriverDir"

# ---------------------------------------------------------------------------
# Step 1: Enable test signing
# ---------------------------------------------------------------------------

Write-Step "Step 1: Enable test signing"

$testSigning = bcdedit /enum "{current}" | Select-String "testsigning\s+Yes"
if ($testSigning) {
    Write-Ok "Test signing is already enabled"
} else {
    Write-Host "  Enabling test signing..." -ForegroundColor Yellow
    bcdedit /set testsigning on | Out-Null
    Write-Ok "Test signing enabled — REBOOT REQUIRED before driver can load"
    Write-Warn "After reboot, re-run this script with -SkipInstall if tools are already installed"
}

# ---------------------------------------------------------------------------
# Step 2: Install Visual Studio Build Tools
# ---------------------------------------------------------------------------

if (-not $SkipInstall) {
    Write-Step "Step 2: Install Visual Studio Build Tools 2022"

    # Check for existing VS installation
    $vsWhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
    $vsInstalled = $false
    if (Test-Path $vsWhere) {
        $vsPath = & $vsWhere -latest -property installationPath 2>$null
        if ($vsPath) {
            Write-Ok "Visual Studio found at $vsPath"
            $vsInstalled = $true
        }
    }

    if (-not $vsInstalled) {
        $vsInstallerUrl = "https://aka.ms/vs/17/release/vs_buildtools.exe"
        $vsInstaller = Join-Path $TempDir "vs_buildtools.exe"

        Write-Host "  Downloading VS Build Tools 2022..." -ForegroundColor Yellow
        Invoke-WebRequest -Uri $vsInstallerUrl -OutFile $vsInstaller

        Write-Host "  Installing (this may take 10-20 minutes)..." -ForegroundColor Yellow
        $vsArgs = @(
            "--quiet", "--wait", "--norestart",
            "--add", "Microsoft.VisualStudio.Workload.VCTools",
            "--add", "Microsoft.VisualStudio.Component.VC.Tools.x86.x64",
            "--add", "Microsoft.VisualStudio.Component.Windows11SDK.22621",
            "--add", "Microsoft.VisualStudio.Component.VC.ATL",
            "--includeRecommended"
        )
        $proc = Start-Process -FilePath $vsInstaller -ArgumentList $vsArgs -Wait -PassThru
        if ($proc.ExitCode -eq 0 -or $proc.ExitCode -eq 3010) {
            Write-Ok "VS Build Tools installed (exit code: $($proc.ExitCode))"
        } else {
            Write-Fail "VS Build Tools install failed (exit code: $($proc.ExitCode))"
            exit 1
        }
    }

    # ---------------------------------------------------------------------------
    # Step 3: Install Windows Driver Kit (WDK)
    # ---------------------------------------------------------------------------

    Write-Step "Step 3: Install Windows Driver Kit (WDK)"

    $wdkPath = "${env:ProgramFiles(x86)}\Windows Kits\10"
    if (Test-Path (Join-Path $wdkPath "Include")) {
        Write-Ok "WDK already installed at $wdkPath"
    } else {
        $wdkUrl = "https://go.microsoft.com/fwlink/?linkid=2249371"  # WDK for VS 2022
        $wdkInstaller = Join-Path $TempDir "wdksetup.exe"

        Write-Host "  Downloading WDK..." -ForegroundColor Yellow
        Invoke-WebRequest -Uri $wdkUrl -OutFile $wdkInstaller

        Write-Host "  Installing WDK (this may take 10-15 minutes)..." -ForegroundColor Yellow
        $proc = Start-Process -FilePath $wdkInstaller -ArgumentList "/quiet", "/norestart" -Wait -PassThru
        if ($proc.ExitCode -eq 0 -or $proc.ExitCode -eq 3010) {
            Write-Ok "WDK installed"
        } else {
            Write-Warn "WDK installer exited with code $($proc.ExitCode) — may need manual install"
        }
    }

    # ---------------------------------------------------------------------------
    # Step 4: Install CMake + Ninja
    # ---------------------------------------------------------------------------

    Write-Step "Step 4: Install CMake + Ninja"

    if (Test-CommandExists "cmake") {
        $cmakeVer = (cmake --version | Select-Object -First 1)
        Write-Ok "CMake already installed: $cmakeVer"
    } else {
        Write-Host "  Installing CMake via winget..." -ForegroundColor Yellow
        winget install --id Kitware.CMake --accept-source-agreements --accept-package-agreements --silent 2>$null
        if ($?) { Write-Ok "CMake installed" }
        else {
            Write-Host "  Falling back to direct download..." -ForegroundColor Yellow
            $cmakeUrl = "https://github.com/Kitware/CMake/releases/download/v3.31.6/cmake-3.31.6-windows-x86_64.msi"
            $cmakeInstaller = Join-Path $TempDir "cmake.msi"
            Invoke-WebRequest -Uri $cmakeUrl -OutFile $cmakeInstaller
            Start-Process msiexec.exe -ArgumentList "/i", $cmakeInstaller, "/quiet", "/norestart", "ADD_CMAKE_TO_PATH=System" -Wait
            Write-Ok "CMake installed via MSI"
        }
    }

    if (Test-CommandExists "ninja") {
        Write-Ok "Ninja already installed"
    } else {
        Write-Host "  Installing Ninja..." -ForegroundColor Yellow
        $ninjaUrl = "https://github.com/nicknisi/ninja/releases/download/v1.12.1/ninja-win.zip"
        $ninjaZip = Join-Path $TempDir "ninja.zip"
        $ninjaDir = "C:\Tools\ninja"
        Invoke-WebRequest -Uri "https://github.com/nicknisi/ninja/releases/download/v1.12.1/ninja-win.zip" -OutFile $ninjaZip 2>$null
        if (-not $?) {
            # Fallback: use the official GitHub URL
            Invoke-WebRequest -Uri "https://github.com/ninja-build/ninja/releases/download/v1.12.1/ninja-win.zip" -OutFile $ninjaZip
        }
        Expand-Archive -Path $ninjaZip -DestinationPath $ninjaDir -Force
        $env:Path += ";$ninjaDir"
        [Environment]::SetEnvironmentVariable("Path", $env:Path, [EnvironmentVariableTarget]::Machine)
        Write-Ok "Ninja installed to $ninjaDir"
    }

    # ---------------------------------------------------------------------------
    # Step 5: Install and bootstrap vcpkg
    # ---------------------------------------------------------------------------

    Write-Step "Step 5: Install vcpkg"

    $vcpkgRoot = $env:VCPKG_ROOT
    if (-not $vcpkgRoot) { $vcpkgRoot = "C:\vcpkg" }

    if (Test-Path (Join-Path $vcpkgRoot "vcpkg.exe")) {
        Write-Ok "vcpkg already installed at $vcpkgRoot"
    } else {
        Write-Host "  Cloning vcpkg to $vcpkgRoot..." -ForegroundColor Yellow
        git clone https://github.com/microsoft/vcpkg.git $vcpkgRoot
        Push-Location $vcpkgRoot
        & .\bootstrap-vcpkg.bat -disableMetrics
        Pop-Location
        Write-Ok "vcpkg bootstrapped"
    }

    # Set VCPKG_ROOT environment variable
    if (-not $env:VCPKG_ROOT) {
        [Environment]::SetEnvironmentVariable("VCPKG_ROOT", $vcpkgRoot, [EnvironmentVariableTarget]::Machine)
        $env:VCPKG_ROOT = $vcpkgRoot
        Write-Ok "VCPKG_ROOT set to $vcpkgRoot"
    }
}

# ---------------------------------------------------------------------------
# Step 6: Create test-signing certificate
# ---------------------------------------------------------------------------

Write-Step "Step 6: Create test-signing certificate"

$certName = "AkesoDLP Test"
$existingCert = Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Subject -like "*$certName*" }

if ($existingCert) {
    Write-Ok "Test certificate already exists: $($existingCert.Thumbprint)"
} else {
    Write-Host "  Creating self-signed certificate..." -ForegroundColor Yellow
    $cert = New-SelfSignedCertificate `
        -Type CodeSigningCert `
        -Subject "CN=$certName" `
        -CertStoreLocation Cert:\LocalMachine\My `
        -NotAfter (Get-Date).AddYears(5)

    # Trust the certificate
    $store = New-Object System.Security.Cryptography.X509Certificates.X509Store("Root", "LocalMachine")
    $store.Open("ReadWrite")
    $store.Add($cert)
    $store.Close()

    $store = New-Object System.Security.Cryptography.X509Certificates.X509Store("TrustedPublisher", "LocalMachine")
    $store.Open("ReadWrite")
    $store.Add($cert)
    $store.Close()

    Write-Ok "Certificate created and trusted: $($cert.Thumbprint)"
}

if ($SkipBuild) {
    Write-Step "Build steps skipped (-SkipBuild flag)"
    Write-Host "  Re-run without -SkipBuild to build the agent and driver." -ForegroundColor Yellow
} else {

    # ---------------------------------------------------------------------------
    # Step 7: Build the user-mode agent
    # ---------------------------------------------------------------------------

    Write-Step "Step 7: Build user-mode agent"

    # Enter VS dev shell for MSVC toolchain
    $vsDevShell = Get-ChildItem "${env:ProgramFiles(x86)}\Microsoft Visual Studio" -Recurse -Filter "Launch-VsDevShell.ps1" -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($vsDevShell) {
        Write-Host "  Entering VS Developer Shell..." -ForegroundColor Yellow
        & $vsDevShell.FullName -Arch amd64 -SkipAutomaticLocation 2>$null
    } else {
        Write-Warn "Could not find VS Developer Shell — build may fail if MSVC not in PATH"
    }

    Push-Location $AgentDir
    try {
        $buildDir = Join-Path $AgentDir "build\debug"
        if (Test-Path $buildDir) {
            Write-Host "  Cleaning previous build..." -ForegroundColor Yellow
            Remove-Item -Recurse -Force $buildDir
        }

        Write-Host "  Configuring with CMake (preset: debug)..." -ForegroundColor Yellow
        cmake --preset=debug 2>&1 | Tee-Object -Variable cmakeOutput
        if ($LASTEXITCODE -ne 0) {
            Write-Fail "CMake configure failed"
            Write-Host ($cmakeOutput -join "`n") -ForegroundColor Red
            exit 1
        }

        Write-Host "  Building agent..." -ForegroundColor Yellow
        cmake --build build/debug 2>&1 | Tee-Object -Variable buildOutput
        if ($LASTEXITCODE -ne 0) {
            Write-Fail "Agent build failed"
            exit 1
        }
        Write-Ok "Agent built successfully"
    } finally {
        Pop-Location
    }

    # ---------------------------------------------------------------------------
    # Step 8: Build and sign the driver
    # ---------------------------------------------------------------------------

    Write-Step "Step 8: Build and sign the driver"

    $driverSys = Join-Path $DriverDir "akeso_dlp_filter.sys"

    # For now, check if the driver binary exists from a previous build
    # Full WDK build integration depends on FindWDK.cmake being available
    if (Test-Path $driverSys) {
        Write-Ok "Driver binary found: $driverSys"
    } else {
        Write-Host "  Building driver with CMake (release-driver preset)..." -ForegroundColor Yellow
        Push-Location $AgentDir
        try {
            cmake --preset=release-driver 2>&1 | Tee-Object -Variable driverConfigOutput
            if ($LASTEXITCODE -eq 0) {
                cmake --build build/release-driver 2>&1 | Tee-Object -Variable driverBuildOutput
            }

            # Check for the built .sys file in build output
            $builtSys = Get-ChildItem -Path (Join-Path $AgentDir "build") -Recurse -Filter "akeso_dlp_filter.sys" -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($builtSys) {
                $driverSys = $builtSys.FullName
                Write-Ok "Driver built: $driverSys"
            } else {
                Write-Warn "Driver build did not produce .sys file — may need manual WDK build"
                Write-Host "  You can build manually with: msbuild or WDK build environment" -ForegroundColor Yellow
            }
        } finally {
            Pop-Location
        }
    }

    # Sign the driver
    if (Test-Path $driverSys) {
        Write-Host "  Signing driver..." -ForegroundColor Yellow
        $signtool = Get-ChildItem "${env:ProgramFiles(x86)}\Windows Kits\10\bin" -Recurse -Filter "signtool.exe" -ErrorAction SilentlyContinue |
            Where-Object { $_.FullName -like "*x64*" } |
            Select-Object -First 1

        if ($signtool) {
            & $signtool.FullName sign /v /s My /n "$certName" /fd SHA256 $driverSys 2>&1
            if ($LASTEXITCODE -eq 0) {
                Write-Ok "Driver signed successfully"
            } else {
                Write-Warn "Driver signing failed — ensure test certificate is in My store"
            }
        } else {
            Write-Warn "signtool.exe not found — install WDK or Windows SDK"
        }
    }
}

# ---------------------------------------------------------------------------
# Step 9: Install the driver
# ---------------------------------------------------------------------------

Write-Step "Step 9: Install the driver"

$infPath = Join-Path $DriverDir "akeso_dlp_filter.inf"
$filterLoaded = fltmc filters 2>$null | Select-String "AkesoDLPFilter"

if ($filterLoaded) {
    Write-Ok "AkesoDLPFilter is already loaded"
} else {
    if (Test-Path $infPath) {
        Write-Host "  Installing driver via INF..." -ForegroundColor Yellow

        # Copy driver to System32\drivers
        $driverSys = Get-ChildItem -Path $RepoPath -Recurse -Filter "akeso_dlp_filter.sys" -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($driverSys) {
            Copy-Item $driverSys.FullName "$env:SystemRoot\System32\drivers\akeso_dlp_filter.sys" -Force
            Write-Ok "Driver copied to System32\drivers"
        }

        # Install via RUNDLL32 + INF
        rundll32.exe setupapi.dll,InstallHinfSection DefaultInstall.NTAMD64 132 $infPath 2>$null

        # Try loading
        Write-Host "  Loading minifilter..." -ForegroundColor Yellow
        fltmc load AkesoDLPFilter 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Ok "AkesoDLPFilter loaded"
        } else {
            Write-Warn "fltmc load failed — ensure test signing is enabled and reboot was done"
        }
    } else {
        Write-Warn "INF file not found at $infPath — skipping driver install"
    }
}

# ---------------------------------------------------------------------------
# Step 10: Verify
# ---------------------------------------------------------------------------

Write-Step "Step 10: Verification"

$results = @()

# Test signing
$ts = bcdedit /enum "{current}" | Select-String "testsigning\s+Yes"
if ($ts) {
    Write-Ok "Test signing: Enabled"
    $results += $true
} else {
    Write-Fail "Test signing: Not enabled (reboot required)"
    $results += $false
}

# VS Build Tools
$vsPath = & "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe" -latest -property installationPath 2>$null
if ($vsPath) {
    Write-Ok "Visual Studio: $vsPath"
    $results += $true
} else {
    Write-Fail "Visual Studio: Not found"
    $results += $false
}

# CMake
if (Test-CommandExists "cmake") {
    Write-Ok "CMake: $(cmake --version | Select-Object -First 1)"
    $results += $true
} else {
    Write-Fail "CMake: Not found"
    $results += $false
}

# vcpkg
if (Test-Path (Join-Path $env:VCPKG_ROOT "vcpkg.exe" -ErrorAction SilentlyContinue)) {
    Write-Ok "vcpkg: $env:VCPKG_ROOT"
    $results += $true
} elseif (Test-Path "C:\vcpkg\vcpkg.exe") {
    Write-Ok "vcpkg: C:\vcpkg"
    $results += $true
} else {
    Write-Fail "vcpkg: Not found"
    $results += $false
}

# Certificate
$cert = Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Subject -like "*AkesoDLP*" }
if ($cert) {
    Write-Ok "Test certificate: $($cert.Thumbprint)"
    $results += $true
} else {
    Write-Fail "Test certificate: Not found"
    $results += $false
}

# Driver
$filterLoaded = fltmc filters 2>$null | Select-String "AkesoDLPFilter"
if ($filterLoaded) {
    Write-Ok "AkesoDLPFilter: Loaded"
    $results += $true
} else {
    Write-Warn "AkesoDLPFilter: Not loaded (may need build + reboot)"
    $results += $false
}

# Agent binary
$agentExe = Get-ChildItem -Path $RepoPath -Recurse -Filter "akeso-dlp-agent.exe" -ErrorAction SilentlyContinue | Select-Object -First 1
if ($agentExe) {
    Write-Ok "Agent binary: $($agentExe.FullName)"
    $results += $true
} else {
    Write-Warn "Agent binary: Not built yet"
    $results += $false
}

# Summary
$passed = ($results | Where-Object { $_ -eq $true }).Count
$total = $results.Count
Write-Host ""
Write-Step "Setup Complete: $passed/$total checks passed"

if ($passed -lt $total) {
    Write-Host "`n  Items to address:" -ForegroundColor Yellow
    if (-not $ts) { Write-Host "    - Reboot to enable test signing" -ForegroundColor Yellow }
    if (-not $agentExe) { Write-Host "    - Build agent: cd $AgentDir && cmake --preset=debug && cmake --build build/debug" -ForegroundColor Yellow }
    if (-not $filterLoaded) { Write-Host "    - Load driver: fltmc load AkesoDLPFilter" -ForegroundColor Yellow }
}

Write-Host "`n  Usage:" -ForegroundColor Gray
Write-Host "    Start agent:  .\build\debug\akeso-dlp-agent.exe" -ForegroundColor Gray
Write-Host "    Check driver:  fltmc filters | Select-String AkesoDLP" -ForegroundColor Gray
Write-Host "    Unload driver: fltmc unload AkesoDLPFilter" -ForegroundColor Gray
Write-Host ""
