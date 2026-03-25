@echo off
REM AkesoDLP Agent MSI Build Script (P11-T7)
REM
REM Prerequisites:
REM   - WiX Toolset v4+ installed
REM   - Agent built: cmake --build build/debug --target akeso-dlp-agent
REM   - Driver built and signed: cmake --build build/release-driver
REM
REM Usage:
REM   build.bat [server_address]
REM
REM Example:
REM   build.bat server.company.com:50051

setlocal

set BUILD_DIR=..\build\debug
set DRIVER_DIR=..\build\release-driver\driver
set SERVER_ADDRESS=%1
if "%SERVER_ADDRESS%"=="" set SERVER_ADDRESS=localhost:50051

echo.
echo === AkesoDLP Agent MSI Build ===
echo.
echo   Build dir:  %BUILD_DIR%
echo   Driver dir: %DRIVER_DIR%
echo   Server:     %SERVER_ADDRESS%
echo.

REM Generate config.yaml from template
echo server: > config.yaml.template
echo   host: "%SERVER_ADDRESS%" >> config.yaml.template
echo   port: 50051 >> config.yaml.template
echo monitoring: >> config.yaml.template
echo   clipboard: >> config.yaml.template
echo     enabled: true >> config.yaml.template
echo   browser_upload: >> config.yaml.template
echo     enabled: true >> config.yaml.template

REM Build MSI
echo Building MSI...
wix build AkesoDLP-Agent.wxs ^
  -d BuildDir=%BUILD_DIR% ^
  -d DriverDir=%DRIVER_DIR% ^
  -o AkesoDLP-Agent.msi ^
  -arch x64

if %ERRORLEVEL% neq 0 (
    echo ERROR: MSI build failed.
    exit /b 1
)

echo.
echo === MSI built successfully: AkesoDLP-Agent.msi ===
echo.
echo Install:
echo   msiexec /i AkesoDLP-Agent.msi /qn SERVER_ADDRESS="%SERVER_ADDRESS%"
echo.
echo Uninstall:
echo   msiexec /x AkesoDLP-Agent.msi /qn
echo.

REM Cleanup
del config.yaml.template 2>nul

endlocal
