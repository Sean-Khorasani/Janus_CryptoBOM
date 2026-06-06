@echo off
setlocal

set "PROJECT_ROOT=%~dp0"
set "PROJECT_ROOT=%PROJECT_ROOT:~0,-1%"

:: Configure internal toolchains
set "CARGO_HOME=%PROJECT_ROOT%\.tools\cargo"
set "RUSTUP_HOME=%PROJECT_ROOT%\.tools\rustup"
set "PATH=%PROJECT_ROOT%\.tools\cargo\bin;%PROJECT_ROOT%\.tools\go\bin;%PATH%"

:: Ensure bin directory exists
if not exist "%PROJECT_ROOT%\bin" mkdir "%PROJECT_ROOT%\bin"

if "%~1"=="" goto usage

:loop
if "%~1"=="" goto end
if /i "%~1"=="clean" call :clean
if /i "%~1"=="build" call :build
if /i "%~1"=="all" (
    call :clean
    call :build
)
shift
goto loop

:clean
echo ========================================
echo Cleaning Project...
echo ========================================

echo [1/4] Cleaning Agent...
cd "%PROJECT_ROOT%\agent"
cargo clean

echo [2/4] Cleaning Server...
cd "%PROJECT_ROOT%\server"
go clean

echo [3/4] Cleaning UI...
cd "%PROJECT_ROOT%\ui"
if exist "dist" rmdir /s /q dist

echo [4/4] Cleaning Binaries...
if exist "%PROJECT_ROOT%\bin\janus-agent.exe" del /q "%PROJECT_ROOT%\bin\janus-agent.exe"
if exist "%PROJECT_ROOT%\bin\janus-server.exe" del /q "%PROJECT_ROOT%\bin\janus-server.exe"
if exist "%PROJECT_ROOT%\bin\janus_interceptor.dll" del /q "%PROJECT_ROOT%\bin\janus_interceptor.dll"
if exist "%PROJECT_ROOT%\bin\janus-cli.exe" del /q "%PROJECT_ROOT%\bin\janus-cli.exe"

cd "%PROJECT_ROOT%"
goto :EOF

:build
echo ========================================
echo Building Project...
echo ========================================

echo [1/3] Building Agent (Rust)...
cd "%PROJECT_ROOT%\agent"
cargo build --release
if errorlevel 1 (
    echo Agent build failed!
    exit /b 1
)
copy /Y target\release\janus-agent.exe "%PROJECT_ROOT%\bin\" 
copy /Y target\release\janus_interceptor.dll "%PROJECT_ROOT%\bin\"
copy /Y target\release\janus-agent.exe "%PROJECT_ROOT%\bin\janus-cli.exe" 

echo [2/3] Building Server (Go)...
cd "%PROJECT_ROOT%\server"
go build -o "%PROJECT_ROOT%\bin\janus-server.exe" ./cmd/janus-server
if errorlevel 1 (
    echo Server build failed!
    exit /b 1
)

echo [3/3] Building UI (Node/Vite)...
cd "%PROJECT_ROOT%\ui"
call npm run build
if errorlevel 1 (
    echo UI build failed!
    exit /b 1
)

echo.
echo ========================================
echo Build complete! Executables are in the \bin directory.
echo ========================================
cd "%PROJECT_ROOT%"
goto :EOF

:usage
echo Usage: build.bat [clean] [build] [all]
echo.
echo Commands:
echo   clean        Removes all built artifacts and binaries.
echo   build        Compiles the Agent, Server, and UI.
echo   all          Equivalent to running "clean build".
echo.
echo Example: build.bat clean build
goto end

:end
endlocal
