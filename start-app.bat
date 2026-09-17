@echo off
setlocal

rem Start the PNCAI backend and Angular frontend in separate windows.
set "ROOT=%~dp0"
set "BACKEND=%ROOT%backend"
set "FRONTEND=%ROOT%frontend"

if not exist "%BACKEND%\app\main.py" (
    echo Backend entry point not found: "%BACKEND%\app\main.py"
    pause
    exit /b 1
)

if not exist "%FRONTEND%\package.json" (
    echo Frontend package file not found: "%FRONTEND%\package.json"
    pause
    exit /b 1
)

if not exist "%FRONTEND%\node_modules\.bin\ng.cmd" (
    echo Angular dependencies are not installed.
    echo Run: cd /d "%FRONTEND%" ^&^& npm install
    pause
    exit /b 1
)

powershell -NoProfile -Command "$ports = @(4200, 8000); $busy = $ports | ForEach-Object { if (Get-NetTCPConnection -LocalPort $_ -State Listen -ErrorAction SilentlyContinue) { $_ } }; if ($busy) { Write-Host ('Port(s) already in use: ' + ($busy -join ', ')); exit 1 }"
if errorlevel 1 (
    echo Stop the process using port 4200 or 8000, then run this launcher again.
    pause
    exit /b 1
)

where python >nul 2>&1
if errorlevel 1 (
    echo Python was not found on PATH.
    pause
    exit /b 1
)

where npm >nul 2>&1
if errorlevel 1 (
    echo npm was not found on PATH.
    pause
    exit /b 1
)

start "PNCAI Backend" cmd /k "cd /d "%BACKEND%" && set APP_ENV=local&& set DEMO_DATA_ENABLED=true&& set ENABLE_EXTERNAL_INTEGRATIONS=false&& python -m uvicorn app.main:app --reload --host 0.0.0.0 --port 8000"
start "PNCAI Frontend" cmd /k "cd /d "%FRONTEND%" && npm start"

echo PNCAI application started.
echo Backend:  http://localhost:8000
echo Frontend: http://localhost:4200
endlocal