@echo off
echo Starting AihaX Development Environment...
echo.

set AIHAX_REPORTS=%USERPROFILE%\AihaX\Reports
set AIHAX_DB=%USERPROFILE%\AihaX\db
set AIHAX_CONFIG=%USERPROFILE%\AihaX\config

echo [1/3] Starting Docker backend...
cd /d "%~dp0docker"
docker-compose up -d --build
if errorlevel 1 (
    echo ERROR: Docker failed to start. Is Docker Desktop running?
    pause
    exit /b 1
)

echo [2/3] Waiting for backend health check...
:wait_loop
timeout /t 2 /nobreak >nul
curl -s http://localhost:8000/api/health | findstr "ok" >nul
if errorlevel 1 goto wait_loop

echo [3/3] Starting frontend dev server...
cd /d "%~dp0frontend"
start "AihaX Frontend" cmd /k "npm run dev"

echo.
echo AihaX is ready!
echo   Backend:  http://localhost:8000
echo   Frontend: http://localhost:3000
echo.
pause
