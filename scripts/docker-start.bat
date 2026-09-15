@echo off
echo ========================================
echo   AihaX - Docker Only (no Node.js needed)
echo ========================================
echo.

set AIHAX_REPORTS=%USERPROFILE%\AihaX\Reports
set AIHAX_DB=%USERPROFILE%\AihaX\db
set AIHAX_CONFIG=%USERPROFILE%\AihaX\config

if not exist "%AIHAX_REPORTS%" mkdir "%AIHAX_REPORTS%"
if not exist "%AIHAX_DB%" mkdir "%AIHAX_DB%"
if not exist "%AIHAX_CONFIG%" mkdir "%AIHAX_CONFIG%"

cd /d "%~dp0..\docker"

echo Starting Redis + Backend + Frontend...
docker compose up -d --build

if errorlevel 1 (
    echo.
    echo ERROR: docker compose failed.
    echo Make sure Docker Desktop is running.
    pause
    exit /b 1
)

echo.
echo Waiting for backend...
:wait_backend
timeout /t 3 /nobreak >nul
docker compose exec -T backend curl -sf http://localhost:8000/api/health >nul 2>&1
if errorlevel 1 goto wait_backend

echo.
echo ========================================
echo   AihaX is ready!
echo   UI:      http://localhost:3000
echo   API:     http://localhost:8000
echo ========================================
echo.
echo Open http://localhost:3000 in your browser.
echo First scan target: https://demo.testfire.net
echo.
pause
