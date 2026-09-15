$ErrorActionPreference = "Stop"

Write-Host "Running backend linting (Ruff)..."
& .venv\Scripts\ruff.exe check backend/

Write-Host "Running backend type checking (Mypy)..."
& .venv\Scripts\mypy.exe backend/

Write-Host "Running frontend linting (ESLint)..."
Push-Location frontend
try {
    npm run lint
} finally {
    Pop-Location
}

Write-Host "All checks passed!"
