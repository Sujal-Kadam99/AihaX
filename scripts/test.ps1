$ErrorActionPreference = "Stop"

Write-Host "Running backend tests..."
& .venv\Scripts\python.exe -m pytest backend/tests/ $args
