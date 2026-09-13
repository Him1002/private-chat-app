# ==============================================================================
# ChatSpic Production Startup Script (Windows PowerShell)
# S5-T09: Supported single-instance production server startup
# ==============================================================================
# Architecture notes:
# - Uses '--workers 1' because ChatSpic maintains in-process state:
#   * In-memory WebSocket connection rooms and presence ('rooms', 'online_users')
#   * In-memory sliding window rate limiters (login/registration)
#   * SQLite file-based write concurrency
# - Omits '--reload' mode to prevent unnecessary file watcher overhead and crashes.
# ==============================================================================

[CmdletBinding()]
param(
    [string]$HostAddress = "0.0.0.0",
    [int]$Port = 8000
)

$ErrorActionPreference = "Stop"

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "Starting ChatSpic in Production Mode" -ForegroundColor Cyan
Write-Host "Architecture: Single-Instance, Single-Worker, SQLite, Windows" -ForegroundColor Gray
Write-Host "============================================================" -ForegroundColor Cyan

# Locate Python interpreter (prefer virtual environment if present)
$pythonExe = "python"
if (Test-Path ".\chatapp\Scripts\python.exe") {
    $pythonExe = ".\chatapp\Scripts\python.exe"
    Write-Host "Using virtual environment interpreter: $pythonExe" -ForegroundColor Green
} elseif (Test-Path ".\.venv\Scripts\python.exe") {
    $pythonExe = ".\.venv\Scripts\python.exe"
    Write-Host "Using virtual environment interpreter: $pythonExe" -ForegroundColor Green
} else {
    Write-Host "Using system PATH Python interpreter: $pythonExe" -ForegroundColor Yellow
}

# Verify Python runs and check environment
Write-Host "Verifying environment and configuration..." -ForegroundColor Gray
& $pythonExe -c "from backend.core.config import settings; print(f'Environment: {settings.ENVIRONMENT}, Database: {settings.DATABASE_URL}')"
if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: Configuration validation failed. Aborting startup." -ForegroundColor Red
    exit 1
}

# Supported production startup command:
# Single worker (--workers 1), no reload mode
Write-Host "Starting Uvicorn server on http://${HostAddress}:${Port} (--workers 1)..." -ForegroundColor Green
& $pythonExe -m uvicorn main:app --host $HostAddress --port $Port --workers 1
