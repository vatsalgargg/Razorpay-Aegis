# Razorpay AI Risk Manager — Windows One-Command Launcher
# Usage: .\run.ps1
# Optional: .\run.ps1 -Mode attack
# Optional: .\run.ps1 -KillLLM
# Optional: .\run.ps1 -TestOnly
# Optional: .\run.ps1 -EvalOnly

param(
    [string]$Mode = "both",
    [switch]$KillLLM,
    [switch]$EvalOnly,
    [switch]$TestOnly
)

$ErrorActionPreference = "Stop"

Write-Host ""
Write-Host "========================================================" -ForegroundColor Cyan
Write-Host "     Razorpay AI Risk Manager - Starting Up            " -ForegroundColor Cyan
Write-Host "========================================================" -ForegroundColor Cyan
Write-Host ""

# Load .env
if (Test-Path ".env") {
    Get-Content ".env" | Where-Object { $_ -match "^[^#].*=.*" } | ForEach-Object {
        $parts = $_ -split "=", 2
        [System.Environment]::SetEnvironmentVariable($parts[0].Trim(), $parts[1].Trim(), "Process")
    }
}

if ($KillLLM) {
    $env:FORCE_LLM_TIMEOUT = "true"
    Write-Host "[demo] FORCE_LLM_TIMEOUT=true - LLM will timeout, fallback will fire." -ForegroundColor Magenta
}

# --- Tests only ---
if ($TestOnly) {
    Write-Host "[test] Running pytest..." -ForegroundColor Green
    python -m pytest tests/ -v --tb=short
    exit $LASTEXITCODE
}

# --- Eval only ---
if ($EvalOnly) {
    Write-Host "[eval] Running held-out evaluation..." -ForegroundColor Green
    python -m evaluation.evaluate
    exit $LASTEXITCODE
}

# --- 1. Seed DB & Train Baseline ---
Write-Host "[1/4] Seeding database and baseline model..." -ForegroundColor Green
python -m data.seed_db
python -c "from api.main import _train_detector; _train_detector()"

# --- 2. Start API server in background ---
Write-Host "[2/4] Starting FastAPI server (port 8000)..." -ForegroundColor Green
$serverProc = Start-Process python -ArgumentList "-m uvicorn api.main:app --host 0.0.0.0 --port 8000" -WorkingDirectory $PWD -PassThru -WindowStyle Hidden

# Wait for server ready
Write-Host "[2/4] Waiting for server..." -ForegroundColor Yellow
$ready = $false
for ($i = 0; $i -lt 20; $i++) {
    Start-Sleep -Seconds 1
    try {
        $r = Invoke-RestMethod -Uri "http://127.0.0.1:8000/health" -TimeoutSec 2 -ErrorAction Stop
        if ($r.status -eq "ok") { $ready = $true; break }
    } catch {
        # Fallback to curl.exe if available
        $curlOut = curl.exe -s http://127.0.0.1:8000/health 2>$null
        if ($curlOut -match "ok") { $ready = $true; break }
    }
}

if (-not $ready) {
    Write-Host "[ERROR] Server did not respond. Check uvicorn." -ForegroundColor Red
    Stop-Process -Id $serverProc.Id -Force -ErrorAction SilentlyContinue
    exit 1
}
Write-Host "[2/4] Server ready [OK]" -ForegroundColor Green

# --- 3. Run simulator ---
Write-Host "[3/4] Running transaction stream (mode=$Mode)..." -ForegroundColor Green
if ($KillLLM) {
    python -m api.simulator --mode $Mode --kill-llm --speed 120
} else {
    python -m api.simulator --mode $Mode --speed 120
}

# --- 4. Evaluation ---
Write-Host ""
Write-Host "[4/4] Running held-out evaluation..." -ForegroundColor Green
python -m evaluation.evaluate

# --- Done ---
Write-Host ""
Write-Host "[OK] Complete. Server PID=$($serverProc.Id) active on http://localhost:8000" -ForegroundColor Cyan
Write-Host "     Live CLI Dashboard: python -m dashboard.cli" -ForegroundColor Cyan
Write-Host "     Audit Trail API:    http://localhost:8000/audit" -ForegroundColor Cyan
Write-Host "     Metrics API:        http://localhost:8000/metrics" -ForegroundColor Cyan
