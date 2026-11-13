param([string]$Opa = "opa", [string]$Python = "python")
$ErrorActionPreference = "Stop"
$projectRoot = Split-Path $PSScriptRoot -Parent
Set-Location -LiteralPath $projectRoot
if (Get-NetTCPConnection -State Listen -LocalPort 8181,8000,8501 -ErrorAction SilentlyContinue) {
    throw 'A demo port is already occupied. Stop the existing demo before starting another copy.'
}
$null = Get-Command $Opa -ErrorAction Stop
$null = Get-Command $Python -ErrorAction Stop
& $Python scripts/seed_data.py
if ($LASTEXITCODE -ne 0) { throw 'Synthetic data publication failed.' }
$env:SIMULATION_MODE = "1"
$env:DEV_FAILURES = "1"
$env:OPA_URL = "http://127.0.0.1:8181"
$env:API_URL = "http://127.0.0.1:8000"
$processRecords = @()
$specifications = @(
    @{ Name='opa'; File=$Opa; Arguments=@('run','--server','--addr=127.0.0.1:8181','--log-level=error','policies/engine.rego') },
    @{ Name='api'; File=$Python; Arguments=@('-m','uvicorn','app.api:app','--host','127.0.0.1','--port','8000') },
    @{ Name='ui'; File=$Python; Arguments=@('-m','streamlit','run','ui/streamlit_app.py','--server.address=127.0.0.1','--server.port=8501','--server.headless=true','--browser.gatherUsageStats=false') }
)
try {
foreach ($specification in $specifications) {
    $process = Start-Process -FilePath $specification.File -ArgumentList $specification.Arguments -WorkingDirectory $projectRoot -WindowStyle Hidden -PassThru -RedirectStandardOutput ($specification.Name + '.log') -RedirectStandardError ($specification.Name + '-error.log')
    $processRecords += @{ Id=$process.Id; Started=$process.StartTime.ToUniversalTime().ToString('o'); Name=$specification.Name }
    $processRecords | ConvertTo-Json | Set-Content -LiteralPath '.pids.json'
}
$ready = $false
for ($attempt = 0; $attempt -lt 60; $attempt++) {
    try {
        $apiHealth = Invoke-RestMethod 'http://127.0.0.1:8000/health' -TimeoutSec 1
        $uiHealth = Invoke-RestMethod 'http://127.0.0.1:8501/_stcore/health' -TimeoutSec 1
        if ($apiHealth.opa_ready -and $uiHealth -eq 'ok') { $ready = $true; break }
    } catch { }
    Start-Sleep -Milliseconds 200
}
if (-not $ready) { throw 'Startup health checks failed. Inspect the component error logs.' }
Write-Output 'Ready: http://127.0.0.1:8501. Run scripts/stop.ps1 to stop.'
} catch {
    & (Join-Path $PSScriptRoot 'stop.ps1')
    throw
}
