$ErrorActionPreference = "Stop"
$projectRoot = Split-Path $PSScriptRoot -Parent
$pidFile = Join-Path $projectRoot '.pids.json'
function Stop-DemoProcessTree([int]$ProcessId, [datetime]$Started) {
    $process = Get-Process -Id $ProcessId -ErrorAction SilentlyContinue
    if (-not $process -or $process.StartTime.ToUniversalTime().Ticks -ne $Started.ToUniversalTime().Ticks) { return }
    # Windows virtual-environment launchers can own a second Python process.
    $children = Get-CimInstance Win32_Process -Filter "ParentProcessId=$ProcessId"
    foreach ($child in $children) {
        $childProcess = Get-Process -Id $child.ProcessId -ErrorAction SilentlyContinue
        if ($childProcess -and $childProcess.StartTime -ge $process.StartTime) {
            Stop-DemoProcessTree $childProcess.Id $childProcess.StartTime
        }
    }
    $current = Get-Process -Id $ProcessId -ErrorAction SilentlyContinue
    if ($current -and $current.StartTime.ToUniversalTime().Ticks -eq $Started.ToUniversalTime().Ticks) {
        Stop-Process -Id $ProcessId
    }
}
if (Test-Path -LiteralPath $pidFile) {
    $processRecords = Get-Content -LiteralPath $pidFile -Raw | ConvertFrom-Json
    foreach ($record in $processRecords) {
        $process = Get-Process -Id $record.Id -ErrorAction SilentlyContinue
        # A reused PID must never stop an unrelated later process.
        if ($process -and $process.StartTime.ToUniversalTime().Ticks -eq ([datetime]$record.Started).ToUniversalTime().Ticks) {
            Stop-DemoProcessTree $record.Id $record.Started
        }
    }
    Remove-Item -LiteralPath $pidFile
}
