<#
.SYNOPSIS
    Local end-to-end test for the Windows install flow.
.DESCRIPTION
    Builds the agent locally, runs mockapi + provision in background,
    invokes scripts/install.ps1 with -LocalBinary against localhost,
    and verifies the BlindwatchAgent service reaches the Running state.
    Cleans up at the end. MUST be run from elevated PowerShell.
.NOTES
    Run as Administrator. The script registers a real Windows service
    named BlindwatchAgent and removes it again at the end.
#>

[CmdletBinding()]
param(
    [int]$ApiPort = 19800,
    [switch]$KeepInstalled
)

$ErrorActionPreference = 'Stop'

# --- Admin guard ---
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    throw "This script must be run from an elevated (Administrator) PowerShell session."
}

$RepoRoot   = Split-Path -Parent $PSScriptRoot
$BinaryPath = Join-Path $env:TEMP 'blindwatch-agent-test.exe'
$ServiceName = 'BlindwatchAgent'
$ApiUrl     = "http://localhost:$ApiPort"

function Step($msg) { Write-Host "==> $msg" -ForegroundColor Cyan }
function Pass($msg) { Write-Host "[PASS] $msg" -ForegroundColor Green }
function Fail($msg) { Write-Host "[FAIL] $msg" -ForegroundColor Red; throw $msg }

# --- Pre-flight: clear any leftover service from previous run ---
$existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($existing) {
    Step "Removing stale service from previous run"
    Stop-Service $ServiceName -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 1
    & sc.exe delete $ServiceName | Out-Null
    Start-Sleep -Seconds 1
}

if (Test-Path 'C:\ProgramData\blindwatch\state.json') {
    Step "Removing stale data dir state from previous run"
    Remove-Item 'C:\ProgramData\blindwatch' -Recurse -Force -ErrorAction SilentlyContinue
}

$mockapiJob   = $null
$provisionLog = Join-Path $env:TEMP 'bw-provision.log'

try {
    # --- Build agent ---
    Step "Building agent binary"
    Push-Location $RepoRoot
    try {
        & go build -o $BinaryPath ./cmd/agent
        if ($LASTEXITCODE -ne 0) { Fail "go build failed" }
    } finally { Pop-Location }
    Pass "Built $BinaryPath"

    # --- Start mockapi ---
    Step "Starting mockapi on :$ApiPort"
    $mockapiJob = Start-Job -Name bw-mockapi -ScriptBlock {
        param($repo, $port)
        Set-Location $repo
        & go run ./cmd/mockapi --addr ":$port" 2>&1
    } -ArgumentList $RepoRoot, $ApiPort

    # Poll for readiness
    $ready = $false
    for ($i = 0; $i -lt 30; $i++) {
        Start-Sleep -Milliseconds 500
        try {
            $r = Invoke-RestMethod "$ApiUrl/status" -TimeoutSec 1 -ErrorAction Stop
            if ($r) { $ready = $true; break }
        } catch { }
    }
    if (-not $ready) {
        Receive-Job $mockapiJob | Write-Host
        Fail "mockapi did not become ready"
    }
    Pass "mockapi ready at $ApiUrl"

    # --- Provision a test agent ---
    Step "Provisioning a test agent"
    Push-Location $RepoRoot
    try {
        $provOut = & go run ./cmd/provision --api $ApiUrl --agent-name win-svc-test 2>&1
        $provOut | Out-File -FilePath $provisionLog -Encoding UTF8
    } finally { Pop-Location }

    $tokLine = $provOut | Where-Object { $_ -match '^export BW_TOKEN=' } | Select-Object -First 1
    $secLine = $provOut | Where-Object { $_ -match '^export BW_SECRET=' } | Select-Object -First 1
    if (-not $tokLine -or -not $secLine) {
        $provOut | Write-Host
        Fail "Could not extract token/secret from provision output"
    }
    $token  = ($tokLine -replace '^export BW_TOKEN=','').Trim()
    $secret = ($secLine -replace '^export BW_SECRET=','').Trim()
    Pass "Provisioned agent (token=$($token.Substring(0,12))...)"

    # --- Run install.ps1 ---
    Step "Invoking install.ps1 -LocalBinary against $ApiUrl"
    $installScript = Join-Path $PSScriptRoot 'install.ps1'
    & $installScript -Token $token -Secret $secret -ApiUrl $ApiUrl `
        -LocalBinary $BinaryPath -Version 'v0.0.0-local'
    if ($LASTEXITCODE -ne 0 -and $null -ne $LASTEXITCODE) {
        # install.ps1 uses Write-Fatal which calls exit 1; if we get here without
        # throwing, $LASTEXITCODE may have been set by an inner native command.
    }

    # --- Verify service is Running ---
    Step "Verifying service state"
    $svc = Get-Service -Name $ServiceName -ErrorAction Stop
    if ($svc.Status -ne 'Running') {
        Get-Content 'C:\ProgramData\blindwatch\agent.log' -Tail 30 -ErrorAction SilentlyContinue
        Fail "Service status is '$($svc.Status)', expected 'Running'"
    }
    Pass "Service $ServiceName is Running"

    # --- Verify connection to mockapi (agent should appear in /status) ---
    Step "Verifying agent connected to mockapi"
    $connected = $false
    for ($i = 0; $i -lt 20; $i++) {
        Start-Sleep -Milliseconds 500
        $st = Invoke-RestMethod "$ApiUrl/status" -ErrorAction SilentlyContinue
        if ($st.connected_agents -and $st.connected_agents.Count -gt 0) { $connected = $true; break }
    }
    if (-not $connected) {
        Get-Content 'C:\ProgramData\blindwatch\agent.log' -Tail 50 -ErrorAction SilentlyContinue | Write-Host
        Fail "Agent did not register with mockapi within 10s"
    }
    Pass "Agent connected to mockapi"

    # --- Verify Stop works ---
    Step "Stopping service to verify SCM Stop handler"
    Stop-Service -Name $ServiceName -ErrorAction Stop
    Start-Sleep -Seconds 2
    $svc = Get-Service -Name $ServiceName
    if ($svc.Status -ne 'Stopped') {
        Fail "Service did not stop cleanly (status=$($svc.Status))"
    }
    Pass "Service stopped cleanly"

    Write-Host ""
    Write-Host "  ALL CHECKS PASSED" -ForegroundColor Green
    Write-Host ""
    Write-Host "  Recent agent.log tail:" -ForegroundColor DarkGray
    Get-Content 'C:\ProgramData\blindwatch\agent.log' -Tail 15 -ErrorAction SilentlyContinue |
        ForEach-Object { Write-Host "    $_" -ForegroundColor DarkGray }
}
finally {
    if (-not $KeepInstalled) {
        Step "Cleanup"
        if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
            Stop-Service $ServiceName -Force -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 1
            & sc.exe delete $ServiceName | Out-Null
        }
        Remove-Item 'C:\Program Files\blindwatch' -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item 'C:\ProgramData\blindwatch' -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item $BinaryPath -Force -ErrorAction SilentlyContinue
    }

    if ($mockapiJob) {
        Stop-Job $mockapiJob -ErrorAction SilentlyContinue
        Remove-Job $mockapiJob -Force -ErrorAction SilentlyContinue
    }
}
