<#
NOTE: #Requires -RunAsAdministrator is intentionally NOT used here because it
is ignored when the script is piped through Invoke-Expression (irm | iex).
Admin privileges are checked at runtime below, with auto-elevation fallback.
#>
<#
.SYNOPSIS
    blind.watch agent installer for Windows.
.DESCRIPTION
    Installs or upgrades the blind.watch monitoring agent as a Windows service.
.PARAMETER Token
    Agent authentication token (required for first install). Falls back to $env:BW_TOKEN.
.PARAMETER Secret
    One-time provisioning secret (required for first install). Falls back to $env:BW_SECRET.
.PARAMETER ApiUrl
    API endpoint URL. Defaults to https://api.blind.watch.
.PARAMETER Upgrade
    Upgrade an existing installation instead of fresh install.
.PARAMETER Version
    Install a specific version. Defaults to latest release.
.PARAMETER DataDir
    Data directory path. Defaults to C:\ProgramData\blindwatch.
.EXAMPLE
    .\install.ps1 -Token bw_xxx -Secret prov_xxx
.EXAMPLE
    $env:BW_TOKEN='bw_xxx'; $env:BW_SECRET='prov_xxx'; irm https://get.blind.watch/agent/windows | iex
#>
param(
    [string]$Token,
    [string]$Secret,
    [string]$ApiUrl = "https://api.blind.watch",
    [switch]$Upgrade,
    [string]$Version,
    [string]$DataDir = "C:\ProgramData\blindwatch"
)

$ErrorActionPreference = "Stop"

$Repo = "watchblind/agent.blind.watch"
$BinaryName = "blindwatch-agent.exe"
$InstallDir = "C:\Program Files\blindwatch"
$ServiceName = "BlindwatchAgent"
$Platform = "windows_amd64"

# --- Resolve token/secret from env if not provided ---
if (-not $Token) { $Token = $env:BW_TOKEN }
if (-not $Secret) { $Secret = $env:BW_SECRET }
if ($env:BW_API_URL) { $ApiUrl = $env:BW_API_URL }

# --- Admin check + auto-elevation ---
# #Requires -RunAsAdministrator doesn't work with `irm | iex`, so we check
# at runtime. If not admin, re-launch elevated with all parameters preserved.
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "[info]  Administrator privileges required — requesting elevation via UAC..." -ForegroundColor Blue

    # Save script to temp file so it can be invoked as -File with named params
    $tmpScript = Join-Path $env:TEMP "blindwatch-install-$(Get-Random).ps1"
    try {
        Invoke-WebRequest -Uri "https://get.blind.watch/agent/windows" -OutFile $tmpScript -UseBasicParsing
    } catch {
        Write-Host "[error] Could not download installer for elevation: $_" -ForegroundColor Red
        exit 1
    }

    $argList = @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "`"$tmpScript`"")
    if ($Token)   { $argList += @("-Token",   $Token) }
    if ($Secret)  { $argList += @("-Secret",  $Secret) }
    if ($ApiUrl -ne "https://api.blind.watch") { $argList += @("-ApiUrl", $ApiUrl) }
    if ($Upgrade) { $argList += "-Upgrade" }
    if ($Version) { $argList += @("-Version", $Version) }
    if ($DataDir -ne "C:\ProgramData\blindwatch") { $argList += @("-DataDir", "`"$DataDir`"") }

    try {
        Start-Process -FilePath "powershell.exe" -ArgumentList $argList -Verb RunAs -Wait
    } catch {
        Write-Host "[error] Elevation cancelled or failed. Please run from an elevated PowerShell prompt." -ForegroundColor Red
        Remove-Item $tmpScript -ErrorAction SilentlyContinue
        exit 1
    }
    Remove-Item $tmpScript -ErrorAction SilentlyContinue
    exit
}

# --- Helpers ---
function Write-Info  { param([string]$Msg) Write-Host "[info]  $Msg" -ForegroundColor Blue }
function Write-Ok    { param([string]$Msg) Write-Host "[ok]    $Msg" -ForegroundColor Green }
function Write-Warn  { param([string]$Msg) Write-Host "[warn]  $Msg" -ForegroundColor Yellow }
function Write-Fatal { param([string]$Msg) Write-Host "[error] $Msg" -ForegroundColor Red; exit 1 }

# --- Resolve version ---
function Resolve-AgentVersion {
    if ($Version) { return $Version }

    Write-Info "Fetching latest version..."
    try {
        $resp = Invoke-RestMethod -Uri "https://api.github.com/repos/$Repo/releases/latest" `
            -Headers @{ Accept = "application/vnd.github+json"; "User-Agent" = "blind.watch-installer" }
        return $resp.tag_name
    } catch {
        # Fallback to get.blind.watch
        try {
            $resp = Invoke-RestMethod -Uri "https://get.blind.watch/agent/version"
            return $resp.version
        } catch {
            Write-Fatal "Could not determine latest version. Use -Version to specify."
        }
    }
}

# --- Download and verify ---
function Get-AgentBinary {
    param([string]$Ver)

    $tag = $Ver
    $archiveName = "blindwatch-agent_$($Ver.TrimStart('v'))_${Platform}.zip"
    $tmpDir = Join-Path ([System.IO.Path]::GetTempPath()) "blindwatch-install-$(Get-Random)"
    New-Item -ItemType Directory -Path $tmpDir -Force | Out-Null

    $archivePath = Join-Path $tmpDir $archiveName
    $checksumsPath = Join-Path $tmpDir "checksums.txt"

    Write-Info "Downloading $archiveName..."
    $baseUrl = "https://github.com/$Repo/releases/download/$tag"
    try {
        Invoke-WebRequest -Uri "$baseUrl/$archiveName" -OutFile $archivePath -UseBasicParsing
    } catch {
        Write-Fatal "Download failed: $archiveName"
    }

    Write-Info "Downloading checksums..."
    try {
        Invoke-WebRequest -Uri "$baseUrl/checksums.txt" -OutFile $checksumsPath -UseBasicParsing
    } catch {
        Write-Fatal "Checksums download failed"
    }

    # Verify checksum
    Write-Info "Verifying SHA-256 checksum..."
    $expected = (Get-Content $checksumsPath | Where-Object { $_ -match $archiveName }) -replace '\s+.*$', ''
    if (-not $expected) {
        Write-Fatal "Archive not found in checksums file"
    }

    $actual = (Get-FileHash -Path $archivePath -Algorithm SHA256).Hash.ToLower()
    if ($expected -ne $actual) {
        Write-Fatal "Checksum mismatch!`n  Expected: $expected`n  Actual:   $actual"
    }
    Write-Ok "Checksum verified"

    # Extract binary
    Write-Info "Extracting binary..."
    Expand-Archive -Path $archivePath -DestinationPath $tmpDir -Force

    $binaryPath = Join-Path $tmpDir $BinaryName
    if (-not (Test-Path $binaryPath)) {
        Write-Fatal "Binary not found in archive"
    }

    return @{ BinaryPath = $binaryPath; TmpDir = $tmpDir }
}

# --- Install binary ---
function Install-AgentBinary {
    param([string]$BinaryPath)

    if ($Upgrade) {
        Write-Info "Stopping $ServiceName..."
        Stop-Service -Name $ServiceName -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2
    }

    if (-not (Test-Path $InstallDir)) {
        New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    }

    Write-Info "Installing binary to $InstallDir\$BinaryName..."
    Copy-Item -Path $BinaryPath -Destination (Join-Path $InstallDir $BinaryName) -Force
    Write-Ok "Binary installed"
}

# --- Create data directory ---
function New-DataDirectory {
    if (-not (Test-Path $DataDir)) {
        Write-Info "Creating data directory: $DataDir"
        New-Item -ItemType Directory -Path $DataDir -Force | Out-Null
        New-Item -ItemType Directory -Path (Join-Path $DataDir "wal") -Force | Out-Null
        Write-Ok "Data directory ready"
    }
}

# --- Install Windows Service ---
function Install-AgentService {
    $binaryFullPath = Join-Path $InstallDir $BinaryName
    $existingService = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue

    if ($existingService -and $Upgrade) {
        Write-Info "Service already exists, skipping service creation"
        return
    }

    if ($existingService) {
        Write-Warn "Service $ServiceName already exists"
        return
    }

    Write-Info "Installing Windows service: $ServiceName..."
    $binPath = "`"$binaryFullPath`" --data-dir `"$DataDir`" --wal-dir `"$DataDir\wal`""
    New-Service -Name $ServiceName `
        -BinaryPathName $binPath `
        -DisplayName "blind.watch Agent" `
        -Description "blind.watch monitoring agent — encrypted infrastructure monitoring" `
        -StartupType Automatic | Out-Null

    # Configure service recovery: restart on failure
    & sc.exe failure $ServiceName reset= 86400 actions= restart/10000/restart/10000/restart/30000 | Out-Null

    Write-Ok "Windows service installed"
}

# --- First boot provisioning ---
function Invoke-FirstBoot {
    $stateFile = Join-Path $DataDir "state.json"
    if (Test-Path $stateFile) {
        Write-Info "Agent already provisioned, skipping first boot"
        return
    }

    if (-not $Token -or -not $Secret) {
        Write-Fatal "Token and secret are required for first install. Use -Token and -Secret parameters."
    }

    Write-Info "Running first-boot provisioning..."
    $binaryFullPath = Join-Path $InstallDir $BinaryName

    $env:BW_TOKEN = $Token
    $env:BW_SECRET = $Secret
    $env:BW_API_URL = $ApiUrl

    & $binaryFullPath --first-boot --data-dir $DataDir --wal-dir "$DataDir\wal"
    if ($LASTEXITCODE -ne 0) {
        Write-Fatal "First-boot provisioning failed"
    }

    # Clear sensitive env vars
    Remove-Item Env:\BW_TOKEN -ErrorAction SilentlyContinue
    Remove-Item Env:\BW_SECRET -ErrorAction SilentlyContinue

    Write-Ok "Provisioning complete"
}

# --- Install upgrade helper ---
function Install-UpgradeHelper {
    Write-Info "Installing upgrade helper..."
    $upgradeScript = @'
param([Parameter(Mandatory)][string]$Version)
if ($Version -notmatch '^v?\d+\.\d+\.\d+') { throw "Invalid version: $Version" }
$script = Invoke-RestMethod -Uri "https://get.blind.watch/agent/windows"
Invoke-Expression "& { $script } -Upgrade -Version $Version"
'@
    $upgradeScript | Set-Content -Path (Join-Path $InstallDir "upgrade.ps1") -Encoding UTF8 -Force
    Write-Ok "Upgrade helper installed"
}

# --- Start service ---
function Start-AgentService {
    Write-Info "Starting $ServiceName..."
    Start-Service -Name $ServiceName

    Start-Sleep -Seconds 2
    $svc = Get-Service -Name $ServiceName
    if ($svc.Status -eq "Running") {
        Write-Ok "Agent is running"
    } else {
        Write-Fatal "Agent failed to start. Check Event Viewer for details."
    }
}

# --- Main ---
function Main {
    Write-Host ""
    Write-Host "  blind.watch agent installer (Windows)"
    Write-Host "  ======================================"
    Write-Host ""

    $ver = Resolve-AgentVersion
    Write-Info "Version: $ver"

    $result = Get-AgentBinary -Ver $ver
    Install-AgentBinary -BinaryPath $result.BinaryPath
    New-DataDirectory
    Install-AgentService
    Install-UpgradeHelper

    if (-not $Upgrade) {
        Invoke-FirstBoot
    }

    Start-AgentService

    Write-Host ""
    Write-Ok "blind.watch agent $ver installed and running"
    Write-Host ""
    Write-Host "  Status:  Get-Service $ServiceName"
    Write-Host "  Logs:    Get-EventLog -LogName Application -Source $ServiceName"
    Write-Host "  Version: & '$InstallDir\$BinaryName' --version"
    Write-Host ""

    # Cleanup
    if (Test-Path $result.TmpDir) {
        Remove-Item -Path $result.TmpDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Main
