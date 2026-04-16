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
.PARAMETER ProvisionFile
    Path to a JSON provisioning file (token, provisioning_secret, api_url).
    Used internally during UAC elevation to avoid leaking secrets via the
    process command line. May also be supplied directly.
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
    [string]$DataDir = "C:\ProgramData\blindwatch",
    [string]$ProvisionFile,
    [string]$InstallerUrl = "https://get.blind.watch/agent/windows",
    # Testing escape hatch: install this local .exe instead of downloading
    # from GitHub releases. Skips checksum verification. Do not use in production.
    [string]$LocalBinary
)

$ErrorActionPreference = "Stop"

$Repo = "watchblind/agent.blind.watch"
$BinaryName = "blindwatch-agent.exe"
$InstallDir = "C:\Program Files\blindwatch"
$ServiceName = "BlindwatchAgent"
$Platform = "windows_amd64"

# --- Resolve token/secret from env if not provided ---
if (-not $Token)         { $Token = $env:BW_TOKEN }
if (-not $Secret)        { $Secret = $env:BW_SECRET }
if (-not $ProvisionFile) { $ProvisionFile = $env:BW_PROVISION_FILE }
if ($env:BW_API_URL)     { $ApiUrl = $env:BW_API_URL }

# --- If a provision file is supplied, hydrate Token/Secret/ApiUrl from it ---
if ($ProvisionFile -and (Test-Path $ProvisionFile)) {
    try {
        $pf = Get-Content -Raw $ProvisionFile | ConvertFrom-Json
        if (-not $Token  -and $pf.token)               { $Token  = $pf.token }
        if (-not $Secret -and $pf.provisioning_secret) { $Secret = $pf.provisioning_secret }
        if ($pf.api_url) { $ApiUrl = $pf.api_url }
    } catch {
        Write-Host "[error] Failed to read provision file ${ProvisionFile}: $_" -ForegroundColor Red
        exit 1
    }
}

# --- Helpers (defined early so the elevation path can call them) ---
function Write-Info  { param([string]$Msg) Write-Host "[info]  $Msg" -ForegroundColor Blue }
function Write-Ok    { param([string]$Msg) Write-Host "[ok]    $Msg" -ForegroundColor Green }
function Write-Warn  { param([string]$Msg) Write-Host "[warn]  $Msg" -ForegroundColor Yellow }
function Write-Fatal { param([string]$Msg) Write-Host "[error] $Msg" -ForegroundColor Red; exit 1 }

# Write text as UTF-8 without a BOM. Windows PowerShell 5's
# `Set-Content -Encoding UTF8` prepends EF BB BF, which Go's encoding/json
# rejects. This helper avoids that across PS 5 and 7.
function Write-Utf8NoBom {
    param([string]$Path, [string]$Content)
    $enc = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($Path, $Content, $enc)
}

# Write a transient provision JSON file readable only by the current user
# (and Administrators / SYSTEM by inheritance). Returns the file path.
function New-TransientProvisionFile {
    param([string]$Tok, [string]$Sec, [string]$Api)

    $path = Join-Path $env:TEMP ("bw-prov-{0}.json" -f ([guid]::NewGuid().ToString('N')))

    $data = @{
        token               = $Tok
        provisioning_secret = $Sec
        api_url             = $Api
    } | ConvertTo-Json -Compress

    # Create the file with no inherited ACEs, then add the current user only
    Write-Utf8NoBom -Path $path -Content $data

    try {
        $acl = Get-Acl $path
        $acl.SetAccessRuleProtection($true, $false)  # disable inheritance, drop existing
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            [System.Security.Principal.WindowsIdentity]::GetCurrent().Name,
            'FullControl', 'Allow')
        $acl.AddAccessRule($rule)
        # Administrators must also be able to read after elevation in case the
        # current user is a standard account being elevated to a different admin.
        $admins = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')
        $adminRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            $admins, 'FullControl', 'Allow')
        $acl.AddAccessRule($adminRule)
        Set-Acl -Path $path -AclObject $acl
    } catch {
        Write-Warn "Could not tighten ACL on provision file: $_"
    }

    return $path
}

# --- Admin check + auto-elevation ---
# #Requires -RunAsAdministrator doesn't work with `irm | iex`, so we check
# at runtime. If not admin, re-launch elevated with parameters preserved.
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Info "Administrator privileges required - requesting elevation via UAC..."

    # Save script to temp file so it can be invoked as -File with named params
    $tmpScript = Join-Path $env:TEMP ("blindwatch-install-{0}.ps1" -f ([guid]::NewGuid().ToString('N')))
    try {
        Invoke-WebRequest -Uri $InstallerUrl -OutFile $tmpScript -UseBasicParsing
    } catch {
        Write-Fatal "Could not download installer for elevation from ${InstallerUrl}: $_"
    }

    # If we have token+secret, stage them in a provision file so they are
    # NOT visible in the elevated process command line / Get-Process output.
    $stagedProvFile = $null
    if (-not $ProvisionFile -and $Token -and $Secret) {
        $stagedProvFile = New-TransientProvisionFile -Tok $Token -Sec $Secret -Api $ApiUrl
    }

    $elevatedProvFile = if ($stagedProvFile) { $stagedProvFile } else { $ProvisionFile }

    $argList = @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "`"$tmpScript`"")
    if ($elevatedProvFile) { $argList += @("-ProvisionFile", "`"$elevatedProvFile`"") }
    if ($ApiUrl -ne "https://api.blind.watch") { $argList += @("-ApiUrl", $ApiUrl) }
    if ($Upgrade) { $argList += "-Upgrade" }
    if ($Version) { $argList += @("-Version", $Version) }
    if ($DataDir -ne "C:\ProgramData\blindwatch") { $argList += @("-DataDir", "`"$DataDir`"") }
    if ($InstallerUrl -ne "https://get.blind.watch/agent/windows") {
        $argList += @("-InstallerUrl", $InstallerUrl)
    }
    if ($LocalBinary) { $argList += @("-LocalBinary", "`"$LocalBinary`"") }

    $exitCode = 1
    try {
        $proc = Start-Process -FilePath "powershell.exe" -ArgumentList $argList `
            -Verb RunAs -Wait -PassThru
        $exitCode = $proc.ExitCode
    } catch {
        Write-Fatal "Elevation cancelled or failed. Please run from an elevated PowerShell prompt."
    } finally {
        Remove-Item $tmpScript -ErrorAction SilentlyContinue
        if ($stagedProvFile) {
            Remove-Item $stagedProvFile -Force -ErrorAction SilentlyContinue
        }
    }

    exit $exitCode
}

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
    $tmpDir = Join-Path ([System.IO.Path]::GetTempPath()) ("blindwatch-install-{0}" -f ([guid]::NewGuid().ToString('N')))
    New-Item -ItemType Directory -Path $tmpDir -Force | Out-Null

    $archivePath = Join-Path $tmpDir $archiveName
    $checksumsPath = Join-Path $tmpDir "checksums.txt"

    Write-Info "Downloading $archiveName..."
    $baseUrl = "https://github.com/$Repo/releases/download/$tag"
    try {
        Invoke-WebRequest -Uri "$baseUrl/$archiveName" -OutFile $archivePath -UseBasicParsing
    } catch {
        Write-Fatal "Download failed: $archiveName ($_)"
    }

    Write-Info "Downloading checksums..."
    try {
        Invoke-WebRequest -Uri "$baseUrl/checksums.txt" -OutFile $checksumsPath -UseBasicParsing
    } catch {
        Write-Fatal "Checksums download failed"
    }

    # Verify checksum
    Write-Info "Verifying SHA-256 checksum..."
    $expected = (Get-Content $checksumsPath | Where-Object { $_ -match [regex]::Escape($archiveName) }) -replace '\s+.*$', ''
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
    } elseif (-not (Test-Path (Join-Path $DataDir "wal"))) {
        New-Item -ItemType Directory -Path (Join-Path $DataDir "wal") -Force | Out-Null
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
        -Description "blind.watch monitoring agent - encrypted infrastructure monitoring" `
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
        Write-Fatal "Token and secret are required for first install. Use -Token and -Secret parameters or -ProvisionFile."
    }

    Write-Info "Running first-boot provisioning..."
    $binaryFullPath = Join-Path $InstallDir $BinaryName

    # Write a tightly-scoped provision file inside DataDir (admin-only).
    # The agent reads it with --provision-file, so token/secret never appear
    # in the process command line or environment of subsequent processes.
    $bootProv = Join-Path $DataDir "first-boot.json"
    $data = @{
        token               = $Token
        provisioning_secret = $Secret
        api_url             = $ApiUrl
    } | ConvertTo-Json -Compress

    Write-Utf8NoBom -Path $bootProv -Content $data

    try {
        & $binaryFullPath --first-boot --provision-file $bootProv `
            --data-dir $DataDir --wal-dir "$DataDir\wal"
        $ec = $LASTEXITCODE
    } finally {
        Remove-Item $bootProv -Force -ErrorAction SilentlyContinue
    }

    if ($ec -ne 0) {
        Write-Fatal "First-boot provisioning failed (exit code $ec)"
    }

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

# --- Show recent service diagnostics on failure ---
function Show-ServiceDiagnostics {
    Write-Warn "Recent agent.log tail:"
    $logPath = Join-Path $DataDir "agent.log"
    if (Test-Path $logPath) {
        Get-Content -Path $logPath -Tail 30 | ForEach-Object { Write-Host "    $_" }
    } else {
        Write-Host "    (no $logPath yet)"
    }

    Write-Warn "Recent System event log entries for service control manager:"
    try {
        Get-WinEvent -LogName System -MaxEvents 10 -ErrorAction Stop |
            Where-Object { $_.ProviderName -eq 'Service Control Manager' -and $_.Message -match $ServiceName } |
            Select-Object -First 5 |
            ForEach-Object { Write-Host ("    [{0}] {1}" -f $_.TimeCreated, $_.Message.Trim()) }
    } catch {
        Write-Host "    (could not read System event log: $_)"
    }
}

# --- Start service ---
function Start-AgentService {
    Write-Info "Starting $ServiceName..."
    Start-Service -Name $ServiceName -ErrorAction Stop

    # Poll for up to 15s — Windows SCM start can take several seconds even when healthy.
    $deadline = (Get-Date).AddSeconds(15)
    while ((Get-Date) -lt $deadline) {
        $svc = Get-Service -Name $ServiceName
        if ($svc.Status -eq 'Running') {
            Write-Ok "Agent is running"
            return
        }
        Start-Sleep -Milliseconds 500
    }

    Show-ServiceDiagnostics
    Write-Fatal "Agent failed to reach Running state. See diagnostics above."
}

# --- Main ---
function Main {
    Write-Host ""
    Write-Host "  blind.watch agent installer (Windows)"
    Write-Host "  ======================================"
    Write-Host ""

    if ($LocalBinary) {
        if (-not (Test-Path $LocalBinary)) {
            Write-Fatal "LocalBinary not found: $LocalBinary"
        }
        Write-Warn "Using local binary (testing mode, checksum NOT verified): $LocalBinary"
        $result = @{ BinaryPath = (Resolve-Path $LocalBinary).Path; TmpDir = $null }
    } else {
        $ver = Resolve-AgentVersion
        Write-Info "Version: $ver"
        $result = Get-AgentBinary -Ver $ver
    }

    Install-AgentBinary -BinaryPath $result.BinaryPath
    New-DataDirectory
    Install-AgentService
    Install-UpgradeHelper

    if (-not $Upgrade) {
        Invoke-FirstBoot
    }

    Start-AgentService

    Write-Host ""
    $verLabel = if ($LocalBinary) { "(local build)" } else { $ver }
    Write-Ok "blind.watch agent $verLabel installed and running"
    Write-Host ""
    Write-Host "  Status:  Get-Service $ServiceName"
    Write-Host "  Logs:    Get-Content '$DataDir\agent.log' -Wait"
    Write-Host "  Version: & '$InstallDir\$BinaryName' --version"
    Write-Host ""

    # Cleanup
    if ($result.TmpDir -and (Test-Path $result.TmpDir)) {
        Remove-Item -Path $result.TmpDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Main
