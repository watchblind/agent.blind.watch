param([Parameter(Mandatory)][string]$Version)
if ($Version -notmatch '^v?\d+\.\d+\.\d+') { throw "Invalid version: $Version" }
$script = Invoke-RestMethod -Uri "https://get.blind.watch/agent/windows"
Invoke-Expression "& { $script } -Upgrade -Version $Version"
