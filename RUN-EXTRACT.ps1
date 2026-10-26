param(
    [string]$Serial = 'R58NA2KW1TR',
    [string]$DeviceUuid = 'fd41c401-3203-099c-d27c-000001200000',
    [string]$Adb = 'adb',
    [switch]$CheckOnly
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$python = Join-Path $root '.venv\Scripts\python.exe'
$frida = Join-Path $root '.venv\Scripts\frida.exe'
$server = 'C:\Users\kelly\Documents\Default Project\root-a21s\tools\frida-server-17.24.2-android-arm64'
$remote = '/data/local/tmp/frida-server'
$package = 'com.samsung.android.oneconnect'
$privateDir = Join-Path $root 'private'

function Section([string]$text) {
    Write-Host "`n=== $text ===" -ForegroundColor Cyan
}

function Stop-With([string]$text) {
    Write-Host "`nERROR: $text" -ForegroundColor Red
    Read-Host 'Press Enter to close'
    exit 1
}

function Invoke-Adb([string[]]$Arguments) {
    & $Adb @Arguments 2>&1
}

Section 'Checking host tools'
if (-not (Test-Path $python)) { Stop-With "Python venv not found: $python" }
if (-not (Test-Path $frida)) { Stop-With "Frida CLI not found: $frida" }
if (-not (Test-Path $server)) { Stop-With "Frida server not found: $server" }
& $Adb version | Out-Null
if ($LASTEXITCODE -ne 0) { Stop-With 'adb is not available in PATH.' }
if (-not (Test-Path $privateDir)) { New-Item -ItemType Directory -Path $privateDir | Out-Null }
Write-Host 'Host tools OK.'

if ($CheckOnly) {
    Write-Host 'Check-only mode: no phone commands were run.'
    exit 0
}

Section "Waiting for phone $Serial"
$deadline = (Get-Date).AddSeconds(30)
$devices = ''
do {
    $devices = (Invoke-Adb @('devices')) -join "`n"
    if ($devices -match ([regex]::Escape($Serial) + '\s+device')) { break }
    Start-Sleep -Seconds 2
} while ((Get-Date) -lt $deadline)

if ($devices -notmatch ([regex]::Escape($Serial) + '\s+device')) {
    Stop-With 'Phone is not online. Unlock it, keep USB debugging on, replug the cable, and accept the Allow prompt.'
}
Write-Host "Phone online: $Serial"

Section 'Checking root'
$rootOut = (Invoke-Adb @('-s', $Serial, 'shell', 'su -c id')) -join "`n"
if ($rootOut -notmatch 'uid=0') {
    Stop-With 'Root is not available. Open Magisk, grant Shell/ADB root, then rerun.'
}
Write-Host 'Root OK.'

Section 'Checking SmartThings'
$pkgOut = (Invoke-Adb @('-s', $Serial, 'shell', "dumpsys package $package")) -join "`n"
if ($pkgOut -notmatch 'versionName=') {
    Stop-With 'SmartThings is not installed. Install it from Galaxy Store, sign in, and confirm the heat pump is visible. Then rerun.'
}
$versionMatch = [regex]::Match($pkgOut, 'versionName=(\S+)')
Write-Host "SmartThings version: $($versionMatch.Groups[1].Value)"

Section 'Starting Frida server'
Invoke-Adb @('-s', $Serial, 'push', $server, $remote) | Out-Null
Invoke-Adb @('-s', $Serial, 'shell', 'su -c "chmod 700 /data/local/tmp/frida-server"') | Out-Null
Invoke-Adb @('-s', $Serial, 'shell', 'su -c "killall frida-server 2>/dev/null; true"') | Out-Null
Invoke-Adb @('-s', $Serial, 'shell', 'su -c "nohup /data/local/tmp/frida-server -l 127.0.0.1:27042 >/data/local/tmp/frida.log 2>&1 &"') | Out-Null
Start-Sleep -Seconds 3
$fridaPid = (Invoke-Adb @('-s', $Serial, 'shell', 'su -c "pidof frida-server"')) -join "`n"
if (-not $fridaPid.Trim()) {
    $log = (Invoke-Adb @('-s', $Serial, 'shell', 'su -c "tail -30 /data/local/tmp/frida.log"')) -join "`n"
    Stop-With "Frida server did not start. Log:`n$log"
}
Write-Host "Frida server PID: $($fridaPid.Trim())"

Section 'Finding .datenc stores'
$findCmd = 'su -c "find /data/user/0/com.samsung.android.oneconnect/files -maxdepth 1 -type f -name \"*.datenc\""'
$storeOut = (Invoke-Adb @('-s', $Serial, 'shell', $findCmd)) -join "`n"
$stores = @()
foreach ($match in [regex]::Matches($storeOut, '([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})\.datenc')) {
    if ($stores -notcontains $match.Groups[1].Value) { $stores += $match.Groups[1].Value }
}

if ($stores.Count -eq 0) {
    Stop-With 'No .datenc store found. Open SmartThings, sign in, wait for the device list to sync, then rerun.'
}

Write-Host 'Found stores:'
for ($i = 0; $i -lt $stores.Count; $i++) {
    Write-Host ("  [{0}] {1}" -f ($i + 1), $stores[$i])
}

if ($stores.Count -eq 1) {
    $store = $stores[0]
} else {
    $choice = Read-Host 'Choose store number'
    $index = [int]$choice - 1
    if ($index -lt 0 -or $index -ge $stores.Count) { Stop-With 'Invalid store choice.' }
    $store = $stores[$index]
}
Write-Host "Using store: $store"

Section 'Inspecting store (identifiers only)'
& $python (Join-Path $root 'inspect_encrypted_store.py') --serial $Serial --store $store --show-identifiers --frida $frida
if ($LASTEXITCODE -ne 0) {
    Stop-With 'Store inspection failed. Keep the phone unlocked and SmartThings foreground, then rerun.'
}

Section 'Saving owner PSK'
$out = Join-Path $privateDir 'heatpump-owner-psk.json'
if (Test-Path $out) {
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $out = Join-Path $privateDir "heatpump-owner-psk-$stamp.json"
}
& $python (Join-Path $root 'save-oven-key.py') --serial $Serial --store $store --device-uuid $DeviceUuid --output $out --frida $frida
if ($LASTEXITCODE -ne 0) {
    Stop-With 'PSK save failed. If the inspection showed no credtype=1 entry, the heat pump was not registered through this phone; see RUNBOOK Phase 2 Branch B. If it showed a PSK with a different subject, check the heat pump UUID.'
}

Section 'Result'
$record = Get-Content -Raw $out | ConvertFrom-Json
Write-Host "Saved: $out"
Write-Host "Identity: $($record.psk_identity)"
Write-Host "PSK length: $($record.psk_hex.Length) hex characters"
if ($record.identity_contains_nul) {
    Write-Warning 'The identity contains a zero byte. LocalThings needs smartthings-local 0.1.23 or newer.'
}

Set-Clipboard -Value $record.psk_identity
Write-Host 'Identity copied to clipboard.'
Read-Host 'Press Enter to copy the PSK to the clipboard (keep this window private)'
Set-Clipboard -Value $record.psk_hex
Write-Host 'PSK copied to clipboard. Paste it into LocalThings, then clear the clipboard.'

Section 'Stopping Frida server'
Invoke-Adb @('-s', $Serial, 'shell', 'su -c "killall frida-server 2>/dev/null; true"') | Out-Null
Write-Host 'Frida server stopped.'

Read-Host 'Press Enter to close'
