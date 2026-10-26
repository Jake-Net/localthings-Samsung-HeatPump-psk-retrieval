param(
    [int]$Minutes = 15
)
$ErrorActionPreference = 'Continue'
$serial = 'R58NA2KW1TR'
$frida = 'C:\Users\kelly\Documents\Default Project\psk-retrieval\.venv\Scripts\frida.exe'
$script = Join-Path $env:TEMP 'onboard-spy.js'
$logDir = 'C:\Users\kelly\Documents\Default Project\psk-retrieval\private\onboard-logs'
New-Item -ItemType Directory -Force -Path $logDir | Out-Null
Copy-Item 'C:\Users\kelly\Documents\Default Project\psk-retrieval\agent\src\onboard-spy.js' $script -Force

$attached = @{}
$deadline = (Get-Date).AddMinutes($Minutes)
Write-Host "capture-onboard started; logging to $logDir"

function Get-Pid([string]$name) {
    $out = (& adb -s $serial shell "pidof $name" 2>$null)
    if ($null -eq $out) { return $null }
    $s = ($out | Out-String).Trim()
    if ($s -eq '') { return $null }
    return $s
}

function Attach([string]$name, [string]$targetId) {
    $port = (& adb -s $serial forward tcp:0 tcp:27042 2>$null | Out-String).Trim()
    if ($port -eq '') { return $null }
    $safe = $name -replace '[:.]', '_'
    $outFile = Join-Path $logDir ("{0}-{1}.log" -f $safe, $targetId)
    $proc = Start-Process -FilePath $frida `
        -ArgumentList @('-H', "127.0.0.1:$port", '-q', '-l', $script, '-p', $targetId, '-t', '1200') `
        -RedirectStandardOutput $outFile -RedirectStandardError ($outFile + '.err') -NoNewWindow -PassThru
    return @{ Process = $proc; Port = $port; File = $outFile }
}

while ((Get-Date) -lt $deadline) {
    foreach ($name in @('com.samsung.android.oneconnect', 'com.samsung.android.oneconnect:Core')) {
        $procId = Get-Pid $name
        if ($procId -and -not $attached.ContainsKey($procId)) {
            $a = Attach $name $procId
            if ($a) {
                $attached[$procId] = $a
                Write-Host ("attached {0} pid={1} port={2}" -f $name, $procId, $a.Port)
            }
        }
    }
    Start-Sleep -Seconds 2
}
Write-Host 'capture-onboard finished'
