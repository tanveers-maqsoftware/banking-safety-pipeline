<#
.SYNOPSIS
    Starts the safety pipeline API behind a Cloudflare quick tunnel and prints
    the public URL to paste into Copilot Studio.

.DESCRIPTION
    Replaces the usual two-terminal dance. Starts uvicorn, waits for it to pass
    its own health check, opens the tunnel, then reads the generated hostname
    out of cloudflared's output so you do not have to hunt for it.

    The API binds to 127.0.0.1 only. Nothing on your network can reach it -- the
    tunnel is the sole route in, which is what we want for a service handling
    customer messages.

    Both processes are stopped on exit, including Ctrl+C.

.PARAMETER Port
    Local port for the API. Default 8000.

.EXAMPLE
    .\run.ps1
#>
[CmdletBinding()]
param(
    [int]$Port = 8000
)

$ErrorActionPreference = 'Stop'

$root = $PSScriptRoot
$python = Join-Path $root '.venv\Scripts\python.exe'

if (-not (Test-Path $python)) {
    throw "No virtualenv at .venv. Run the Setup steps in README.md first."
}
if (-not (Get-Command cloudflared -ErrorAction SilentlyContinue)) {
    throw "cloudflared not found. Install it with: winget install --id Cloudflare.cloudflared"
}

$log = Join-Path ([System.IO.Path]::GetTempPath()) "cloudflared-$Port.log"
Remove-Item $log -ErrorAction SilentlyContinue

$api = $null
$tunnel = $null

try {
    Write-Host "Starting API on 127.0.0.1:$Port ..." -ForegroundColor Cyan
    $api = Start-Process -FilePath $python `
        -ArgumentList '-m', 'uvicorn', 'main:app', '--host', '127.0.0.1', '--port', $Port `
        -WorkingDirectory $root -PassThru -NoNewWindow

    # The service warms spaCy and lingua on startup, so first boot is slow.
    # Poll its health endpoint rather than guessing with a fixed sleep.
    $ready = $false
    foreach ($attempt in 1..60) {
        if ($api.HasExited) { throw "API exited during startup (code $($api.ExitCode))." }
        try {
            $health = Invoke-RestMethod "http://127.0.0.1:$Port/v1/health" -TimeoutSec 2
            if ($health.status -eq 'ok') { $ready = $true; break }
        } catch { Start-Sleep -Seconds 1 }
    }
    if (-not $ready) { throw "API did not become healthy within 60s." }

    Write-Host "API healthy. Serving prompts:" -ForegroundColor Green
    $health.active_prompts.PSObject.Properties |
        ForEach-Object { Write-Host "  $($_.Name)@$($_.Value)" -ForegroundColor DarkGray }

    Write-Host "`nOpening Cloudflare tunnel ..." -ForegroundColor Cyan
    $tunnel = Start-Process -FilePath 'cloudflared' `
        -ArgumentList 'tunnel', '--url', "http://127.0.0.1:$Port" `
        -PassThru -NoNewWindow -RedirectStandardError $log

    # cloudflared prints the assigned hostname to stderr a second or two in.
    $url = $null
    foreach ($attempt in 1..45) {
        Start-Sleep -Seconds 1
        if (Test-Path $log) {
            $match = Select-String -Path $log -Pattern 'https://[a-z0-9-]+\.trycloudflare\.com' |
                Select-Object -First 1
            if ($match) { $url = $match.Matches[0].Value; break }
        }
        if ($tunnel.HasExited) { throw "cloudflared exited. See $log" }
    }
    if (-not $url) { throw "Could not read the tunnel URL. See $log" }

    Write-Host ""
    Write-Host "  Public URL : $url" -ForegroundColor Green
    Write-Host "  Connector  : $url/v1/process" -ForegroundColor Green
    Write-Host "  Health     : $url/v1/health" -ForegroundColor DarkGray
    Write-Host "  API docs   : http://127.0.0.1:$Port/docs" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "This URL is new on every restart -- re-point the Copilot Studio" -ForegroundColor Yellow
    Write-Host "connector whenever you restart this script." -ForegroundColor Yellow
    Write-Host "`nCtrl+C to stop both processes." -ForegroundColor DarkGray

    while (-not $api.HasExited -and -not $tunnel.HasExited) { Start-Sleep -Seconds 1 }
}
finally {
    foreach ($proc in @($tunnel, $api)) {
        if ($proc -and -not $proc.HasExited) {
            Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
        }
    }
    Write-Host "`nStopped." -ForegroundColor DarkGray
}
