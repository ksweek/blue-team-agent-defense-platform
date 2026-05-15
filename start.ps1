param(
    [ValidateSet("local", "docker")]
    [string]$Mode = "local",
    [switch]$Build,
    [switch]$SkipInstall,
    [switch]$ExternalWorker
)

$ErrorActionPreference = "Stop"

$ProjectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$BackendDir = Join-Path $ProjectRoot "backend"
$FrontendDir = Join-Path $ProjectRoot "frontend"
$EnvFile = Join-Path $ProjectRoot ".env"
$EnvExampleFile = Join-Path $ProjectRoot ".env.example"
$RunLogDir = Join-Path $ProjectRoot "run_logs"

function Read-DotEnvFile {
    param(
        [string]$Path
    )

    $result = @{}
    if (-not (Test-Path $Path)) {
        return $result
    }

    foreach ($line in Get-Content -Path $Path) {
        $trimmed = $line.Trim()
        if (-not $trimmed -or $trimmed.StartsWith("#")) {
            continue
        }

        $parts = $trimmed -split "=", 2
        if ($parts.Count -ne 2) {
            continue
        }

        $key = $parts[0].Trim()
        $value = $parts[1].Trim()
        if (($value.StartsWith('"') -and $value.EndsWith('"')) -or ($value.StartsWith("'") -and $value.EndsWith("'"))) {
            $value = $value.Substring(1, $value.Length - 2)
        }
        $result[$key] = $value
    }

    return $result
}

function Ensure-Directory {
    param(
        [string]$Path
    )

    if (-not (Test-Path $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }
}

function Get-MaskedSecret {
    param(
        [string]$Value
    )

    if (-not $Value) {
        return "missing"
    }

    if ($Value.Length -le 8) {
        return ("*" * $Value.Length)
    }

    return "{0}...{1}" -f $Value.Substring(0, 4), $Value.Substring($Value.Length - 4)
}

function Test-PortInUse {
    param(
        [int]$Port
    )

    try {
        return [bool](Get-NetTCPConnection -State Listen -LocalPort $Port -ErrorAction SilentlyContinue)
    } catch {
        return [bool]((netstat -ano) | Select-String -Pattern "[:\.]$Port\s")
    }
}

function Resolve-AvailablePort {
    param(
        [int[]]$Candidates,
        [int]$StartAt
    )

    foreach ($candidate in $Candidates) {
        if (-not (Test-PortInUse -Port $candidate)) {
            return $candidate
        }
    }

    for ($candidate = $StartAt; $candidate -lt ($StartAt + 100); $candidate++) {
        if (-not (Test-PortInUse -Port $candidate)) {
            return $candidate
        }
    }

    throw "No available port was found near $StartAt."
}

function Stop-ProcessTree {
    param(
        [int]$ProcessId
    )

    $children = @(Get-CimInstance Win32_Process -Filter "ParentProcessId = $ProcessId" -ErrorAction SilentlyContinue)
    foreach ($child in $children) {
        Stop-ProcessTree -ProcessId $child.ProcessId
    }

    Stop-Process -Id $ProcessId -Force -ErrorAction SilentlyContinue
}

function Stop-ManagedProcess {
    param(
        [string]$Name,
        [string]$PidFile
    )

    if (-not (Test-Path $PidFile)) {
        return
    }

    $pidText = (Get-Content -Path $PidFile -Raw).Trim()
    if ($pidText -match '^\d+$') {
        Stop-ProcessTree -ProcessId ([int]$pidText)
        Start-Sleep -Milliseconds 500
    }

    Remove-Item -Path $PidFile -Force -ErrorAction SilentlyContinue
    Write-Host "Stopped previous $Name process." -ForegroundColor DarkGray
}

function Start-BackgroundProcess {
    param(
        [string]$Name,
        [string]$WorkingDirectory,
        [string[]]$Commands,
        [string]$OutLog,
        [string]$ErrLog,
        [string]$PidFile
    )

    foreach ($path in @($OutLog, $ErrLog, $PidFile)) {
        if (Test-Path $path) {
            Remove-Item -Path $path -Force -ErrorAction SilentlyContinue
        }
    }

    $escapedDir = $WorkingDirectory.Replace("'", "''")
    $scriptPath = Join-Path $RunLogDir "$Name.startup.ps1"
    $scriptLines = @(
        '$ErrorActionPreference = ''Stop''',
        '[Console]::OutputEncoding = [System.Text.Encoding]::UTF8',
        '$OutputEncoding = [System.Text.Encoding]::UTF8',
        "Set-Location '$escapedDir'"
    ) + $Commands
    Set-Content -Path $scriptPath -Value ($scriptLines -join [Environment]::NewLine) -Encoding UTF8

    $process = Start-Process powershell -WindowStyle Hidden -ArgumentList @(
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        $scriptPath
    ) -RedirectStandardOutput $OutLog -RedirectStandardError $ErrLog -PassThru

    Set-Content -Path $PidFile -Value $process.Id -Encoding ascii
    return $process
}

function Wait-HttpReady {
    param(
        [string]$Url,
        [int]$TimeoutSec = 60,
        [int[]]$AllowedStatusCodes = @(200)
    )

    $deadline = (Get-Date).AddSeconds($TimeoutSec)
    do {
        try {
            $response = Invoke-WebRequest -UseBasicParsing -Uri $Url -TimeoutSec 5
            if ($AllowedStatusCodes -contains [int]$response.StatusCode) {
                return $true
            }
        } catch {
            $statusCode = $null
            if ($_.Exception.Response -and $_.Exception.Response.StatusCode) {
                $statusCode = [int]$_.Exception.Response.StatusCode
            }
            if ($null -ne $statusCode -and $AllowedStatusCodes -contains $statusCode) {
                return $true
            }
        }

        Start-Sleep -Seconds 1
    } while ((Get-Date) -lt $deadline)

    return $false
}

function Show-RecentLog {
    param(
        [string]$Label,
        [string]$Path
    )

    Write-Host ""
    Write-Host "[$Label] $Path" -ForegroundColor Yellow
    if (Test-Path $Path) {
        Get-Content -Path $Path -Tail 40
    } else {
        Write-Host "No log output found."
    }
}

function Invoke-Step {
    param(
        [string]$Title,
        [scriptblock]$Action
    )

    Write-Host ""
    Write-Host "==> $Title" -ForegroundColor Cyan
    & $Action
}

if ($Mode -eq "docker") {
    Push-Location $ProjectRoot
    try {
        $composeArgs = @("compose")
        if ($ExternalWorker) {
            $composeArgs += @("--profile", "external-worker")
        }
        $composeArgs += "up"
        if ($Build) {
            $composeArgs += "--build"
        }
        $composeArgs += "-d"
        docker @composeArgs
    }
    finally {
        Pop-Location
    }

    Write-Host ""
    Write-Host "Docker services are starting." -ForegroundColor Green
    Write-Host "Frontend: http://0.0.0.0:5173" -ForegroundColor Gray
    Write-Host "Backend:  http://0.0.0.0:8000" -ForegroundColor Gray
    if ($ExternalWorker) {
        Write-Host "Worker:   external-worker profile enabled" -ForegroundColor Gray
    }
    return
}

Ensure-Directory -Path $RunLogDir

if ((-not (Test-Path $EnvFile)) -and (Test-Path $EnvExampleFile)) {
    Copy-Item -Path $EnvExampleFile -Destination $EnvFile
    Write-Host "Created .env from .env.example" -ForegroundColor Yellow
}

$envConfig = Read-DotEnvFile -Path $EnvFile
$appEnv = if ($envConfig.ContainsKey("APP_ENV")) { $envConfig["APP_ENV"] } elseif ($envConfig.ContainsKey("ENVIRONMENT")) { $envConfig["ENVIRONMENT"] } else { "development" }
$bootstrapMode = if ($envConfig.ContainsKey("BOOTSTRAP_MODE")) { $envConfig["BOOTSTRAP_MODE"] } else { $(if ($appEnv -eq "production") { "validate" } else { "auto" }) }
$seedSampleData = if ($envConfig.ContainsKey("SEED_SAMPLE_DATA")) { $envConfig["SEED_SAMPLE_DATA"] } else { $(if ($appEnv -eq "production") { "false" } else { "true" }) }
$aiProvider = if ($envConfig.ContainsKey("AI_PROVIDER")) { $envConfig["AI_PROVIDER"] } else { "disabled" }
$aiBaseUrl = if ($envConfig.ContainsKey("AI_BASE_URL")) { $envConfig["AI_BASE_URL"] } elseif ($envConfig.ContainsKey("OPENAI_BASE_URL")) { $envConfig["OPENAI_BASE_URL"] } else { "https://api.openai.com/v1" }
$aiModel = if ($envConfig.ContainsKey("AI_MODEL")) { $envConfig["AI_MODEL"] } elseif ($envConfig.ContainsKey("OPENAI_MODEL")) { $envConfig["OPENAI_MODEL"] } else { "" }
$aiApiKey = if ($envConfig.ContainsKey("AI_API_KEY")) { $envConfig["AI_API_KEY"] } elseif ($envConfig.ContainsKey("OPENAI_API_KEY")) { $envConfig["OPENAI_API_KEY"] } else { "" }
$aiReady = ($aiProvider -ne "disabled") -and (-not [string]::IsNullOrWhiteSpace($aiModel))
$workerMode = if ($ExternalWorker) { "external" } else { "embedded" }

$backendPort = Resolve-AvailablePort -Candidates @(8000, 18000, 18001, 8001) -StartAt 18000
$frontendPort = Resolve-AvailablePort -Candidates @(5173, 15173, 4173) -StartAt 15173
$taskWorkerEmbeddedValue = if ($ExternalWorker) { "false" } else { "true" }
$bindHost = "0.0.0.0"
$probeHost = "127.0.0.1"
$backendProxyTarget = "http://127.0.0.1:$backendPort"

$backendOutLog = Join-Path $RunLogDir "start.backend.out.log"
$backendErrLog = Join-Path $RunLogDir "start.backend.err.log"
$backendPidFile = Join-Path $RunLogDir "start.backend.pid"
$frontendOutLog = Join-Path $RunLogDir "start.frontend.out.log"
$frontendErrLog = Join-Path $RunLogDir "start.frontend.err.log"
$frontendPidFile = Join-Path $RunLogDir "start.frontend.pid"
$workerOutLog = Join-Path $RunLogDir "start.worker.out.log"
$workerErrLog = Join-Path $RunLogDir "start.worker.err.log"
$workerPidFile = Join-Path $RunLogDir "start.worker.pid"

Stop-ManagedProcess -Name "backend" -PidFile $backendPidFile
Stop-ManagedProcess -Name "frontend" -PidFile $frontendPidFile
Stop-ManagedProcess -Name "worker" -PidFile $workerPidFile

if (-not $SkipInstall) {
    Invoke-Step -Title "Installing backend dependencies" -Action {
        Push-Location $BackendDir
        try {
            python -m pip install -r requirements.txt
            if ($LASTEXITCODE -ne 0) {
                throw "Backend dependency installation failed."
            }
        }
        finally {
            Pop-Location
        }
    }

    Invoke-Step -Title "Installing frontend dependencies" -Action {
        Push-Location $FrontendDir
        try {
            npm install
            if ($LASTEXITCODE -ne 0) {
                throw "Frontend dependency installation failed."
            }
        }
        finally {
            Pop-Location
        }
    }
}

$backendCommands = @(
    '$env:PYTHONIOENCODING = ''utf-8''',
    ('$env:TASK_WORKER_EMBEDDED = ''{0}''' -f $taskWorkerEmbeddedValue),
    ('python run_dev.py --host {0} --port {1}' -f $bindHost, $backendPort)
)

$frontendCommands = @(
    ('$env:VITE_API_PROXY_TARGET = ''{0}''' -f $backendProxyTarget),
    ('$env:VITE_PORT = ''{0}''' -f $frontendPort),
    ('npm run dev -- --host {0} --port {1} --strictPort --clearScreen false' -f $bindHost, $frontendPort)
)

$workerCommands = @(
    '$env:PYTHONIOENCODING = ''utf-8''',
    '$env:TASK_WORKER_EMBEDDED = ''false''',
    "python run_worker.py"
)

Invoke-Step -Title "Starting backend in hidden mode" -Action {
    Start-BackgroundProcess -Name "backend" -WorkingDirectory $BackendDir -Commands $backendCommands -OutLog $backendOutLog -ErrLog $backendErrLog -PidFile $backendPidFile | Out-Null
}

if (-not (Wait-HttpReady -Url "http://${probeHost}:${backendPort}/health" -AllowedStatusCodes @(200) -TimeoutSec 90)) {
    Show-RecentLog -Label "backend stdout" -Path $backendOutLog
    Show-RecentLog -Label "backend stderr" -Path $backendErrLog
    throw "Backend did not become ready on http://${probeHost}:${backendPort}/health ."
}

if ($ExternalWorker) {
    Invoke-Step -Title "Starting standalone worker in hidden mode" -Action {
        Start-BackgroundProcess -Name "worker" -WorkingDirectory $BackendDir -Commands $workerCommands -OutLog $workerOutLog -ErrLog $workerErrLog -PidFile $workerPidFile | Out-Null
    }
}

Invoke-Step -Title "Starting frontend in hidden mode" -Action {
    Start-BackgroundProcess -Name "frontend" -WorkingDirectory $FrontendDir -Commands $frontendCommands -OutLog $frontendOutLog -ErrLog $frontendErrLog -PidFile $frontendPidFile | Out-Null
}

if (-not (Wait-HttpReady -Url "http://${probeHost}:${frontendPort}" -AllowedStatusCodes @(200) -TimeoutSec 90)) {
    Show-RecentLog -Label "frontend stdout" -Path $frontendOutLog
    Show-RecentLog -Label "frontend stderr" -Path $frontendErrLog
    throw "Frontend did not become ready on http://${probeHost}:${frontendPort} ."
}

Write-Host ""
Write-Host "Local development services are ready." -ForegroundColor Green
Write-Host "Frontend : http://${bindHost}:${frontendPort}" -ForegroundColor Gray
Write-Host "Backend  : http://${bindHost}:${backendPort}" -ForegroundColor Gray
Write-Host "Docs     : http://${bindHost}:${backendPort}/docs" -ForegroundColor Gray
Write-Host "Env      : $appEnv" -ForegroundColor Gray
Write-Host "Bootstrap: $bootstrapMode" -ForegroundColor Gray
Write-Host "Sample   : $seedSampleData" -ForegroundColor Gray
Write-Host "Provider : $aiProvider" -ForegroundColor Gray
Write-Host "Worker   : $workerMode" -ForegroundColor Gray
Write-Host "Model    : $(if ($aiModel) { $aiModel } else { '-' })" -ForegroundColor Gray
Write-Host "API key  : $(Get-MaskedSecret -Value $aiApiKey)" -ForegroundColor Gray
Write-Host "Logs     : $RunLogDir" -ForegroundColor Gray
if ($backendPort -ne 8000) {
    Write-Host "Backend port 8000 was already occupied, so this startup switched to $backendPort automatically." -ForegroundColor Yellow
}
if ($frontendPort -ne 5173) {
    Write-Host "Frontend port 5173 was already occupied, so this startup switched to $frontendPort automatically." -ForegroundColor Yellow
}
if (-not $aiReady) {
    Write-Host "Real model execution is not ready. Fill AI_PROVIDER / AI_BASE_URL / AI_API_KEY / AI_MODEL in .env." -ForegroundColor Yellow
    Write-Host "Quick check: python .\\test_ai_provider.py" -ForegroundColor Yellow
}
