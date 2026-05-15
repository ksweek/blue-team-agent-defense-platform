[CmdletBinding()]
param(
  [switch]$BackendOnly,
  [switch]$FrontendOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if ($BackendOnly -and $FrontendOnly) {
  throw "Cannot use -BackendOnly and -FrontendOnly together."
}

$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

function Require-Command {
  param([string]$Name)
  if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) {
    throw "Required command not found: $Name"
  }
}

function Invoke-Step {
  param(
    [string]$Name,
    [scriptblock]$Action
  )

  Write-Host ""
  Write-Host "==> $Name" -ForegroundColor Cyan
  & $Action
}

Require-Command python

if (-not $FrontendOnly) {
  Invoke-Step "Backend compile check" {
    python -m compileall backend/app backend/run_dev.py backend/run_worker.py backend/scripts/init_db.py smoke_test.py test_ai_provider.py
  }

  Invoke-Step "Backend database validation" {
    python backend/scripts/init_db.py --mode validate
  }
}

if (-not $BackendOnly) {
  Require-Command npm
  Invoke-Step "Frontend production build" {
    Push-Location frontend
    try {
      npm run build
    }
    finally {
      Pop-Location
    }
  }
}

Write-Host ""
Write-Host "Validation completed." -ForegroundColor Green
