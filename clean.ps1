param(
    [switch]$IncludeDependencies,
    [switch]$IncludeReportArtifacts,
    [switch]$IncludeDatabase
)

$ProjectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path

function Resolve-ProjectTarget {
    param(
        [string]$RelativePath
    )

    $targetPath = Join-Path $ProjectRoot $RelativePath
    $fullPath = [System.IO.Path]::GetFullPath($targetPath)
    $fullRoot = [System.IO.Path]::GetFullPath($ProjectRoot)

    if (-not $fullPath.StartsWith($fullRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing to operate outside project root: $RelativePath"
    }

    return $fullPath
}

function Remove-ProjectItem {
    param(
        [string]$RelativePath
    )

    $fullPath = Resolve-ProjectTarget -RelativePath $RelativePath
    if (Test-Path -LiteralPath $fullPath) {
        Remove-Item -LiteralPath $fullPath -Recurse -Force
        Write-Host "Removed $RelativePath" -ForegroundColor Yellow
        return
    }

    Write-Host "Skipped $RelativePath (not found)" -ForegroundColor DarkGray
}

Write-Host ""
Write-Host "========================================" -ForegroundColor DarkCyan
Write-Host " Blue Team Project Cleanup" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor DarkCyan
Write-Host ""

$defaultTargets = @(
    "run_logs",
    "__pycache__",
    "frontend\dist"
)

foreach ($relativePath in $defaultTargets) {
    Remove-ProjectItem -RelativePath $relativePath
}

Get-ChildItem -Path $ProjectRoot -Recurse -Directory -Force -Filter "__pycache__" | ForEach-Object {
    $fullPath = [System.IO.Path]::GetFullPath($_.FullName)
    $fullRoot = [System.IO.Path]::GetFullPath($ProjectRoot)
    if ($fullPath.StartsWith($fullRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
        Remove-Item -LiteralPath $fullPath -Recurse -Force
        $displayPath = $fullPath.Substring($fullRoot.Length).TrimStart('\')
        Write-Host "Removed $displayPath" -ForegroundColor Yellow
    }
}

if ($IncludeDependencies) {
    Remove-ProjectItem -RelativePath "frontend\node_modules"
}

if ($IncludeReportArtifacts) {
    Remove-ProjectItem -RelativePath "backend\data\reports"
}

if ($IncludeDatabase) {
    Remove-ProjectItem -RelativePath "backend\data\app.db"
}

Write-Host ""
Write-Host "Cleanup complete." -ForegroundColor Green
