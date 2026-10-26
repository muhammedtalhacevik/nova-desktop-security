param([string]$Runtime = "win-x64")

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$out = Join-Path $root "publish\$Runtime"

dotnet publish (Join-Path $root "src\Nova.Desktop\Nova.Desktop.csproj") `
    -c Release -r $Runtime --self-contained true `
    -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true `
    -p:DebugType=none -o $out

Write-Host ""
Write-Host "Hazır: $out\NovaDesktopSecurity.exe" -ForegroundColor Green
