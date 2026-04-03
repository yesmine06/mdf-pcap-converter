# Build mdf2ascii (pure C++, mdflib)
$ErrorActionPreference = "Stop"
$ProjectRoot = if ($PSScriptRoot) { $PSScriptRoot } else { Get-Location }
$VcpkgPath = Join-Path $ProjectRoot "vcpkg"

# Use local vcpkg clone
if (-not (Test-Path $VcpkgPath)) {
    Write-Host "Cloning vcpkg..." -ForegroundColor Yellow
    Set-Location $ProjectRoot
    git clone https://github.com/Microsoft/vcpkg.git vcpkg
}

if (-not (Test-Path (Join-Path $VcpkgPath "vcpkg.exe"))) {
    Write-Host "Bootstrapping vcpkg..." -ForegroundColor Yellow
    & (Join-Path $VcpkgPath "scripts\bootstrap.ps1")
}

$BuildDir = Join-Path $ProjectRoot "build"
if (-not (Test-Path $BuildDir)) {
    New-Item -ItemType Directory -Path $BuildDir | Out-Null
}

Set-Location $BuildDir

$CmakeExe = "cmake"
if (Test-Path "C:\Program Files\CMake\bin\cmake.exe") {
    $CmakeExe = "C:\Program Files\CMake\bin\cmake.exe"
}

Write-Host "Configuring CMake (vcpkg: zlib, expat)..." -ForegroundColor Cyan
& $CmakeExe .. `
  -DCMAKE_BUILD_TYPE=Release `
  -DCMAKE_TOOLCHAIN_FILE=(Join-Path $VcpkgPath "scripts\buildsystems\vcpkg.cmake")

if ($LASTEXITCODE -ne 0) { exit 1 }

Write-Host "Building..." -ForegroundColor Cyan
& $CmakeExe --build . --config Release

if ($LASTEXITCODE -eq 0) {
    $ExePath = Join-Path $BuildDir "Release\mdf2ascii.exe"
    if (-not (Test-Path $ExePath)) { $ExePath = Join-Path $BuildDir "mdf2ascii.exe" }
    Write-Host "`nBuild succeeded: $ExePath" -ForegroundColor Green
} else {
    exit 1
}
