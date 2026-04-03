# Build and prepare the portable distribution folder (dist/)
# Includes: mdf2ascii.exe, MinGW/vcpkg DLLs, GUI, launch scripts

$ErrorActionPreference = "Stop"
$ProjectRoot = if ($PSScriptRoot) { $PSScriptRoot } else { Get-Location }
$DistDir = Join-Path $ProjectRoot "dist"

Write-Host "=== Portable package (dist/) ===" -ForegroundColor Cyan

# 1. Build project
& (Join-Path $ProjectRoot "build.ps1")
if ($LASTEXITCODE -ne 0) { exit 1 }

# 2. Locate executable
$ExePath = Join-Path $ProjectRoot "build\Release\mdf2ascii.exe"
if (-not (Test-Path $ExePath)) {
    $ExePath = Join-Path $ProjectRoot "build\mdf2ascii.exe"
}
if (-not (Test-Path $ExePath)) {
    Write-Host "Error: mdf2ascii.exe not found" -ForegroundColor Red
    exit 1
}

# 3. Recreate dist
if (Test-Path $DistDir) {
    Remove-Item $DistDir -Recurse -Force
}
New-Item -ItemType Directory -Path $DistDir | Out-Null

# 4. Main executable
Copy-Item $ExePath -Destination $DistDir
Write-Host "  + mdf2ascii.exe" -ForegroundColor Green

# 5. vcpkg DLLs (MSVC dynamic link)
$VcpkgInstalled = Join-Path $ProjectRoot "vcpkg\installed"
$Triplets = @()
if (Test-Path $VcpkgInstalled) {
    $Triplets = Get-ChildItem $VcpkgInstalled -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -match "windows" } | Select-Object -ExpandProperty Name
}
if ($Triplets.Count -eq 0) { $Triplets = @("x64-windows", "x86-windows") }
$dllVcpkg = $false
foreach ($Triplet in $Triplets) {
    $BinPath = Join-Path (Join-Path $VcpkgInstalled $Triplet) "bin"
    if (-not (Test-Path $BinPath)) { continue }
    foreach ($dll in (Get-ChildItem $BinPath -Filter "*.dll" -ErrorAction SilentlyContinue)) {
        Copy-Item $dll.FullName -Destination $DistDir -Force
        Write-Host "  + $($dll.Name) (vcpkg)" -ForegroundColor Green
        $dllVcpkg = $true
    }
    if ($dllVcpkg) { break }
}

# 6. MinGW runtime DLLs (GCC / MSYS2) — copy each file
$MingwDlls = @(
    "libwinpthread-1.dll",
    "libstdc++-6.dll",
    "libgcc_s_seh-1.dll"
)
$MingwBinCandidates = @(
    "C:\msys64\ucrt64\bin",
    "C:\msys64\mingw64\bin",
    "C:\msys64\clang64\bin",
    (Join-Path $env:USERPROFILE "msys64\ucrt64\bin")
)
foreach ($d in $MingwDlls) {
    $done = $false
    foreach ($bin in $MingwBinCandidates) {
        if (-not (Test-Path $bin)) { continue }
        $src = Join-Path $bin $d
        if (Test-Path $src) {
            Copy-Item $src -Destination $DistDir -Force
            Write-Host "  + $d (MinGW)" -ForegroundColor Green
            $done = $true
            break
        }
    }
    if (-not $done) {
        Write-Host ('  ! Missing: ' + $d + ' - copy from C:\msys64\ucrt64\bin') -ForegroundColor Yellow
    }
}

# 7. CLI scripts (single-quoted here-string for batch)
$RunBat = @'
@echo off
cd /d "%~dp0"
"mdf2ascii.exe" %*
if "%*"=="" pause
'@
$RunBat | Out-File -FilePath (Join-Path $DistDir "run.bat") -Encoding ASCII
Write-Host "  + run.bat" -ForegroundColor Green

# 8. GUI
$UiDir = Join-Path $DistDir "ui"
New-Item -ItemType Directory -Path $UiDir -Force | Out-Null
$GuiScript = Join-Path $ProjectRoot "ui\converter_gui.py"
if (Test-Path $GuiScript) {
    Copy-Item $GuiScript -Destination $UiDir -Force
    Write-Host "  + ui\converter_gui.py" -ForegroundColor Green
    $RunGuiBat = @'
@echo off
cd /d "%~dp0"
python ui\converter_gui.py
if errorlevel 1 (
    echo Python 3 required: https://www.python.org/downloads/
    pause
)
'@
    $RunGuiBat | Out-File -FilePath (Join-Path $DistDir "run_gui.bat") -Encoding ASCII
    Write-Host "  + run_gui.bat" -ForegroundColor Green
}

# 9. Documentation
$Readme = @'
mdf2ascii - Portable executable package (no compilation)

QUICK START
-----------
  GUI: double-click run_gui.bat (Python 3 required)
  CLI: double-click run.bat or run:
      mdf2ascii.exe --mdf2pcap file.mf4
      mdf2ascii.exe --pcap2mdf capture.pcap

DEFAULT OUTPUT
--------------
  Set CONVERTER_OUTPUT_DIR or use the project default folder.

FILES IN THIS FOLDER
--------------------
  mdf2ascii.exe     Main converter
  lib*.dll          MinGW runtime (required when built with GCC)
  run.bat           Launches CLI
  run_gui.bat       Launches GUI
  ui\               Python GUI script
  README.txt        This file
  MANIFEST.txt      Packaged file list

Copy this folder to another Windows x64 machine (same architecture).
'@
$Readme | Out-File -FilePath (Join-Path $DistDir "README.txt") -Encoding UTF8
Write-Host "  + README.txt" -ForegroundColor Green

# 10. File manifest
$ManifestLines = @("=== Package contents ===", "")
Get-ChildItem $DistDir -Recurse -File | Sort-Object FullName | ForEach-Object {
    $rel = $_.FullName.Substring($DistDir.Length).TrimStart('\')
    $ManifestLines += ("{0,-50} {1,12} bytes" -f $rel, $_.Length)
}
$ManifestLines -join "`r`n" | Out-File -FilePath (Join-Path $DistDir "MANIFEST.txt") -Encoding UTF8
Write-Host "  + MANIFEST.txt" -ForegroundColor Green

Write-Host ""
Write-Host "Ready: $DistDir" -ForegroundColor Green
Write-Host 'Copy the entire dist/ folder for a portable installation.' -ForegroundColor Cyan
