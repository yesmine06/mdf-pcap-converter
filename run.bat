@echo off
REM Lanceur mdf2ascii - execute le convertisseur sans compiler
REM Double-cliquez pour afficher l'aide, ou glissez-deposez un fichier

setlocal
cd /d "%~dp0"

set EXE=
if exist "build\Release\mdf2ascii.exe" set EXE=build\Release\mdf2ascii.exe
if exist "build\mdf2ascii.exe" set EXE=build\mdf2ascii.exe

if "%EXE%"=="" (
    echo mdf2ascii.exe introuvable.
    echo.
    echo Compilation requise. Executez d'abord : build.ps1
    echo Ou en PowerShell : .\build.ps1
    echo.
    pause
    exit /b 1
)

"%EXE%" %*
set ERR=%ERRORLEVEL%
if "%~1"=="" pause
exit /b %ERR%
