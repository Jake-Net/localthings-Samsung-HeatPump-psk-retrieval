@echo off
setlocal
cd /d "%~dp0"
title Heat-pump OwnerPSK extraction
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0RUN-EXTRACT.ps1"
endlocal
