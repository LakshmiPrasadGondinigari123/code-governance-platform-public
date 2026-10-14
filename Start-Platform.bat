@echo off
rem One-click launcher: starts the whole Code-to-Governance platform (UI + API + scanner) and opens it.
setlocal
cd /d "%~dp0"
set "PY=%USERPROFILE%\py312\python.exe"
if not exist "%PY%" set "PY=python"
if "%ADMIN_USERNAME%"=="" set "ADMIN_USERNAME=admin"
if "%ADMIN_PASSWORD%"=="" (
  if not exist "%~dp0.admin_password" powershell -NoProfile -Command "-join ((48..57)+(65..90)+(97..122) | Get-Random -Count 20 | %%{[char]$_}) | Set-Content -NoNewline '%~dp0.admin_password'"
  set /p ADMIN_PASSWORD=<"%~dp0.admin_password"
)
if "%DATA_DIR%"=="" set "DATA_DIR=%~dp0data"
set "PORT=8000"
if exist "%USERPROFILE%\portablegit\cmd" set "PATH=%USERPROFILE%\portablegit\cmd;%PATH%"
powershell -NoProfile -Command "try{(Invoke-WebRequest -UseBasicParsing http://127.0.0.1:%PORT%/liveness -TimeoutSec 2).StatusCode}catch{exit 1}" >nul 2>&1
if %errorlevel%==0 goto open
start "Code-Governance Platform" /min "%PY%" -m uvicorn app.main:app --host 127.0.0.1 --port %PORT%
for /l %%i in (1,1,30) do (
  powershell -NoProfile -Command "try{(Invoke-WebRequest -UseBasicParsing http://127.0.0.1:%PORT%/liveness -TimeoutSec 2).StatusCode}catch{exit 1}" >nul 2>&1
  if not errorlevel 1 goto open
  timeout /t 1 >nul
)
echo Backend did not start. Check that Python and requirements are installed.
pause
exit /b 1
:open
start "" http://localhost:%PORT%
echo Platform running at http://localhost:%PORT%   (login: %ADMIN_USERNAME% / %ADMIN_PASSWORD%)
endlocal


