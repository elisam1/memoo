@echo off
SETLOCAL
REM Start Memoo on Windows (double-click to run)
pushd %~dp0

IF NOT EXIST node_modules (
  echo Installing dependencies (one-time)...
  call npm install
)

set PORT=8081
set NODE_ENV=production

REM Optional: set BASE_URL to your PC's LAN address so email links work
REM Example: set BASE_URL=http://%COMPUTERNAME%:8081
REM Prefer setting BASE_URL in .env for persistence

start "" http://localhost:%PORT%/
call npm start

popd
ENDLOCAL
