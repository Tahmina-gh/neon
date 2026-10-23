@echo off
title Neon Motion
cd /d "%~dp0backend"
where node >nul 2>nul
if errorlevel 1 (
  echo Node.js was not found. Install it from https://nodejs.org and run this again.
  pause
  exit /b 1
)
if not exist node_modules\.installed (
  echo Installing - first time only, please wait...
  call npm install
  if errorlevel 1 (
    echo.
    echo Install failed - see the message above.
    pause
    exit /b 1
  )
  echo ok> node_modules\.installed
)
echo.
echo Starting Neon Motion... your browser will open at http://localhost:3000
echo Keep this window open while you use the site. Close it to stop.
echo.
start "" /b cmd /c "timeout /t 3 /nobreak >nul && start http://localhost:3000"
node --no-warnings server.js
pause
