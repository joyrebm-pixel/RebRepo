@echo off
setlocal
cd /d "%~dp0"

where node >nul 2>nul
if errorlevel 1 (
  echo Node.js is required. Install Node.js, then run this launcher again.
  pause
  exit /b 1
)

where npm >nul 2>nul
if errorlevel 1 (
  echo npm is required. Reinstall Node.js with npm enabled, then run this launcher again.
  pause
  exit /b 1
)

if not exist "node_modules\mysql2\promise.js" (
  echo Dependencies are missing. Run "npm install" in this folder first.
  pause
  exit /b 1
)

powershell -NoProfile -Command "try { $health = Invoke-RestMethod -Uri 'http://127.0.0.1:3000/api/health' -TimeoutSec 2; if ($health.service -eq 'virus-scanner') { exit 0 } } catch {}; exit 1" >nul 2>nul
if errorlevel 1 (
  start "Virus Scanner Node server" cmd.exe /k "cd /d ""%~dp0"" && npm start"
)

echo Waiting for the app and XAMPP MySQL...
powershell -NoProfile -Command "$deadline = (Get-Date).AddSeconds(45); do { try { $status = Invoke-RestMethod -Uri 'http://127.0.0.1:3000/api/auth/status' -TimeoutSec 3; if (($status.PSObject.Properties.Name -contains 'configured') -and ($status.PSObject.Properties.Name -contains 'scannerConfigured') -and $status.configured) { Start-Process 'http://localhost:3000'; exit 0 } } catch {}; Start-Sleep -Seconds 1 } while ((Get-Date) -lt $deadline); exit 1"
if errorlevel 1 (
  echo The app could not connect to MySQL. Start MySQL in the XAMPP Control Panel and check .env.
  pause
  exit /b 1
)
