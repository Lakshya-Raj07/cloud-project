@echo off
REM Keycloak Standalone Launcher Script (CloudGovRealm)
echo ========================================================
echo  Starting Keycloak IdP Standalone Server on :8080...
echo ========================================================
cd /d "%~dp0\..\.."
.\venv\Scripts\python.exe src\identity\keycloak_server.py

