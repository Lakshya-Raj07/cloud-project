@echo off
cd /d "%~dp0"
echo Starting Multi-Scenario Benchmark & Launching Interactive GUI Window...
.\venv\Scripts\python.exe run_demo.py
pause

