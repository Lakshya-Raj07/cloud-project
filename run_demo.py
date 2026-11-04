"""
run_demo.py
-----------
One-Click Root Launcher for the Interactive Benchmark & Pop-up GUI Window.
Run this directly from terminal:
    python run_demo.py
"""

import sys
import subprocess
from pathlib import Path

# Auto-detect and relaunch with venv Python if running on system Python
project_root = Path(__file__).resolve().parent
venv_python = project_root / "venv" / "Scripts" / "python.exe"
if venv_python.exists() and sys.executable.lower() != str(venv_python).lower():
    res = subprocess.run([str(venv_python)] + sys.argv)
    sys.exit(res.returncode)

# Ensure project root is on path
if str(project_root / "src") not in sys.path:
    sys.path.insert(0, str(project_root / "src"))

from benchmark.show_benchmark import run_benchmark_and_show_window

if __name__ == "__main__":
    run_benchmark_and_show_window()

