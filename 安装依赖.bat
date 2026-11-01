@echo off
rem === Install Python dependencies for the G3 battery tray (pystray + pillow) ===
echo === [1/2] Installing pystray + pillow (Aliyun mirror) ===
python -m pip install pystray pillow -i https://mirrors.aliyun.com/pypi/simple/
if errorlevel 1 (
  echo === [2/2] Mirror failed, retrying with default index ===
  python -m pip install pystray pillow
)
echo === Verifying ===
python -c "import pystray, PIL; print('pystray + pillow OK')"
echo === Done. If 'python' was not found, install Python 3.12+ first (add to PATH) ===
pause
