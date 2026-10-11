@echo off
chcp 65001 >nul
cd /d "%~dp0"
where python >nul 2>nul
if %errorlevel%==0 (
  python app.py
) else (
  where python3 >nul 2>nul
  if %errorlevel%==0 (
    python3 app.py
  ) else (
    echo 未找到 Python 3，请先安装： https://www.python.org/downloads/
    pause
  )
)
pause
