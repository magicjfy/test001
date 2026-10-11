#!/usr/bin/env bash
cd "$(dirname "$0")"
if command -v python3 >/dev/null 2>&1; then
  python3 app.py
elif command -v python >/dev/null 2>&1; then
  python app.py
else
  echo "未找到 Python 3，请先安装：https://www.python.org/downloads/"
  exit 1
fi
