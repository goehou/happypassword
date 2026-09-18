@echo off
:: 打包单文件 exe, 输出 dist\hpw.exe, 挂到 GitHub Releases 即可
pip install pyinstaller -q
pyinstaller --onefile --name hpw --clean pw.py
echo.
echo 输出: dist\hpw.exe
pause
