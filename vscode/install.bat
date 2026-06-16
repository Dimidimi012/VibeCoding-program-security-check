@echo off
chcp 65001 >nul
echo ========================================
echo   Code Sentry VS Code 扩展安装脚本
echo ========================================
echo.

set "EXT_DIR=%USERPROFILE%\.vscode\extensions\hanako.code-sentry-0.1.0"

echo [1/3] 创建扩展目录...
if exist "%EXT_DIR%" (
    echo   已存在，正在覆盖...
    rmdir /s /q "%EXT_DIR%"
)
mkdir "%EXT_DIR%"

echo [2/3] 复制扩展文件...
xcopy /e /y /q "%~dp0out" "%EXT_DIR%\out\"
xcopy /y /q "%~dp0package.json" "%EXT_DIR%\"
xcopy /y /q "%~dp0images\icon.png" "%EXT_DIR%\images\"

echo [3/3] 安装完成！
echo.
echo 下一步:
echo   1. 重启 VS Code
echo   2. 打开设置 (Ctrl+,)，搜索 "codeSentry"
echo   3. 设置 "Code Sentry Path" 为 code-sentry 项目的路径
echo      例如: C:\Users\dimidimi\Desktop\hanak_workplace\code-sentry
echo.
echo   安装路径: %EXT_DIR%
echo.
pause
