@echo off
chcp 65001 >nul

echo ========================================
echo        CodeQL 代码安全分析平台
echo ========================================
echo.

echo [1/2] 验证环境...
java -version
if errorlevel 1 (
    echo [错误] Java环境配置失败！
    pause
    exit /b 1
)

codeql version >nul 2>&1
if errorlevel 1 (
    echo [错误] CodeQL环境配置失败！
    pause
    exit /b 1
)

echo [2/2] 启动服务...
echo 服务地址: http://127.0.0.1:5000 
echo 新增功能:
echo   - 代码审计 (主页)
echo   - QL规则生成器 (http://127.0.0.1:5000/generator)
echo   - 审计报告历史 (http://127.0.0.1:5000/reports) 
echo   - 个人中心 (http://127.0.0.1:5000/profile)
echo 按 Ctrl+C 停止服务
echo.

cd /d "D:\NetworkSecurity\project"
python app.py

pause