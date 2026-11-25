@echo off
setlocal
set "shareRoot=%~dp0.."
set "shareExe=%shareRoot%\ui\DropPorter.Wpf\bin\Release\net10.0-windows10.0.19041.0\DropPorter.exe"
if not exist "%shareExe%" (
    echo Build tools\DropPorterWpf.proj with Visual Studio MSBuild first.
    exit /b 1
)
start "" "%shareExe%"
exit /b 0
