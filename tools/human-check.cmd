@echo off
setlocal
set "shareRoot=%~dp0.."
set "shareExe=%shareRoot%\ui\DropPorter.Wpf\bin\Release\net10.0-windows10.0.19041.0\DropPorter.exe"
if not exist "%shareExe%" (
    echo Build tools\DropPorterWpf.proj with Visual Studio MSBuild first.
    exit /b 1
)
rem Optional receive ACK rate: human-check.cmd 54 (12, 24, 36 or 54 Mbps fixed; default adapts from 36).
if not "%~1"=="" set "DROPPORTER_RECEIVE_ACK_MBPS=%~1"
start "" "%shareExe%"
exit /b 0
