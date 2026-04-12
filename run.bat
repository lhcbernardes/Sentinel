@echo off
REM Sentinel-RS Run Script for Windows
REM Usage: run.bat

echo Starting Sentinel-RS...
echo.

REM Identify network interface (show available adapters)
echo Available Network Adapters:
echo.
ipconfig | findstr /C:"Ethernet" /C:"Wi-Fi" /C:"Adapter"
echo.

REM Default interface - change if needed
set INTERFACE=Ethernet

echo Using interface: %INTERFACE%
echo Web Interface: http://localhost:8080
echo.

REM Run application
cargo run

pause