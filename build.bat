@echo off
echo Building SSLClaw for Windows...

:: Check if gcc is available (required by Fyne/CGO)
where gcc >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo ------------------------------------------------------------------
    echo ERROR: gcc ^(C compiler^) was not found in your PATH. 
    echo Fyne requires CGO to build on Windows.
    echo Please install MSYS2 from https://www.msys2.org/
    echo Open "MSYS2 MinGW64" terminal and run: pacman -S mingw-w64-x86_64-gcc
    echo Then add C:\msys64\mingw64\bin to your Windows PATH environment variable.
    echo ------------------------------------------------------------------
    pause
    exit /b 1
)

:: Build the application
set CGO_ENABLED=1
go build -ldflags="-s -w -H=windowsgui" -o SSLClaw.exe .

if %ERRORLEVEL% NEQ 0 (
    echo ------------------------------------------------------------------
    echo ERROR: Build failed. See the output above for more details.
    echo ------------------------------------------------------------------
    pause
    exit /b %ERRORLEVEL%
)

echo.
echo ==================================================================
echo SUCCESS! SSLClaw has been compiled to SSLClaw.exe
echo You can now double-click SSLClaw.exe to launch the application.
echo ==================================================================
pause
