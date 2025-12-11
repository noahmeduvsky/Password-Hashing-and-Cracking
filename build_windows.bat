@echo off
REM Windows build script for C password hash cracking backends
REM Requires: MinGW-w64 or MSVC with OpenSSL

echo Building C password hash cracking backends for Windows...
echo.

REM Check for MinGW-w64 (gcc)
where gcc >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    echo Found GCC compiler...
    goto :build_mingw
)

REM Check for MSVC (cl)
where cl >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    echo Found MSVC compiler...
    goto :build_msvc
)

echo ERROR: No C compiler found!
echo.
echo Please install one of the following:
echo   1. MinGW-w64: https://www.mingw-w64.org/downloads/
echo   2. Visual Studio Build Tools (with C++ support)
echo   3. Use WSL (Windows Subsystem for Linux)
echo.
echo Then install OpenSSL development libraries:
echo   - For MinGW: Download from https://slproweb.com/products/Win32OpenSSL.html
echo   - For MSVC: Download from same location
echo.
goto :end

:build_mingw
echo Building with MinGW-w64...
echo.

REM Check if OpenSSL is available
if not exist "C:\OpenSSL-Win64\include\openssl\sha.h" (
    echo WARNING: OpenSSL not found in default location
    echo Trying to find OpenSSL in PATH...
)

REM Build serial backend
echo Building serial backend...
gcc -Wall -Wextra -O2 -shared hash_cracker_serial.c -o hash_cracker_serial.dll -lssl -lcrypto -I"C:\OpenSSL-Win64\include" -L"C:\OpenSSL-Win64\lib" 2>build_serial.log
if %ERRORLEVEL% EQU 0 (
    echo SUCCESS: Built hash_cracker_serial.dll
) else (
    echo ERROR: Failed to build serial backend. Check build_serial.log
    type build_serial.log
)

echo.

REM Build multithreaded backend
echo Building multithreaded backend...
gcc -Wall -Wextra -O2 -shared hash_cracker_multithreaded.c hash_cracker_serial.c -o hash_cracker_multithreaded.dll -lssl -lcrypto -lpthread -I"C:\OpenSSL-Win64\include" -L"C:\OpenSSL-Win64\lib" 2>build_multithreaded.log
if %ERRORLEVEL% EQU 0 (
    echo SUCCESS: Built hash_cracker_multithreaded.dll
) else (
    echo ERROR: Failed to build multithreaded backend. Check build_multithreaded.log
    type build_multithreaded.log
)

goto :end

:build_msvc
echo Building with MSVC...
echo.
echo NOTE: MSVC build requires manual configuration of OpenSSL paths
echo Please modify this script with correct paths to OpenSSL libraries
echo.
goto :end

:end
echo.
echo Build complete!
pause

