# PowerShell build script for C password hash cracking backends on Windows
# Requires: MinGW-w64 or MSVC with OpenSSL

Write-Host "Building C password hash cracking backends for Windows..." -ForegroundColor Cyan
Write-Host ""

# Check for GCC (MinGW-w64)
$gccPath = Get-Command gcc -ErrorAction SilentlyContinue
if ($gccPath) {
    Write-Host "Found GCC compiler at: $($gccPath.Source)" -ForegroundColor Green
    Write-Host "Building with MinGW-w64..." -ForegroundColor Yellow
    Write-Host ""
    
    # Try to find OpenSSL
    $opensslPaths = @(
        "C:\OpenSSL-Win64",
        "C:\Program Files\OpenSSL-Win64",
        "$env:ProgramFiles\OpenSSL-Win64"
    )
    
    $opensslPath = $null
    foreach ($path in $opensslPaths) {
        if (Test-Path "$path\include\openssl\sha.h") {
            $opensslPath = $path
            break
        }
    }
    
    if ($opensslPath) {
        Write-Host "Found OpenSSL at: $opensslPath" -ForegroundColor Green
        $includeFlag = "-I`"$opensslPath\include`""
        $libFlag = "-L`"$opensslPath\lib`""
    } else {
        Write-Host "WARNING: OpenSSL not found in standard locations" -ForegroundColor Yellow
        Write-Host "Trying system PATH..." -ForegroundColor Yellow
        $includeFlag = ""
        $libFlag = ""
    }
    
    # Build serial backend
    Write-Host "Building serial backend..." -ForegroundColor Yellow
    $serialCmd = "gcc -Wall -Wextra -O2 -shared hash_cracker_serial.c -o hash_cracker_serial.dll -lssl -lcrypto $includeFlag $libFlag"
    try {
        Invoke-Expression $serialCmd 2>&1 | Out-File -FilePath build_serial.log
        if (Test-Path "hash_cracker_serial.dll") {
            Write-Host "SUCCESS: Built hash_cracker_serial.dll" -ForegroundColor Green
        } else {
            Write-Host "ERROR: Build failed. Check build_serial.log" -ForegroundColor Red
            Get-Content build_serial.log
        }
    } catch {
        Write-Host "ERROR: $($_.Exception.Message)" -ForegroundColor Red
    }
    
    Write-Host ""
    
    # Build multithreaded backend
    Write-Host "Building multithreaded backend..." -ForegroundColor Yellow
    $multithreadedCmd = "gcc -Wall -Wextra -O2 -shared hash_cracker_multithreaded.c hash_cracker_serial.c -o hash_cracker_multithreaded.dll -lssl -lcrypto -lpthread $includeFlag $libFlag"
    try {
        Invoke-Expression $multithreadedCmd 2>&1 | Out-File -FilePath build_multithreaded.log
        if (Test-Path "hash_cracker_multithreaded.dll") {
            Write-Host "SUCCESS: Built hash_cracker_multithreaded.dll" -ForegroundColor Green
        } else {
            Write-Host "ERROR: Build failed. Check build_multithreaded.log" -ForegroundColor Red
            Get-Content build_multithreaded.log
        }
    } catch {
        Write-Host "ERROR: $($_.Exception.Message)" -ForegroundColor Red
    }
    
} else {
    # Check for MSVC
    $clPath = Get-Command cl -ErrorAction SilentlyContinue
    if ($clPath) {
        Write-Host "Found MSVC compiler at: $($clPath.Source)" -ForegroundColor Green
        Write-Host "MSVC build not yet automated. Please use build_windows.bat or build manually." -ForegroundColor Yellow
    } else {
        Write-Host "ERROR: No C compiler found!" -ForegroundColor Red
        Write-Host ""
        Write-Host "Please install one of the following:" -ForegroundColor Yellow
        Write-Host "  1. MinGW-w64: https://www.mingw-w64.org/downloads/" -ForegroundColor White
        Write-Host "  2. Visual Studio Build Tools (with C++ support)" -ForegroundColor White
        Write-Host "  3. Use WSL (Windows Subsystem for Linux)" -ForegroundColor White
        Write-Host ""
        Write-Host "Then install OpenSSL development libraries:" -ForegroundColor Yellow
        Write-Host "  Download from: https://slproweb.com/products/Win32OpenSSL.html" -ForegroundColor White
        exit 1
    }
}

Write-Host ""
Write-Host "Build complete!" -ForegroundColor Green

