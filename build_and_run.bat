@echo off

echo Building the Go project...

REM Ensure Go modules are tidy
go mod tidy

REM Build the executable
go build -o backend.exe

REM Check if the build succeeded
IF %ERRORLEVEL% EQU 0 (
    echo Build succeeded. Running the executable...
    backend.exe
) ELSE (
    echo Build failed.
    exit /b 1
)
