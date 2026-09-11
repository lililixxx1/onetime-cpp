@echo off
rem Build script: configure + build (Release). Requires VS 2022 Build Tools (C++ workload).
set "CMAKE=%ProgramFiles(x86)%\Microsoft Visual Studio\2022\BuildTools\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin"
set "PATH=%CMAKE%;%PATH%"
if "%1"=="test-only" goto test
cmake -S . -B build || exit /b 1
cmake --build build --config Release --parallel || exit /b 1
:test
build\Release\onetime_tests.exe
