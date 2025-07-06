@echo off
set PROJECT=samlify

if "%1" == "install" goto install
if "%1" == "clean" goto clean
if "%1" == "rebuild" goto rebuild
if "%1" == "pretest" goto pretest
if "%1" == "doc" goto doc
if "%1" == "install_jdk" goto install_jdk

echo Usage: build.bat [install^|clean^|rebuild^|pretest^|doc^|install_jdk]
goto end

:install
echo Installing %PROJECT%
npm install
goto end

:clean
echo Cleaning node_modules
rmdir /s /q node_modules
goto end

:rebuild
call :clean
echo Rebuilding...
mkdir build
tsc
goto end

:pretest
echo Preparing tests...
mkdir build\test 2>nul
xcopy test\key build\test\key /E /I /Y
xcopy test\misc build\test\misc /E /I /Y
goto end

:doc
echo Serving docs with docsify...
docsify serve ./docs
goto end

:install_jdk
echo JDK installation is not applicable on Windows via this script.
echo Please manually install OpenJDK from https://adoptium.net/
goto end

:end
