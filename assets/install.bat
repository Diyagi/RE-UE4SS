@echo off
setlocal

set "DST=%~dp0..\..\..\..\common\MISERY\MISERY\Binaries\Win64"

if not exist "%DST%" (
    echo Error: Destination directory not found.
    pause
    exit /b 1
)

copy /Y "%~dp0dwmapi.dll" "%DST%\"
copy /Y "%~dp0override.txt" "%DST%\"
copy /Y "%~dp0UE4SS-settings.ini" "%DST%\"

echo Done!
pause
