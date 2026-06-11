@echo off
chcp 65001 > nul
echo Начинаем установку Multi-Algo Cryptotool

set "INSTALL_DIR=C:\Program Files\Cryptotool"
mkdir "%INSTALL_DIR%" 2>nul
copy /Y cryptotool.exe "%INSTALL_DIR%\"
copy /Y gronsfeld.dll "%INSTALL_DIR%\"
copy /Y atbash.dll "%INSTALL_DIR%\"

setx PATH "%PATH%;%INSTALL_DIR%" /M

echo Установка успешно завершена
pause