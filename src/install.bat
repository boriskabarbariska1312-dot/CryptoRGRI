@echo off
chcp 65001 > nul
echo Начинаем установку Multi-Algo Cryptotool (cryptum)

set "INSTALL_DIR=C:\Program Files\Cryptum"
mkdir "%INSTALL_DIR%" 2>nul

echo Копирование исполняемого файла и библиотек...
copy /Y cryptum.exe "%INSTALL_DIR%\"
copy /Y gronsfeld.dll "%INSTALL_DIR%\"
copy /Y atbash.dll "%INSTALL_DIR%\"
copy /Y rc4.dll "%INSTALL_DIR%\"
copy /Y blowfish.dll "%INSTALL_DIR%\"
copy /Y mtproto.dll "%INSTALL_DIR%\"

echo Добавление программы в системный PATH...
setx PATH "%PATH%;%INSTALL_DIR%" /M

echo Установка успешно завершена. Программа доступна по команде: cryptum
pause