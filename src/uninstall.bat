@echo off
chcp 65001 > nul
echo Начинаем удаление Multi-Algo Cryptotool (cryptum)

set "INSTALL_DIR=C:\Program Files\Cryptum"
del /Q "%INSTALL_DIR%\*.*"
rmdir "%INSTALL_DIR%"

echo Удаление успешно завершено
echo Внимание: Переменную PATH необходимо очистить вручную в настройках среды Windows
pause