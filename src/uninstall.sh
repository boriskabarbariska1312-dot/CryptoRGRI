#!/bin/bash

INSTALL_DIR="/opt/cryptum"
BIN_DIR="/usr/local/bin"

echo "Начинаем удаление Multi-Algo Cryptotool (cryptum)"

# Удаление скрипта-обертки из системного PATH
sudo rm -f "$BIN_DIR/cryptum"

# Удаление директории со всеми бинарниками и библиотеками алгоритмов
sudo rm -rf "$INSTALL_DIR"

echo "Удаление успешно завершено"