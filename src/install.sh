#!/bin/bash

INSTALL_DIR="/opt/cryptum"
BIN_DIR="/usr/local/bin"

echo "Начинаем установку Multi-Algo Cryptotool (cryptum)"

# Создание директории для приложения и библиотек
sudo mkdir -p "$INSTALL_DIR"

# Копирование бинарного файла и динамических библиотек
sudo cp cryptum "$INSTALL_DIR/"
sudo cp libgronsfeld.so "$INSTALL_DIR/"
sudo cp libatbash.so "$INSTALL_DIR/"

# Установка прав на исполнение
sudo chmod +x "$INSTALL_DIR/cryptum"

# Создание символьной ссылки в PATH
sudo ln -sf "$INSTALL_DIR/cryptum" "$BIN_DIR/cryptum"

echo "Установка успешно завершена. Программа доступна по команде: cryptum"