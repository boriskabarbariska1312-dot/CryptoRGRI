#!/bin/bash

INSTALL_DIR="/opt/cryptum"
BIN_DIR="/usr/local/bin"

echo "Начинаем установку Multi-Algo Cryptotool (cryptum)"

sudo mkdir -p "$INSTALL_DIR"

# Определение расширения динамических библиотек в зависимости от ОС
if [[ "$OSTYPE" == "darwin"* ]]; then
    EXT="dylib"
else
    EXT="so"
fi

# Копирование бинарного файла и всех динамических библиотек
echo "Копирование файлов проекта..."
sudo cp cryptum "$INSTALL_DIR/"
sudo cp libgronsfeld.$EXT "$INSTALL_DIR/"
sudo cp libatbash.$EXT "$INSTALL_DIR/"
sudo cp librc4.$EXT "$INSTALL_DIR/"
sudo cp libblowfish.$EXT "$INSTALL_DIR/"
sudo cp libmtproto.$EXT "$INSTALL_DIR/"

# Установка прав на исполнение для главного бинарника
sudo chmod +x "$INSTALL_DIR/cryptum"

# Создаем скрипт-обертку в системном PATH
echo "Создание скрипта-обертки в $BIN_DIR..."
sudo bash -c "cat > \"$BIN_DIR/cryptum\"" << EOF
#!/bin/bash
exec "$INSTALL_DIR/cryptum" "\$@"
EOF

# Установка прав на исполнение для скрипта-обертки
sudo chmod +x "$BIN_DIR/cryptum"

echo "Установка успешно завершена. Программа доступна по команде: cryptum"