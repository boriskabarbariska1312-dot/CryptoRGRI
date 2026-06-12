#ifndef AES256_H
#define AES256_H

#include <vector>
#include <cstdint>

class AES256 {
public:
    // Конструктор принимает 32-байтный ключ и сразу запускает Key Expansion
    AES256(const std::vector<uint8_t>& key);

    // Чтобы Зафиксировать метод прослойку для аеса любимого
    uint8_t encryptBlock_gmul(uint8_t a, uint8_t b);
    // Шифрует один блок (16 байт) in-place (прямо в переданном массиве)
    void encryptBlock(uint8_t* block);

    // Расшифровывает один блок (16 байт) in-place
    void decryptBlock(uint8_t* block);

private:
    // Количество раундов для AES-256 строго равно 14
    static const int Nr = 14;
    // Размер ключа в 32-битных словах (32 байта = 8 слов)
    static const int Nk = 8;

    // Сюда мы запишем развернутые раундовые ключи (размер: 16 байт * 15 ключей = 240 байт)
    uint8_t roundKeys[240]; 

    // Внутренняя функция развертки ключа
    void keyExpansion(const uint8_t* key);

    // Вспомогательная функция для шага MixColumns (умножение в полях Галуа)
    uint8_t gmul(uint8_t a, uint8_t b);
};

#endif // AES256_H