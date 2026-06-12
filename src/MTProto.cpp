#include "AES256.h"
#include "SHA256.h"
#include <vector>
#include <cstdint>
#include <cstring>
#include <iostream>

// Структуры для соответствия интерфейсу нашей РГР
struct ConstBuffer {
    const uint8_t* data;
    size_t size;
};

struct MutBuffer {
    uint8_t* data;
    size_t size;
};

namespace {
    // Внутренняя функция KDF (Генерация ключей по стандарту MTProto 2.0)
    // Она принимает Auth Key (из пароля) и Message Key (из данных)
    void mtproto_kdf(const std::vector<uint8_t>& auth_key, const uint8_t* msg_key, 
                     std::vector<uint8_t>& aes_key, std::vector<uint8_t>& aes_iv) {
        
        aes_key.resize(32);
        aes_iv.resize(32);

        // MTProto 2.0 KDF формула:
        // sha256a = SHA256(msg_key + auth_key[0..31])
        // sha256b = SHA256(auth_key[32..63] + msg_key)
        
        std::vector<uint8_t> bufferA;
        bufferA.insert(bufferA.end(), msg_key, msg_key + 16);
        bufferA.insert(bufferA.end(), auth_key.begin(), auth_key.begin() + 32);
        std::vector<uint8_t> sha256a = calculate_sha256(bufferA);

        std::vector<uint8_t> bufferB;
        bufferB.insert(bufferB.end(), auth_key.begin() + 32, auth_key.begin() + 64);
        bufferB.insert(bufferB.end(), msg_key, msg_key + 16);
        std::vector<uint8_t> sha256b = calculate_sha256(bufferB);

        // Собираем aes_key из кусков хэшей
        // aes_key = sha256a[0..7] + sha256b[8..23] + sha256a[24..31]
        std::memcpy(&aes_key[0], &sha256a[0], 8);
        std::memcpy(&aes_key[8], &sha256b[8], 16);
        std::memcpy(&aes_key[24], &sha256a[24], 8);

        // Собираем aes_iv (Вектор инициализации)
        // aes_iv = sha256b[0..7] + sha256a[8..23] + sha256b[24..31]
        std::memcpy(&aes_iv[0], &sha256b[0], 8);
        std::memcpy(&aes_iv[8], &sha256a[8], 16);
        std::memcpy(&aes_iv[24], &sha256b[24], 8);
    }
}

// Экспортируем функции для динамической загрузки (.so)
extern "C" {

    int encrypt(ConstBuffer key, ConstBuffer input, MutBuffer* output) {
        if (!output || !output->data) return -1;

        // 1. Готовим 64-байтный Auth Key из пароля пользователя с помощью SHA-256
        std::vector<uint8_t> user_key(key.data, key.data + key.size);
        std::vector<uint8_t> auth_key = calculate_sha256(user_key);
        // Добавим еще один хэш, чтобы расширить до 64 байт, как требует протокол
        std::vector<uint8_t> auth_key_part2 = calculate_sha256(auth_key);
        auth_key.insert(auth_key.end(), auth_key_part2.begin(), auth_key_part2.end());

        // 2. Выравниваем входные данные по размеру блока (16 байт) + место под Message Key (16 байт)
        size_t payload_size = input.size;
        size_t padding = (16 - (payload_size % 16)) % 16;
        size_t encrypted_data_size = payload_size + padding;
        
        // Полный размер выходных данных: 16 байт (MsgKey) + зашифрованные данные
        size_t total_needed = 16 + encrypted_data_size;
        if (output->size < total_needed) {
            return total_needed; // Возвращаем требуемый размер, если буфер мал
        }

        // 3. Генерируем Message Key. В реальном Telegram это хэш от данных.
        std::vector<uint8_t> data_to_hash(input.data, input.data + payload_size);
        std::vector<uint8_t> msg_key_hash = calculate_sha256(data_to_hash);
        uint8_t msg_key[16];
        std::memcpy(msg_key, msg_key_hash.data(), 16); // Берем первые 16 байт хэша

        // Копируем msg_key в самое начало выходного буфера
        std::memcpy(output->data, msg_key, 16);

        // 4. Запускаем KDF для получения ключей AES IGE
        std::vector<uint8_t> aes_key, aes_iv;
        mtproto_kdf(auth_key, msg_key, aes_key, aes_iv);

        // 5. Инициализируем ядро AES-256
        AES256 aes(aes_key);

        // Инициализируем вектора для режима IGE
        uint8_t x_or_cipher[16]; // Предыдущий шифротекст (C_{i-1})
        uint8_t x_or_plain[16];  // Предыдущий открытый текст (P_{i-1})
        std::memcpy(x_or_cipher, &aes_iv[0], 16);
        std::memcpy(x_or_plain, &aes_iv[16], 16);

        // 6. Основной цикл шифрования IGE
        uint8_t* plain_ptr = const_cast<uint8_t*>(input.data);
        uint8_t* cipher_ptr = output->data + 16;

        for (size_t offset = 0; offset < encrypted_data_size; offset += 16) {
            uint8_t pt_block[16] = {0};
            
            // Копируем данные, учитывая возможный паддинг (нули в конце)
            size_t to_copy = (payload_size - offset > 16) ? 16 : (payload_size - offset);
            std::memcpy(pt_block, plain_ptr + offset, to_copy);

            uint8_t ct_block[16];
            // Формула IGE: C_i = E(P_i ^ C_{i-1}) ^ P_{i-1}
            for (int i = 0; i < 16; ++i) {
                ct_block[i] = pt_block[i] ^ x_or_cipher[i];
            }

            aes.encryptBlock(ct_block);

            for (int i = 0; i < 16; ++i) {
                ct_block[i] ^= x_or_plain[i];
            }

            // Сохраняем результат
            std::memcpy(cipher_ptr + offset, ct_block, 16);

            // Обновляем вектора для следующего шага
            std::memcpy(x_or_cipher, ct_block, 16);
            std::memcpy(x_or_plain, pt_block, 16);
        }

        output->size = total_needed;
        return 0;
    }

    int decrypt(ConstBuffer key, ConstBuffer input, MutBuffer* output) {
        if (!output || !output->data || input.size < 16) return -1;

        // 1. Восстанавливаем Auth Key из пароля
        std::vector<uint8_t> user_key(key.data, key.data + key.size);
        std::vector<uint8_t> auth_key = calculate_sha256(user_key);
        std::vector<uint8_t> auth_key_part2 = calculate_sha256(auth_key);
        auth_key.insert(auth_key.end(), auth_key_part2.begin(), auth_key_part2.end());

        // 2. Извлекаем Message Key из начала входящих данных
        uint8_t msg_key[16];
        std::memcpy(msg_key, input.data, 16);

        // 3. Запускаем KDF
        std::vector<uint8_t> aes_key, aes_iv;
        mtproto_kdf(auth_key, msg_key, aes_key, aes_iv);

        // 4. Инициализируем AES
        AES256 aes(aes_key);

        // Настраиваем вектора IGE (Для дешифрования они меняются местами!)
        uint8_t x_or_cipher[16]; // C_{i-1}
        uint8_t x_or_plain[16];  // P_{i-1}
        std::memcpy(x_or_cipher, &aes_iv[0], 16);
        std::memcpy(x_or_plain, &aes_iv[16], 16);

        size_t cipher_size = input.size - 16;
        if (output->size < cipher_size) return cipher_size;

        // 5. Цикл дешифрования IGE
        const uint8_t* cipher_ptr = input.data + 16;
        uint8_t* plain_ptr = output->data;

        for (size_t offset = 0; offset < cipher_size; offset += 16) {
            uint8_t ct_block[16];
            std::memcpy(ct_block, cipher_ptr + offset, 16);
            
            uint8_t pt_block[16];
            // Формула обратного IGE: P_i = D(C_i ^ P_{i-1}) ^ C_{i-1}
            for (int i = 0; i < 16; ++i) {
                pt_block[i] = ct_block[i] ^ x_or_plain[i];
            }

            aes.decryptBlock(pt_block);

            for (int i = 0; i < 16; ++i) {
                pt_block[i] ^= x_or_cipher[i];
            }

            std::memcpy(plain_ptr + offset, pt_block, 16);

            // Обновляем вектора (используем исходный шифротекст ct_block и полученный pt_block)
            std::memcpy(x_or_cipher, ct_block, 16);
            std::memcpy(x_or_plain, pt_block, 16);
        }

        output->size = cipher_size; // Реальный размер может быть чуть меньше из-за паддинга, но для бинарных файлов это ок
        return 0;
    }
}


// БЛОК ОТЛАДКИ (Раскомментируй строку ниже, чтобы протестировать ТОЛЬКО этот файл)
//
// Если строка #define DEBUG_ATBASH закомментирована, компилятор при сборке всего 
// проекта просто игнорирует код внутри #ifdef и #endif
//
// #define DEBUG_ATBASH 

#ifdef DEBUG_ATBASH
int main() {
    cout << "--- Отладка модуля MTProto ---" << endl;
    string test;
    cin >> test;
    string enc = encryptMTProto(test);
    cout << "Тест шифра: " << enc << endl;
    cout << "Тест дешифра: " << decryptMTProto(enc) << endl;
    return 0;
}
#endif


