#include "AES256.h"
#include "SHA256.h"
#include <vector>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <iomanip>  // Для setw и setfill
#include <string>   // Для std::string

using namespace std; // Чтобы не писать std:: перед cout, string и hex

// Базовые структуры (Должны быть в самом начале файла!)
struct ConstBuffer {
    const uint8_t* data;
    size_t size;
};

struct MutBuffer {
    uint8_t* data;
    size_t size;
};

struct AlgorithmInfo {
    const char* name;
    uint64_t key_size; 
    uint64_t block_size;
};

namespace {
    // Внутренняя функция для красивого дампа байт в консоль
    void print_hex(const string& label, const uint8_t* data, size_t len) {
        cout << "[MTPROTO STEP] " << label << ": ";
        for (size_t i = 0; i < len; ++i) {
            cout << hex << setw(2) << setfill('0') << (int)data[i] << " ";
        }
        cout << dec << "\n";
    }

    // Внутренняя функция KDF (Генерация ключей по стандарту MTProto 2.0)
    void mtproto_kdf(const std::vector<uint8_t>& auth_key, const uint8_t* msg_key, 
                     std::vector<uint8_t>& aes_key, std::vector<uint8_t>& aes_iv) {
        
        aes_key.resize(32);
        aes_iv.resize(32);

        std::vector<uint8_t> bufferA;
        bufferA.insert(bufferA.end(), msg_key, msg_key + 16);
        bufferA.insert(bufferA.end(), auth_key.begin(), auth_key.begin() + 32);
        std::vector<uint8_t> sha256a = calculate_sha256(bufferA);

        std::vector<uint8_t> bufferB;
        bufferB.insert(bufferB.end(), auth_key.begin() + 32, auth_key.begin() + 64);
        bufferB.insert(bufferB.end(), msg_key, msg_key + 16);
        std::vector<uint8_t> sha256b = calculate_sha256(bufferB);

        std::memcpy(&aes_key[0], &sha256a[0], 8);
        std::memcpy(&aes_key[8], &sha256b[8], 16);
        std::memcpy(&aes_key[24], &sha256a[24], 8);

        std::memcpy(&aes_iv[0], &sha256b[0], 8);
        std::memcpy(&aes_iv[8], &sha256a[8], 16);
        std::memcpy(&aes_iv[24], &sha256b[24], 8);
    }
}

// Экспортируем функции наружу
extern "C" {

    const AlgorithmInfo* get_algorithm_info() {
        static AlgorithmInfo info = { "MTProto 2.0 (AES-IGE)", 32, 16 };
        return &info;
    }

    size_t get_output_size(size_t input_size, int op_type) {
        if (op_type == 1) { 
            size_t padding = (16 - (input_size % 16)) % 16;
            return 16 + input_size + padding; 
        } else { 
            return input_size > 16 ? input_size - 16 : 0;
        }
    }

    int encrypt(ConstBuffer key, ConstBuffer input, MutBuffer* output) {
        if (!output || !output->data) return -1;

        cout << "\n=== НАЧАЛО ШИФРОВАНИЯ MTPROTO ===\n";
        print_hex("Входной пароль/ключ пользователя", key.data, key.size);

        std::vector<uint8_t> user_key(key.data, key.data + key.size);
        std::vector<uint8_t> auth_key = calculate_sha256(user_key);
        std::vector<uint8_t> auth_key_part2 = calculate_sha256(auth_key);
        auth_key.insert(auth_key.end(), auth_key_part2.begin(), auth_key_part2.end());
        
        print_hex("Сгенерированный Auth Key (64 байта)", auth_key.data(), 64);

        size_t payload_size = input.size;
        size_t padding = (16 - (payload_size % 16)) % 16;
        size_t encrypted_data_size = payload_size + padding;
        size_t total_needed = 16 + encrypted_data_size;

        if (output->size < total_needed) return total_needed;

        std::vector<uint8_t> data_to_hash(input.data, input.data + payload_size);
        std::vector<uint8_t> msg_key_hash = calculate_sha256(data_to_hash);
        uint8_t msg_key[16];
        std::memcpy(msg_key, msg_key_hash.data(), 16);
        
        print_hex("Вычисленный Message Key (16 байт хэша данных)", msg_key, 16);
        std::memcpy(output->data, msg_key, 16);

        std::vector<uint8_t> aes_key, aes_iv;
        mtproto_kdf(auth_key, msg_key, aes_key, aes_iv);
        
        print_hex("KDF: Вычисленный AES Key (32 байта)", aes_key.data(), 32);
        print_hex("KDF: Вычисленный AES IV (32 байта)", aes_iv.data(), 32);

        AES256 aes(aes_key);
        uint8_t x_or_cipher[16];
        uint8_t x_or_plain[16];
        std::memcpy(x_or_cipher, &aes_iv[0], 16);
        std::memcpy(x_or_plain, &aes_iv[16], 16);

        uint8_t* plain_ptr = const_cast<uint8_t*>(input.data);
        uint8_t* cipher_ptr = output->data + 16;

        cout << "--- Запуск сцепления блоков IGE ---\n";
        int block_num = 0;
        for (size_t offset = 0; offset < encrypted_data_size; offset += 16) {
            uint8_t pt_block[16] = {0};
            size_t to_copy = (payload_size - offset > 16) ? 16 : (payload_size - offset);
            std::memcpy(pt_block, plain_ptr + offset, to_copy);

            cout << "[Блок " << block_num << "] Исходный текст (hex): ";
            for(int i=0; i<16; i++) cout << hex << setw(2) << setfill('0') << (int)pt_block[i] << " ";
            cout << "\n";

            uint8_t ct_block[16];
            for (int i = 0; i < 16; ++i) ct_block[i] = pt_block[i] ^ x_or_cipher[i];
            
            aes.encryptBlock(ct_block);

            for (int i = 0; i < 16; ++i) ct_block[i] ^= x_or_plain[i];

            std::memcpy(cipher_ptr + offset, ct_block, 16);
            
            cout << "[Блок " << block_num << "] Шифротекст IGE (hex): ";
            for(int i=0; i<16; i++) cout << hex << setw(2) << setfill('0') << (int)ct_block[i] << " ";
            cout << "\n";

            std::memcpy(x_or_cipher, ct_block, 16);
            std::memcpy(x_or_plain, pt_block, 16);
            block_num++;
        }

        output->size = total_needed;
        cout << "=== ШИФРОВАНИЕ УСПЕШНО ЗАВЕРШЕНО ===\n\n";
        return 0;
    }

    int decrypt(ConstBuffer key, ConstBuffer input, MutBuffer* output) {
        if (!output || !output->data || input.size < 16) return -1;

        cout << "\n=== НАЧАЛО ДЕШИФРОВАНИЯ MTPROTO ===\n";
        
        std::vector<uint8_t> user_key(key.data, key.data + key.size);
        std::vector<uint8_t> auth_key = calculate_sha256(user_key);
        std::vector<uint8_t> auth_key_part2 = calculate_sha256(auth_key);
        auth_key.insert(auth_key.end(), auth_key_part2.begin(), auth_key_part2.end());

        uint8_t msg_key[16];
        std::memcpy(msg_key, input.data, 16);
        print_hex("Извлеченный из файла Message Key", msg_key, 16);

        std::vector<uint8_t> aes_key, aes_iv;
        mtproto_kdf(auth_key, msg_key, aes_key, aes_iv);
        
        print_hex("Восстановленный AES Key", aes_key.data(), 32);
        print_hex("Восстановленный AES IV", aes_iv.data(), 32);

        AES256 aes(aes_key);
        uint8_t x_or_cipher[16];
        uint8_t x_or_plain[16];
        std::memcpy(x_or_cipher, &aes_iv[0], 16);
        std::memcpy(x_or_plain, &aes_iv[16], 16);

        size_t cipher_size = input.size - 16;
        if (output->size < cipher_size) return cipher_size;

        const uint8_t* cipher_ptr = input.data + 16;
        uint8_t* plain_ptr = output->data;

        cout << "--- Запуск обратного сцепления блоков IGE ---\n";
        int block_num = 0;
        for (size_t offset = 0; offset < cipher_size; offset += 16) {
            uint8_t ct_block[16];
            std::memcpy(ct_block, cipher_ptr + offset, 16);
            
            uint8_t pt_block[16];
            for (int i = 0; i < 16; ++i) pt_block[i] = ct_block[i] ^ x_or_plain[i];

            aes.decryptBlock(pt_block);

            for (int i = 0; i < 16; ++i) pt_block[i] ^= x_or_cipher[i];

            std::memcpy(plain_ptr + offset, pt_block, 16);

            cout << "[Блок " << block_num << "] Расшифрованный текст: ";
            for(int i=0; i<16; i++) {
                if(pt_block[i] >= 32 && pt_block[i] <= 126) cout << (char)pt_block[i];
                else cout << "."; // Заменяем непечатные символы паддинга точкой
            }
            cout << "\n";

            std::memcpy(x_or_cipher, ct_block, 16);
            std::memcpy(x_or_plain, pt_block, 16);
            block_num++;
        }

        output->size = cipher_size;
        cout << "=== ДЕШИФРОВАНИЕ УСПЕШНО ЗАВЕРШЕНО ===\n\n";
        return 0;
    }
}
