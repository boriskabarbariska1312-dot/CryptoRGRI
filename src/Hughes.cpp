#include "crypto.h" // Подключаем наши базовые структуры
#include <iostream>
#include <vector>
#include <cstring>
#include <fstream>

using namespace std;

// Нам необходима функция быстрого возведения
// // Объявим её как extern, чтобы не дублировать код
extern int64_t powerBinary(int64_t base, int64_t exp, int64_t mod, bool show_steps);

// Структура ключа для Хьюза, чтобы удобно передавать все параметры через ConstBuffer key
struct HughesKey {
    int64_t n;
    int64_t a;
    int64_t b;
    int64_t a_inv;
    int64_t b_inv;
};

extern "C" {

    const AlgorithmInfo* get_algorithm_info() {
        static AlgorithmInfo info = { "Hughes Simulation Protocol", sizeof(HughesKey), 1 };
        return &info;
    }

    size_t get_output_size(size_t input_size, int op_type) {
        // В схеме Хьюза каждый байт (char) превращается в int64_t (8 байт) при шифровании,
        // чтобы избежать переполнения по модулю n.
        if (op_type == 1) { 
            return input_size * sizeof(int64_t); 
        } else { 
            return input_size / sizeof(int64_t);
        }
    }

    int encrypt(ConstBuffer key, ConstBuffer input, MutBuffer* output) {
        if (!output || !output->data || key.size < sizeof(HughesKey)) return -1;
        
        // Извлекаем математические ключи из буфера
        HughesKey k;
        std::memcpy(&k, key.data, sizeof(HughesKey));

        size_t needed_size = input.size * sizeof(int64_t);
        if (output->size < needed_size) return needed_size;

        // Создаем файлы для симуляции передачи данных
        // ofstream fileStep1("step1_alice.txt");
        ofstream fileStep2("step2_bob.txt");

        cout << "\nЗАПУСК ФАЙЛОВОГО КРИПТОПРОТОКОЛА ХЬЮЗА (ШИФРОВАНИЕ)\n";
        cout << "Промежуточные файлы шагов 1 и 2 будут сохранены.\n\n";

        const uint8_t* plain_ptr = input.data;
        int64_t* cipher_ptr = reinterpret_cast<int64_t*>(output->data);

        bool firstChar = true;

        for (size_t i = 0; i < input.size; ++i) {
            int64_t M = static_cast<unsigned char>(plain_ptr[i]);

            if (firstChar) {
                cout << "[Пример для первого символа '" << static_cast<char>(M) << "' (ASCII: " << M << ")]:\n";
            }

            // Проход 1: Алиса шифрует символ
            if (firstChar) cout << "[Проход 1] Алиса: C1 = M^a mod n\n";
            int64_t C1 = powerBinary(M, k.a, k.n, firstChar);
            fileStep1 << C1 << " ";

            // Проход 2: Боб накладывает свой ключ
            if (firstChar) cout << "[Проход 2] Боб: C2 = C1^b mod n\n";
            int64_t C2 = powerBinary(C1, k.b, k.n, firstChar);
            fileStep2 << C2 << " ";

            // Сохраняем C2 в выходной буфер
            cipher_ptr[i] = C2;

            if (firstChar) {
                cout << "[Математика для остальных символов скрыта, чтобы не перегружать вывод]\n";
                cout << "Идет потоковое шифрование буфера...\n";
                firstChar = false;
            }
        }

        fileStep1.close();
        fileStep2.close();
        
        output->size = needed_size;
        cout << "=== СИМУЛЯЦИЯ ХЬЮЗА: ЭТАП ШИФРОВАНИЯ ЗАВЕРШЕН ===\n\n";
        return 0;
    }

    int decrypt(ConstBuffer key, ConstBuffer input, MutBuffer* output) {
        if (!output || !output->data || key.size < sizeof(HughesKey)) return -1;

        HughesKey k;
        std::memcpy(&k, key.data, sizeof(HughesKey));

        size_t expected_plain_size = input.size / sizeof(int64_t);
        if (output->size < expected_plain_size) return expected_plain_size;

        ofstream fileStep3("step3_alice.txt");
        ofstream fileFinal("decrypted.txt");

        cout << "\nЗАПУСК ФАЙЛОВОГО КРИПТОПРОТОКОЛА ХЬЮЗА (ДЕШИФРОВАНИЕ)\n";
        cout << "Промежуточные файлы шагов 3 и финальный текст будут сохранены.\n\n";

        const int64_t* cipher_ptr = reinterpret_cast<const int64_t*>(input.data);
        uint8_t* plain_ptr = output->data;

        bool firstChar = true;
        string decryptedText = "";

        for (size_t i = 0; i < expected_plain_size; ++i) {
            int64_t C2 = cipher_ptr[i];

            if (firstChar) {
                cout << "[Дешифрование. Проверка первого блока C2 = " << C2 << "]\n";
            }

            // Проход 3: Алиса снимает свой ключ
            if (firstChar) cout << "[Проход 3] Алиса: C3 = C2^a_inv mod n\n";
            int64_t C3 = powerBinary(C2, k.a_inv, k.n, firstChar);
            fileStep3 << C3 << " ";

            // Финал: Боб дешифрует символ
            if (firstChar) cout << "[Финал] Боб: M_res = C3^b_inv mod n\n\n";
            int64_t M_res = powerBinary(C3, k.b_inv, k.n, firstChar);
            
            char decryptedChar = static_cast<char>(M_res);
            decryptedText += decryptedChar;
            fileFinal.put(decryptedChar);

            plain_ptr[i] = static_cast<uint8_t>(M_res);

            if (firstChar) {
                cout << "[Математика для остальных символов скрыта]\n";
                cout << "Идет восстановление исходного текста...\n";
                firstChar = false;
            }
        }

        fileStep3.close();
        fileFinal.close();

        cout << "\n============= РЕЗУЛЬТАТ СИМУЛЯЦИИ ХЬЮЗА =============" << endl;
        cout << "Расшифрованный текст Бобом:   \"" << decryptedText << "\"" << endl;
        cout << "Результат параллельно записан в файл: decrypted.txt\n";
        cout << "=====================================================" << endl;

        output->size = expected_plain_size;
        return 0;
    }
}
