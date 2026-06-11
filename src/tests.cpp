#include <iostream>
#include <vector>
#include <cstring>
#include <cstdint>
#include <algorithm>
#include <stdexcept>

#if defined(_WIN32)
    #include <windows.h>
    #define LIB_HANDLE HMODULE
    #define LOAD_LIB(path) LoadLibraryA(path.c_str())
    #define GET_FUNC(handle, name) GetProcAddress(handle, name)
    #define CLOSE_LIB(handle) FreeLibrary(handle)
    #define LIB_EXT ".dll"
#else
    #include <dlfcn.h>
    #define LIB_HANDLE void*
    #define LOAD_LIB(path) dlopen(path.c_str(), RTLD_LAZY)
    #define GET_FUNC(handle, name) dlsym(handle, name)
    #define CLOSE_LIB(handle) dlclose(handle)
    #define LIB_EXT ".so"
#endif

#include "crypto.h"

using namespace std;

void safe_clear(uint8_t* ptr, uint64_t size) {
    if (!ptr) return;
#if defined(_WIN32)
    SecureZeroMemory(ptr, size);
#else
    std::memset(ptr, 0, size);
    // Ассемблерный барьер памяти для предотвращения оптимизации очистки компилятором
    asm volatile("" ::: "memory");
#endif
}

void run_test_for_library(const string& lib_name) {
    string lib_path;
#if defined(_WIN32)
    lib_path = lib_name + LIB_EXT;
#else
    lib_path = "./lib" + lib_name + LIB_EXT;
#endif

    LIB_HANDLE handle = LOAD_LIB(lib_path);
    if (!handle) {
        throw runtime_error("Не удалось загрузить библиотеку для тестов: " + lib_path);
    }

    auto get_output_size_func = (size_t (*)(size_t, int))GET_FUNC(handle, "get_output_size");
    auto encrypt_func = (int (*)(ConstBuffer, ConstBuffer, MutBuffer*))GET_FUNC(handle, "encrypt");
    auto decrypt_func = (int (*)(ConstBuffer, ConstBuffer, MutBuffer*))GET_FUNC(handle, "decrypt");
    auto encrypt_with_iv_func = (int (*)(ConstBuffer, ConstBuffer, ConstBuffer, MutBuffer*))GET_FUNC(handle, "encrypt_with_iv");

    if (!get_output_size_func || !encrypt_func || !decrypt_func || !encrypt_with_iv_func) {
        CLOSE_LIB(handle);
        throw runtime_error("Библиотека " + lib_name + " не экспортирует все требуемые функции");
    }

    vector<vector<uint8_t>> test_inputs = {
        {'H', 'e', 'l', 'l', 'o'},
        {'C', '+', '+', '2', '0', '2', '6'},
        {0, 1, 2, 255, 128, 64}
    };

    vector<uint8_t> key_data = {'3', '1', '4'};
    ConstBuffer key_buf = {key_data.data(), key_data.size()};

    try {
        for (uint64_t idx = 0; idx < test_inputs.size(); ++idx) {
            vector<uint8_t>& original = test_inputs[idx];
            
            vector<uint8_t> encrypted(get_output_size_func(original.size(), 1));
            ConstBuffer in_buf = {original.data(), original.size()};
            MutBuffer out_mut = {encrypted.data(), encrypted.size()};
            
            if (encrypt_func(key_buf, in_buf, &out_mut) != 0) {
                safe_clear(encrypted.data(), encrypted.size());
                throw runtime_error("Ошибка при вызове encrypt в " + lib_name);
            }
            encrypted.resize(out_mut.size);

            vector<uint8_t> decrypted(get_output_size_func(encrypted.size(), 2));
            ConstBuffer dec_in_buf = {encrypted.data(), encrypted.size()};
            MutBuffer dec_out_buf = {decrypted.data(), decrypted.size()};

            if (decrypt_func(key_buf, dec_in_buf, &dec_out_buf) != 0) {
                safe_clear(encrypted.data(), encrypted.size());
                safe_clear(decrypted.data(), decrypted.size());
                throw runtime_error("Ошибка при вызове decrypt в " + lib_name);
            }
            decrypted.resize(dec_out_buf.size);

            if (!std::equal(original.begin(), original.end(), decrypted.begin())) {
                safe_clear(encrypted.data(), encrypted.size());
                safe_clear(decrypted.data(), decrypted.size());
                throw runtime_error("Данные после расшифрования не совпадают с исходными в " + lib_name);
            }

            vector<uint8_t> iv_data = {'I', 'V'};
            ConstBuffer iv_buf = {iv_data.data(), iv_data.size()};
            vector<uint8_t> out_iv(get_output_size_func(original.size(), 1) + iv_data.size());
            MutBuffer out_mut_iv = {out_iv.data(), out_iv.size()};
            
            if (encrypt_with_iv_func(key_buf, iv_buf, in_buf, &out_mut_iv) != 0) {
                safe_clear(iv_data.data(), iv_data.size());
                safe_clear(out_iv.data(), out_iv.size());
                safe_clear(encrypted.data(), encrypted.size());
                safe_clear(decrypted.data(), decrypted.size());
                throw runtime_error("Ошибка при вызове encrypt_with_iv в " + lib_name);
            }
            
            safe_clear(iv_data.data(), iv_data.size());
            safe_clear(out_iv.data(), out_iv.size());
            safe_clear(encrypted.data(), encrypted.size());
            safe_clear(decrypted.data(), decrypted.size());
        }
    } catch (...) {
        // Очистка при возникновении любых исключений в процессе тестирования
        for (uint64_t idx = 0; idx < test_inputs.size(); ++idx) {
            safe_clear(test_inputs[idx].data(), test_inputs[idx].size());
        }
        safe_clear(key_data.data(), key_data.size());
        CLOSE_LIB(handle);
        throw; // Перенаправление исключения в вызывающий контекст main()
    }

    for (uint64_t idx = 0; idx < test_inputs.size(); ++idx) {
        safe_clear(test_inputs[idx].data(), test_inputs[idx].size());
    }
    safe_clear(key_data.data(), key_data.size());
    CLOSE_LIB(handle);
}

int main() {
    try {
        run_test_for_library("gronsfeld");
        run_test_for_library("atbash");
        cout << "Тестирование завершено без ошибок\n";
        return 0;
    } catch (const exception& e) {
        cerr << "Ошибка тестирования: " << e.what() << "\n";
        return 1;
    }
}