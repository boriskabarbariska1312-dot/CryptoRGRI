#include <iostream>
#include <vector>
#include <cstring>
#include <cstdint>
#include <algorithm>
#include <stdexcept>

#if defined(_WIN32)
    #include <windows.h>
    #include <fcntl.h>
    #include <io.h>
    #define LIB_HANDLE HMODULE
    #define LOAD_LIB(path) LoadLibraryA(path.c_str())
    #define GET_FUNC(handle, name) GetProcAddress(handle, name)
    #define CLOSE_LIB(handle) FreeLibrary(handle)
    #define LIB_EXT ".dll"
#else
    #include <dlfcn.h>
    #include <string.h>
    #define LIB_HANDLE void*
    #define LOAD_LIB(path) dlopen(path.c_str(), RTLD_LAZY)
    #define GET_FUNC(handle, name) dlsym(handle, name)
    #define CLOSE_LIB(handle) dlclose(handle)
    #if defined(__APPLE__)
        #define LIB_EXT ".dylib"
    #else
        #define LIB_EXT ".so"
    #endif
#endif

struct LibraryGuard {
    LIB_HANDLE handle = nullptr;
    LibraryGuard(LIB_HANDLE h) : handle(h) {}
    ~LibraryGuard() {
        if (handle) {
            CLOSE_LIB(handle);
        }
    }
    LibraryGuard(const LibraryGuard&) = delete;
    LibraryGuard& operator=(const LibraryGuard&) = delete;
};

#include "crypto.h"
using namespace std;

void safe_clear(uint8_t* ptr, uint64_t size) {
    if (!ptr || size == 0) return;
#if defined(_WIN32)
    SecureZeroMemory(ptr, size);
#else
    std::memset(ptr, 0, size);
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

    LIB_HANDLE raw_handle = LOAD_LIB(lib_path);
    if (!raw_handle) {
        throw runtime_error("Не удалось загрузить библиотеку для тестов: " + lib_path);
    }
    LibraryGuard guard(raw_handle);

    auto get_output_size_func = (size_t (*)(size_t, int))GET_FUNC(raw_handle, "get_output_size");
    auto encrypt_func = (int (*)(ConstBuffer, ConstBuffer, MutBuffer*))GET_FUNC(raw_handle, "encrypt");
    auto decrypt_func = (int (*)(ConstBuffer, ConstBuffer, MutBuffer*))GET_FUNC(raw_handle, "decrypt");

    if (!get_output_size_func || !encrypt_func || !decrypt_func) {
        throw runtime_error("Библиотека " + lib_name + " не экспортирует базовые функции");
    }

    vector<vector<uint8_t>> test_inputs = {
        {'H', 'e', 'l', 'l', 'o'},
        {'C', '+', '+', '2', '0', '2', '6'}
    };

    vector<uint8_t> key_data = (lib_name == "mtproto") ? vector<uint8_t>(256, 0x4A) : vector<uint8_t>(16, 0x11);
    ConstBuffer key_buf = {key_data.data(), key_data.size()};

    for (const auto& original : test_inputs) {
        vector<uint8_t> encrypted(get_output_size_func(original.size(), 1));
        ConstBuffer in_buf = {original.data(), original.size()};
        MutBuffer out_mut = {encrypted.data(), encrypted.size()};
        
        if (encrypt_func(key_buf, in_buf, &out_mut) != 0) {
            throw runtime_error("Ошибка при вызове encrypt в " + lib_name);
        }
        encrypted.resize(out_mut.size);

        if (lib_name == "sha256") {
            if (encrypted.size() != 32) {
                throw runtime_error("SHA256 вернул неверный размер хэша");
            }
            continue; // Пропускаем дешифрование
        }

        // Для остальных алгоритмов выполняем полную проверку
        vector<uint8_t> decrypted(get_output_size_func(encrypted.size(), 2));
        ConstBuffer dec_in_buf = {encrypted.data(), encrypted.size()};
        MutBuffer dec_out_buf = {decrypted.data(), decrypted.size()};

        if (decrypt_func(key_buf, dec_in_buf, &dec_out_buf) != 0) {
            throw runtime_error("Ошибка при вызове decrypt в " + lib_name);
        }
        decrypted.resize(dec_out_buf.size);

        if (!std::equal(original.begin(), original.end(), decrypted.begin(), decrypted.end())) {
            throw runtime_error("Данные после расшифрования не совпадают в " + lib_name);
        }
    }
}

int main() {
    try {
        run_test_for_library("gronsfeld");
        run_test_for_library("atbash");
        run_test_for_library("rc4");
        run_test_for_library("blowfish");
        run_test_for_library("mtproto");
        run_test_for_library("sha256"); 
        cout << "Тестирование завершено без ошибок\n";
        return 0;
    } catch (const exception& e) {
        cerr << "Ошибка тестирования: " << e.what() << "\n";
        return 1;
    }
}