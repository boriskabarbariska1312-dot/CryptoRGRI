#include <iostream>
#include <fstream>
#include <vector>
#include <cstring>
#include <cstdint>
#include <random>
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
    #define LIB_EXT ".so"
#endif

#include "crypto.h"

using namespace std;

const uint64_t CHUNK_SIZE = 65536;

const vector<string> SUPPORTED_ALGORITHMS = {"gronsfeld", "atbash"};

void safe_clear(uint8_t* ptr, uint64_t size) {
    if (!ptr) return;
#if defined(_WIN32)
    SecureZeroMemory(ptr, size);
#else
    std::memset(ptr, 0, size);
    // Ассемблерный барьер памяти для предотвращения удаления вызова компилятором при оптимизации
    asm volatile("" ::: "memory");
#endif
}

void print_help() {
    cout << "Cryptum: Multi-Algo Cryptotool\n";
    cout << "Использование:\n";
    cout << "  -a, --algorithm <name>    Имя алгоритма\n";
    cout << "  -m, --mode <mode>         Режим: encrypt, decrypt, generate-key\n";
    cout << "  -i, --input <path>        Входной файл (или - для stdin)\n";
    cout << "  -o, --output <path>       Выходной файл (или - для stdout)\n";
    cout << "  -k, --key <path>          Путь к файлу ключа (или - для stdin)\n";
    cout << "  -s, --save-key <path>     Путь сохранения ключа (или - для stdout)\n";
    cout << "  -h, --help                Справка\n\n";
    cout << "Список поддерживаемых алгоритмов:\n";
    for (const auto& algo : SUPPORTED_ALGORITHMS) {
        cout << "  - " << algo << "\n";
    }
}

void parse_arguments(int argc, char* argv[], string& algo_name, string& mode_str, string& input_path, string& output_path, string& key_path, string& save_key_path) {
    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "-a") == 0 || strcmp(argv[i], "--algorithm") == 0) {
            if (i + 1 < argc) algo_name = argv[++i];
            else throw runtime_error("Значение для аргумента алгоритма отсутствует");
        }
        else if (strcmp(argv[i], "-m") == 0 || strcmp(argv[i], "--mode") == 0) {
            if (i + 1 < argc) mode_str = argv[++i];
            else throw runtime_error("Значение для аргумента режима отсутствует");
        }
        else if (strcmp(argv[i], "-i") == 0 || strcmp(argv[i], "--input") == 0) {
            if (i + 1 < argc) input_path = argv[++i];
            else throw runtime_error("Значение для аргумента входного файла отсутствует");
        }
        else if (strcmp(argv[i], "-o") == 0 || strcmp(argv[i], "--output") == 0) {
            if (i + 1 < argc) output_path = argv[++i];
            else throw runtime_error("Значение для аргумента выходного файла отсутствует");
        }
        else if (strcmp(argv[i], "-k") == 0 || strcmp(argv[i], "--key") == 0) {
            if (i + 1 < argc) key_path = argv[++i];
            else throw runtime_error("Значение для аргумента ключа отсутствует");
        }
        else if (strcmp(argv[i], "-s") == 0 || strcmp(argv[i], "--save-key") == 0) {
            if (i + 1 < argc) save_key_path = argv[++i];
            else throw runtime_error("Значение для аргумента сохранения ключа отсутствует");
        }
        else {
            throw runtime_error(string("Неизвестный аргумент командной строки: ") + argv[i]);
        }
    }
}

LIB_HANDLE load_crypto_library(const string& algo_name) {
    string lib_path;
#if defined(_WIN32)
    lib_path = algo_name + LIB_EXT;
#else
    lib_path = "./lib" + algo_name + LIB_EXT;
#endif
    LIB_HANDLE handle = LOAD_LIB(lib_path);
    if (!handle) throw runtime_error("Ошибка загрузки библиотеки: " + lib_path);
    return handle;
}

int process_stream(istream& in_stream, ostream& out_stream, int op_type, ConstBuffer key_buf, 
                   size_t (*get_output_size_func)(size_t, int), 
                   int (*crypto_func)(ConstBuffer, ConstBuffer, MutBuffer*)) {
    
    size_t effective_chunk_size = CHUNK_SIZE;
    if (key_buf.size > 0) {
        // Выравнивание размера блока под размер ключа для корректной работы потоковых шифров
        effective_chunk_size = (CHUNK_SIZE / key_buf.size) * key_buf.size;
        if (effective_chunk_size == 0) effective_chunk_size = key_buf.size;
    }

    size_t read_block_size = effective_chunk_size;
    if (op_type == 2) {
        read_block_size = get_output_size_func(effective_chunk_size, 1);
    }

    vector<uint8_t> input_buffer(read_block_size);
    // Исправленный вызов функции без использования удаленных флагов потока
    size_t initial_out_size = get_output_size_func(read_block_size, op_type);
    vector<uint8_t> output_buffer(initial_out_size);
    int crypto_status = 0;

    while (true) {
        in_stream.read(reinterpret_cast<char*>(input_buffer.data()), read_block_size);
        size_t bytes_read = static_cast<size_t>(in_stream.gcount());
        
        if (bytes_read == 0) break; 

        ConstBuffer input_chunk = { input_buffer.data(), bytes_read };
        size_t expected_out_size = get_output_size_func(bytes_read, op_type);
        
        if (expected_out_size > output_buffer.size()) output_buffer.resize(expected_out_size);
        MutBuffer output_chunk = { output_buffer.data(), output_buffer.size() };

        crypto_status = crypto_func(key_buf, input_chunk, &output_chunk);

        if (crypto_status != 0) {
            cerr << "Ошибка в динамической библиотеке при обработке данных\n";
            break;
        }

        if (output_chunk.size > 0) {
            out_stream.write(reinterpret_cast<const char*>(output_chunk.data), output_chunk.size);
        }

        in_stream.peek();
        if (in_stream.eof() || !in_stream.good()) break;
    }
    
    // Гарантированная очистка векторов с критическими данными перед выходом из функции
    safe_clear(input_buffer.data(), input_buffer.size());
    safe_clear(output_buffer.data(), output_buffer.size());
    return crypto_status;
}

int main(int argc, char* argv[]) {
    try {
#if defined(_WIN32)
        SetConsoleOutputCP(CP_UTF8);
        SetConsoleCP(CP_UTF8);
        _setmode(_fileno(stdin), _O_BINARY);
        _setmode(_fileno(stdout), _O_BINARY);
#endif

        if (argc == 1) {
            print_help();
            return 0;
        }
        for (int i = 1; i < argc; ++i) {
            if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
                print_help();
                return 0;
            }
        }

        string algo_name, mode_str, input_path, output_path, key_path, save_key_path;
        parse_arguments(argc, argv, algo_name, mode_str, input_path, output_path, key_path, save_key_path);

        if ((key_path == "-" && input_path == "-") || (save_key_path == "-" && output_path == "-")) {
            print_help();
            return 0;
        }

        if (algo_name.empty() || mode_str.empty()) {
            throw runtime_error("Отсутствуют обязательные аргументы алгоритма или режима");
        }

        if (find(SUPPORTED_ALGORITHMS.begin(), SUPPORTED_ALGORITHMS.end(), algo_name) == SUPPORTED_ALGORITHMS.end()) {
            throw runtime_error("Указанный алгоритм '" + algo_name + "' не поддерживается");
        }

        if (mode_str != "encrypt" && mode_str != "decrypt" && mode_str != "generate-key") {
            throw runtime_error("Неподдерживаемый режим '" + mode_str + "'");
        }

        if ((mode_str == "encrypt" || mode_str == "decrypt") && key_path.empty()) {
            throw runtime_error("Отсутствует обязательный аргумент: путь к файлу ключа (-k, --key)");
        }

        LIB_HANDLE handle = load_crypto_library(algo_name);

        auto get_algo_info = (const AlgorithmInfo* (*)())GET_FUNC(handle, "get_algorithm_info");
        auto get_output_size_func = (size_t (*)(size_t, int))GET_FUNC(handle, "get_output_size");
        auto encrypt_func = (int (*)(ConstBuffer, ConstBuffer, MutBuffer*))GET_FUNC(handle, "encrypt");
        auto decrypt_func = (int (*)(ConstBuffer, ConstBuffer, MutBuffer*))GET_FUNC(handle, "decrypt");

        if (!get_algo_info || !get_output_size_func || !encrypt_func || !decrypt_func) {
            CLOSE_LIB(handle);
            throw runtime_error("Некорректная библиотека: отсутствуют требуемые функции");
        }

        const AlgorithmInfo* info = get_algo_info();

        if (mode_str == "generate-key") {
            if (save_key_path.empty()) {
                CLOSE_LIB(handle);
                throw runtime_error("Не указан путь для сохранения ключа");
            }
            uint64_t k_size = info->key_size == 0 ? 16 : info->key_size; 
            vector<uint8_t> new_key(k_size);
            random_device rd; 
            
            std::generate(new_key.begin(), new_key.end(), [&rd]() { return static_cast<uint8_t>(rd() & 0xFF); });

            ostream* key_out_stream = &cout;
            ofstream key_out_file;
            if (save_key_path != "-") {
                key_out_file.open(save_key_path, ios::binary);
                if (!key_out_file) throw runtime_error("Ошибка записи ключа в файл");
                key_out_stream = &key_out_file;
            }
            
            key_out_stream->write(reinterpret_cast<const char*>(new_key.data()), new_key.size());
            if (save_key_path != "-") cout << "\nКлюч успешно сгенерирован\n";
            
            safe_clear(new_key.data(), new_key.size());
            CLOSE_LIB(handle);
            return 0;
        }

        vector<uint8_t> key_data;
        if (!key_path.empty()) {
            if (key_path == "-") {
                char ch;
                while (cin.get(ch)) key_data.push_back(static_cast<uint8_t>(ch));
                cin.clear();
            } else {
                ifstream kf(key_path, ios::binary | ios::ate);
                if (!kf.is_open()) {
                    CLOSE_LIB(handle);
                    throw runtime_error("Не удалось открыть файл ключа");
                }
                streamsize size = kf.tellg();
                kf.seekg(0, ios::beg);
                key_data.resize(size);
                kf.read(reinterpret_cast<char*>(key_data.data()), size);
                kf.close();
            }
        }

        int op_type = 0;
        auto crypto_func = encrypt_func;
        if (mode_str == "encrypt") {
            op_type = 1;
            crypto_func = encrypt_func;
        } else if (mode_str == "decrypt") {
            op_type = 2;
            crypto_func = decrypt_func;
        }

        istream* in_stream = &cin;
        ostream* out_stream = &cout;
        ifstream in_file;
        ofstream out_file;

        if (!input_path.empty() && input_path != "-") {
            in_file.open(input_path, ios::binary);
            if (!in_file.is_open()) {
                CLOSE_LIB(handle);
                safe_clear(key_data.data(), key_data.size());
                throw runtime_error("Ошибка открытия входного файла");
            }
            in_stream = &in_file;
        }

        if (!output_path.empty() && output_path != "-") {
            out_file.open(output_path, ios::binary);
            if (!out_file.is_open()) {
                CLOSE_LIB(handle);
                safe_clear(key_data.data(), key_data.size());
                throw runtime_error("Ошибка открытия выходного файла");
            }
            out_stream = &out_file;
        }

        ConstBuffer key_buf = { key_data.data(), key_data.size() };

        int crypto_status = process_stream(*in_stream, *out_stream, op_type, key_buf, get_output_size_func, crypto_func);

        safe_clear(key_data.data(), key_data.size());

        if (in_file.is_open()) in_file.close();
        if (out_file.is_open()) out_file.close();
        CLOSE_LIB(handle);

        return crypto_status;
    } catch (const exception& e) {
        cerr << "Произошла ошибка: " << e.what() << "\n";
        return 1;
    }
}