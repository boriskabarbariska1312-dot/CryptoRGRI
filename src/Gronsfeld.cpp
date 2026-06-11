#include "crypto.h"

extern "C" const AlgorithmInfo* get_algorithm_info() {
    static const AlgorithmInfo INFO = {"Gronsfeld", 0}; 
    return &INFO;
}

extern "C" size_t get_output_size(size_t input_size, int operation_type) {
    (void)operation_type;
    return input_size; 
}

extern "C" int encrypt(ConstBuffer key, ConstBuffer input, MutBuffer* output) {
    if (key.size == 0 || output->size < input.size) return 1;

    for (size_t i = 0; i < input.size; ++i) {
        uint8_t key_byte = key.data[i % key.size];
        uint8_t shift = (key_byte >= '0' && key_byte <= '9') ? (key_byte - '0') : (key_byte % 10);
        output->data[i] = static_cast<uint8_t>((input.data[i] + shift) % 256);
    }
    
    output->size = input.size;
    return 0;
}

extern "C" int decrypt(ConstBuffer key, ConstBuffer input, MutBuffer* output) {
    if (key.size == 0 || output->size < input.size) return 1;

    for (size_t i = 0; i < input.size; ++i) {
        uint8_t key_byte = key.data[i % key.size];
        uint8_t shift = (key_byte >= '0' && key_byte <= '9') ? (key_byte - '0') : (key_byte % 10);
        output->data[i] = static_cast<uint8_t>((input.data[i] - shift + 256) % 256);
    }
    
    output->size = input.size;
    return 0;
}

extern "C" int encrypt_with_iv(ConstBuffer key, ConstBuffer iv, ConstBuffer input, MutBuffer* output) {
    (void)iv;
    return encrypt(key, input, output);
}