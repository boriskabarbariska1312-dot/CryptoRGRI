#include "crypto.h"
#include <algorithm>

extern "C" const AlgorithmInfo* get_algorithm_info() {
    static const AlgorithmInfo INFO = {"Atbash", 0}; 
    return &INFO;
}

extern "C" size_t get_output_size(size_t input_size, int operation_type) {
    (void)operation_type;
    return input_size; 
}

extern "C" int encrypt(ConstBuffer key, ConstBuffer input, MutBuffer* output) {
    (void)key;
    if (output->size < input.size) return 1;

    std::transform(input.data, input.data + input.size, output->data, [](uint8_t in_byte) {
        return static_cast<uint8_t>(255 - in_byte);
    });
    
    output->size = input.size;
    return 0;
}

extern "C" int decrypt(ConstBuffer key, ConstBuffer input, MutBuffer* output) {
    return encrypt(key, input, output);
}

extern "C" int encrypt_with_iv(ConstBuffer key, ConstBuffer iv, ConstBuffer input, MutBuffer* output) {
    (void)iv;
    return encrypt(key, input, output);
}