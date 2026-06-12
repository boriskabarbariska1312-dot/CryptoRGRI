#include "crypto.h"
#include <cstdint>
#include <cstddef>
#include <cstring>

static const AlgorithmInfo RC4_INFO = {
    "rc4",
    16 // Дефолтный размер ключа (128 бит)
};

static void secure_wipe(void* ptr, size_t size) {
    if (!ptr) return;
    std::memset(ptr, 0, size);
    asm volatile("" ::: "memory");
}

extern "C" {

const AlgorithmInfo* get_algorithm_info() {
    return &RC4_INFO;
}

size_t get_output_size(size_t input_size, int operation_type) {
    return input_size;
}

static void rc4_crypt_internal(const uint8_t* key, size_t key_len, const uint8_t* input, size_t input_len, uint8_t* output) {
    uint8_t s_box[256];
    for (int i = 0; i < 256; ++i) {
        s_box[i] = static_cast<uint8_t>(i);
    }

    uint8_t j = 0;
    for (int i = 0; i < 256; ++i) {
        j = static_cast<uint8_t>(j + s_box[i] + key[i % key_len]);
        uint8_t temp = s_box[i];
        s_box[i] = s_box[j];
        s_box[j] = temp;
    }

    uint8_t idx_i = 0;
    uint8_t idx_j = 0;
    for (size_t k = 0; k < input_len; ++k) {
        idx_i = static_cast<uint8_t>(idx_i + 1);
        idx_j = static_cast<uint8_t>(idx_j + s_box[idx_i]);
        
        uint8_t temp = s_box[idx_i];
        s_box[idx_i] = s_box[idx_j];
        s_box[idx_j] = temp;

        uint8_t t = static_cast<uint8_t>(s_box[idx_i] + s_box[idx_j]);
        output[k] = input[k] ^ s_box[t];
    }

    secure_wipe(s_box, sizeof(s_box));
}

int encrypt(ConstBuffer key, ConstBuffer input, MutBuffer* output) {
    if (!output || output->size < input.size || !key.data || key.size == 0) {
        return 1;
    }
    rc4_crypt_internal(key.data, key.size, input.data, input.size, output->data);
    output->size = input.size;
    return 0;
}

int decrypt(ConstBuffer key, ConstBuffer input, MutBuffer* output) {
    if (!output || output->size < input.size || !key.data || key.size == 0) {
        return 1;
    }
    rc4_crypt_internal(key.data, key.size, input.data, input.size, output->data);
    output->size = input.size;
    return 0;
}

}
