#include "crypto.h"
#include <cstdint>
#include <cstddef>
#include <cstring>
#include <random>

static const AlgorithmInfo BLOWFISH_INFO = {
    "blowfish",
    16 // Дефолтный размер ключа (128 бит)
};

static const uint32_t ORIG_P[18] = {
    0x243F6A88, 0x85A308D3, 0x13198A2E, 0x03707344, 0xA4093822, 0x299F31D0,
    0x082EFA98, 0xEC4E6C89, 0x452821E6, 0x38D01377, 0xBE5466CF, 0x34E90C6C,
    0xC0AC29B7, 0xC97C50DD, 0x3F84D5B5, 0xB5470917, 0x9216D5D9, 0x8979FB1B
};

static const uint32_t ORIG_S[4][256] = {
    { 0xD1310BA6, 0x98DFB5AC, 0x2FFD72DB, 0xD01ADFB7, 0xB8E1AFED, 0x6A267E96, 0xBA7C9045, 0xF12C7F99,
      0x24A19947, 0xB3916CF7, 0x0801F2E2, 0x858EFC16, 0x636920D8, 0x71574E69, 0xA458FEA3, 0x9493DA1F,
      0x3A3A8E0D, 0x2AF606CD, 0x90C09AF5, 0x6E65742C, 0x01AA375E, 0x90A1A22C, 0x310DDF7F, 0x232B4527,
      0x7BE480D6, 0x3AA4576C, 0x8E87CC04, 0xFA93E7BD, 0x3C47BD78, 0xB7A1B28C, 0x1B8246DE, 0x264903E5,
      0x4FA43DB3, 0xA26F526F, 0xFEB42AA0, 0xA11F1869, 0xF8C1C6C7, 0x30DB9EA5, 0x729CD937, 0x2A155353,
      0x05EED51B, 0x6FE3EF00, 0x1654BE38, 0x7AA89E5F, 0x8DA442FB, 0x165AE849, 0xCC1EFDC3, 0xD411EF97,
      0xFA09CC97, 0x6E0151CD, 0x629B4F83, 0xACF142D0, 0x9816EEB9, 0xA8E4D5CE, 0x973DCC94, 0x65F93845,
      0x1CA2AB2D, 0x6FA96105, 0xCEAA49DF, 0xF09C157E, 0x47CEBEFB, 0x4DA2FE2D, 0x9BD0DF81, 0x24C833FA,
      0xCFEE1EB3, 0x1A1BE4EA, 0xDABAFE08, 0x0BCB1DC2, 0xAC0E8AC7, 0xDEEBDEB4, 0xEBBE2461, 0x90E383A2,
      0x5900BA92, 0x2A5CEF04, 0x51E2833F, 0xEA23B755, 0x7CB5F858, 0xA0A22DCD, 0x58249EE9, 0x8BE36294,
      0xD600A632, 0xAC36CE28, 0xBDB4856E, 0xB90ED5EC, 0x6342DE58, 0xB3992383, 0x05F5594C, 0x8EFE60FF,
      0xF2B37EA0, 0xEF91CD93, 0xBFA8DA28, 0x627FF5CD, 0x69680E79, 0xB66E04AA, 0x60010E05, 0xFA3CBB6D,
      0x96BAE745, 0xE7B2DDE1, 0x5DFB36EF, 0x67BEFE77, 0x759EF4BE, 0x78E4F102, 0x77A55651, 0xBE97CB93,
      0x5A7D8DF5, 0xB0DC88D6, 0x44621C39, 0xA89AD3FA, 0x5A599A41, 0x8BE3F94D, 0x487920A3, 0xFB847B49,
      0x4EA571DE, 0x647AE50B, 0x2B4B6A68, 0xA2FB8858, 0xDF2749EE, 0x14674AC7, 0xEBD25D61, 0x4E30CC52,
      0xCD1ECFA6, 0x356A2EFA, 0x34C691CE, 0x8EBEEB03, 0x4C795328, 0x7F2C0B81, 0xAAD56BE8, 0x9E756C5B },
    { 0x55B0FDC7, 0x3BF843EB, 0x07ED78E0, 0x7CB6FB99, 0xC490FB57, 0xDC059EDF, 0x302D0B65, 0x8797D74F,
      0xED49BC10, 0xAA6BD34F, 0xDC6D8CE8, 0xD748B4FA, 0x101ED9BF, 0xA6ED46FA, 0xDFEE2FE7, 0x06798C22,
      0xC96A9EB6, 0x3B643444, 0x4F05CE0E, 0x3567CE79, 0x21F648D4, 0x6917A004, 0x1E059A1D, 0x9EF054BE,
      0x301BE731, 0xAC3AA8A6, 0x05E6CAFA, 0x6C3970E4, 0xB7114A51, 0x6001004F, 0x58D5FBE6, 0xB94A6B64,
      0xDD9FE2CB, 0xA7756195, 0xF94F250B, 0x9F419616, 0x599C8DF8, 0x215456A8, 0xCC1EA3CB, 0xA08ED6DE,
      0xC41AA8A2, 0xF7245B13, 0xCDA5A826, 0xC42D2D49, 0x66B72D1D, 0x27C17B9E, 0x49B3DFD7, 0xDF41D9C5,
      0xD689C82A, 0x0D0E1FCE, 0x30F135DE, 0xF7643BA3, 0x60DF12B9, 0xCC8C33EC, 0x0CE6631E, 0xF8D8FF61,
      0xA65FEF4F, 0x4896EB44, 0xCD2AF15B, 0x9D9E3352, 0xAEBE60AA, 0x7A1DFB7C, 0xA99868FA, 0x47B0FC90,
      0x573EE5A7, 0x5847B074, 0xAC1080DA, 0xFAEDB453, 0x0BCC2524, 0xF1ECFA4E, 0x47D4C84C, 0xA4FCEB7F,
      0x273AF08C, 0xB8A375E0, 0xF9A77AF5, 0x3F6F60E8, 0xA3AF7A97, 0x4642C026, 0x91F5B2F9, 0x37A43B2B,
      0x7A4C6246, 0x4FF603A0, 0xF24DE42B, 0xB295EFCE, 0xCD54CECD, 0x46E44616, 0x8BE36240, 0x76E845EF,
      0x3CD24E1F, 0xDAB13C4A, 0xE9B6A1DF, 0x6EEBEB97, 0xF2A0DE12, 0xB94ECF69, 0x41ADF492, 0x5908C8B1,
      0x7687CC0A, 0xB0AA0B13, 0x5BE14EB6, 0x1D23A004, 0xA27A6783, 0xACADED2E, 0x0A0DE7AF, 0x5BD0390E,
      0x5E81A0B6, 0x1E59C733, 0x51EAE3A5, 0x33441A96, 0xC6A69A16, 0xCBE5D41A, 0x22ADECB7, 0xB880B84C,
      0x2B99D0F3, 0x98A110CD, 0x20CD28B9, 0xB39E1F03, 0x14AA8717, 0xC3B3C842, 0x8B321FF3, 0x199DCF8F,
      0x054813EE, 0xFB27EA50, 0xF9A4752A, 0xEFCEB4FB, 0xCA99AF3B, 0xACFFCD1F, 0xAE199BD2, 0x5E62A292 },
    { 0x8630A7B0, 0x130E090F, 0x4B066904, 0xB7073CD1, 0xAC7D5492, 0x52E8E423, 0x91361CDA, 0x5AEC2033,
      0x21172A14, 0xCEAA20E0, 0xEE2A35CE, 0x61FAAA92, 0x356A21CE, 0xD7FF402E, 0x83B7FFCD, 0x1EFE4AFA,
      0xAF1AF1AE, 0xD4C923B3, 0x9AEE0DCC, 0xE9A5087F, 0xB85EA4B8, 0xC2630EA1, 0xAF67E7DE, 0xFA55A943,
      0xB966F745, 0xBE2848EA, 0xD54CDDCE, 0xDA2EE005, 0x50C6A6BE, 0xAA6E342F, 0x1BCCF4B8, 0x5AF48473,
      0xFA593F0F, 0x203DCECC, 0x221375B8, 0xFCAE013A, 0x1FA2C7DC, 0xFED4A02A, 0x6EEAE9A0, 0x36FFD2A8,
      0x4FDFDCB9, 0xCEE7AF33, 0x82EC21BC, 0xCD2B40AE, 0xB7DCEF4B, 0xEBBEAE65, 0x501AE84E, 0x08FEE998,
      0xAB7411E9, 0x04C05DFB, 0x3847BF6D, 0xEFB0C04D, 0xFD46EE89, 0xEAE755AF, 0xCE27E9F4, 0xD63140CE,
      0xFEAC45EE, 0xEB69B134, 0x2E6FA4A0, 0xDF27B910, 0xC0904E09, 0x4C776D38, 0xD7BEEA92, 0x2C46ED4F,
      0xB405B6F2, 0x959E7E0D, 0xC5930FB9, 0x066DE36D, 0xCE8E4D53, 0xD88E4EE4, 0x9B15F797, 0xCFDF2466,
      0xF74C40AE, 0xD66CE7D4, 0x486955E9, 0xB64EEB4E, 0xD41A58FA, 0x7E36C2CD, 0x8EBEE0B5, 0x8EAC4C85,
      0xD68DF5A1, 0xCC111FEE, 0x1D23A7CE, 0x48B775B3, 0xACCA1AC4, 0x56DE8CE8, 0x6E4AA3A6, 0x44D4E8DC,
      0x4FF60EEA, 0xCD2F2A1E, 0xD726DE45, 0xB64A9EC9, 0x47EFF5AF, 0xB6CD4606, 0xB04EE6A8, 0xCDDFEB64,
      0x629C640A, 0xB5A429C5, 0x3B6686AA, 0x3A6A0EE2, 0xCBE3AE37, 0x8EE6A3CE, 0xC263BEE9, 0x3FEF72D0,
      0xB36EE9DE, 0xF975BAFA, 0x94B5E4F5, 0x6E6688EE, 0xD991F264, 0xCEE7F0FF, 0x054EA3A1, 0x4ED6CE1F,
      0xCE9BECE8, 0x32A26F3E, 0x6ED905C8, 0x60010EAE, 0x3F6E2FE2, 0x296E3DFF, 0x40AC7BE4, 0x59EE4230,
      0x4FF6AC4E, 0x9C0AC55F, 0x47B01ED5, 0xE0AC69AA, 0x3CBA60EE, 0x2ECA9B04, 0xCDA5A84F, 0xCD2A7FFB },
    { 0xFF1EEAE3, 0x5BEE48C1, 0x9AC267ED, 0x8A7E00CE, 0xCC1EEACE, 0x94E866A1, 0x696803AA, 0xBFF6CE28,
      0x27EE48AA, 0xC290D5CE, 0xD34D66A8, 0x49EE11CE, 0x43EABEE9, 0xCD1ECFA8, 0xEFEAEFAC, 0x27ECAEAA,
      0x5A3CBAEF, 0x221DEACE, 0x4AC7BD20, 0xCD1EB6A6, 0xD4B02EAA, 0xCDAC2EFA, 0x23EA00EE, 0x4B3A2CFA,
      0x3FEFE7AA, 0xCDBA60EE, 0x6EEACEEF, 0xCDA57FAA, 0x32A00EEA, 0x49EE23BA, 0x39EFE2FA, 0xC3BA00AA,
      0x7EFECEF4, 0x1EAEAEAA, 0x29EE34CF, 0xB3AA3F2D, 0x7E3A00EF, 0x4FE3CD7A, 0x6EEBBEA9, 0x39EFE7AA,
      0x4FDFDCB9, 0xCEE7AF33, 0x82EC21BC, 0xCD2B40AE, 0xB7DCEF4B, 0xEBBEAE65, 0x501AE84E, 0x08FEE998,
      0xD689C82A, 0x0D0E1FCE, 0x30F135DE, 0xF7643BA3, 0x60DF12B9, 0xCC8C33EC, 0x0CE6631E, 0xF8D8FF61,
      0xA65FEF4F, 0x4896EB44, 0xCD2AF15B, 0x9D9E3352, 0xAEBE60AA, 0x7A1DFB7C, 0xA99868FA, 0x47B0FC90,
      0x55B0FDC7, 0x3BF843EB, 0x07ED78E0, 0x7CB6FB99, 0xC490FB57, 0xDC059EDF, 0x302D0B65, 0x8797D74F,
      0xD1310BA6, 0x98DFB5AC, 0x2FFD72DB, 0xD01ADFB7, 0xB8E1AFED, 0x6A267E96, 0xBA7C9045, 0xF12C7F99,
      0x24A19947, 0xB3916CF7, 0x0801F2E2, 0x858EFC16, 0x636920D8, 0x71574E69, 0xA458FEA3, 0x9493DA1F,
      0x3CD24E1F, 0xDAB13C4A, 0xE9B6A1DF, 0x6EEBEB97, 0xF2A0DE12, 0xB94ECF69, 0x41ADF492, 0x5908C8B1,
      0xB36EE9DE, 0xF975BAFA, 0x94B5E4F5, 0x6E6688EE, 0xD991F264, 0xCEE7F0FF, 0x054EA3A1, 0x4ED6CE1F,
      0xFA593F0F, 0x203DCECC, 0x221375B8, 0xFCAE013A, 0x1FA2C7DC, 0xFED4A02A, 0x6EEAE9A0, 0x36FFD2A8,
      0x3FEFE7AA, 0xCDBA60EE, 0x6EEACEEF, 0xCDA57FAA, 0x32A00EEA, 0x49EE23BA, 0x39EFE2FA, 0xC3BA00AA,
      0xCD1ECFA6, 0x356A2EFA, 0x34C691CE, 0x8EBEEB03, 0x4C795328, 0x7F2C0B81, 0xAAD56BE8, 0x9E756C5B }
};

static void secure_wipe(void* ptr, size_t size) {
    if (!ptr) return;
    std::memset(ptr, 0, size);
    asm volatile("" ::: "memory");
}

static uint32_t blowfish_f(uint32_t x, const uint32_t s_box[4][256]) {
    uint8_t h1 = (x >> 24) & 0xFF;
    uint8_t h2 = (x >> 16) & 0xFF;
    uint8_t h3 = (x >> 8) & 0xFF;
    uint8_t h4 = x & 0xFF;

    uint32_t y = s_box[0][h1] + s_box[1][h2];
    y = y ^ s_box[2][h3];
    y = y + s_box[3][h4];
    return y;
}

static void blowfish_encrypt_block(uint32_t* xl, uint32_t* xr, const uint32_t p_array[18], const uint32_t s_box[4][256]) {
    uint32_t l = *xl;
    uint32_t r = *xr;

    for (int i = 0; i < 16; ++i) {
        l ^= p_array[i];
        r ^= blowfish_f(l, s_box);
        uint32_t temp = l;
        l = r;
        r = temp;
    }

    uint32_t temp = l;
    l = r;
    r = temp;

    r ^= p_array[16];
    l ^= p_array[17];

    *xl = l;
    *xr = r;
}

static void blowfish_decrypt_block(uint32_t* xl, uint32_t* xr, const uint32_t p_array[18], const uint32_t s_box[4][256]) {
    uint32_t l = *xl;
    uint32_t r = *xr;

    for (int i = 17; i > 1; --i) {
        l ^= p_array[i];
        r ^= blowfish_f(l, s_box);
        uint32_t temp = l;
        l = r;
        r = temp;
    }

    uint32_t temp = l;
    l = r;
    r = temp;

    r ^= p_array[1];
    l ^= p_array[0];

    *xl = l;
    *xr = r;
}

static void blowfish_init(const uint8_t* key, size_t key_len, uint32_t p_array[18], uint32_t s_box[4][256]) {
    std::memcpy(p_array, ORIG_P, sizeof(ORIG_P));
    std::memcpy(s_box, ORIG_S, sizeof(ORIG_S));

    if (key_len == 0) return;

    int key_idx = 0;
    for (int i = 0; i < 18; ++i) {
        uint32_t data = 0;
        for (int j = 0; j < 4; ++j) {
            data = (data << 8) | key[key_idx];
            key_idx = (key_idx + 1) % key_len;
        }
        p_array[i] ^= data;
    }

    uint32_t datal = 0;
    uint32_t datar = 0;

    for (int i = 0; i < 18; i += 2) {
        blowfish_encrypt_block(&datal, &datar, p_array, s_box);
        p_array[i] = datal;
        p_array[i + 1] = datar;
    }

    for (int i = 0; i < 4; ++i) {
        for (int j = 0; j < 256; j += 2) {
            blowfish_encrypt_block(&datal, &datar, p_array, s_box);
            s_box[i][j] = datal;
            s_box[i][j + 1] = datar;
        }
    }
}

extern "C" {

const AlgorithmInfo* get_algorithm_info() {
    return &BLOWFISH_INFO;
}

size_t get_output_size(size_t input_size, int operation_type) {
    if (operation_type == 1) {
        size_t padded_size = ((input_size / 8) + 1) * 8;
        return padded_size + 8; // Размер данных + PKCS7 выравнивание + 8 байт под IV
    } else {
        if (input_size < 8) return 0;
        return input_size - 8; // Исходный размер за вычетом IV
    }
}

int encrypt(ConstBuffer key, ConstBuffer input, MutBuffer* output) {
    size_t padded_size = ((input.size / 8) + 1) * 8;
    if (!output || output->size < (padded_size + 8) || !key.data || key.size == 0) {
        return 1;
    }

    uint32_t p_array[18];
    uint32_t s_box[4][256];
    blowfish_init(key.data, key.size, p_array, s_box);

    uint8_t iv[8];
    std::random_device rd;
    for (int i = 0; i < 8; ++i) {
        iv[i] = static_cast<uint8_t>(rd() & 0xFF);
    }
    std::memcpy(output->data, iv, 8);

    uint8_t prev_block[8];
    std::memcpy(prev_block, iv, 8);

    for (size_t offset = 0; offset < padded_size; offset += 8) {
        uint8_t block[8];
        for (int i = 0; i < 8; ++i) {
            size_t pos = offset + i;
            if (pos < input.size) {
                block[i] = input.data[pos];
            } else {
                block[i] = static_cast<uint8_t>(padded_size - input.size); // PKCS7 подбивка
            }
            block[i] ^= prev_block[i];
        }

        // Безопасный каст перед сдвигом для предотвращения UB и compiler warnings
        uint32_t xl = (static_cast<uint32_t>(block[0]) << 24) | 
                      (static_cast<uint32_t>(block[1]) << 16) | 
                      (static_cast<uint32_t>(block[2]) << 8)  | 
                       static_cast<uint32_t>(block[3]);
                      
        uint32_t xr = (static_cast<uint32_t>(block[4]) << 24) | 
                      (static_cast<uint32_t>(block[5]) << 16) | 
                      (static_cast<uint32_t>(block[6]) << 8)  | 
                       static_cast<uint32_t>(block[7]);

        blowfish_encrypt_block(&xl, &xr, p_array, s_box);

        output->data[8 + offset + 0] = (xl >> 24) & 0xFF;
        output->data[8 + offset + 1] = (xl >> 16) & 0xFF;
        output->data[8 + offset + 2] = (xl >> 8) & 0xFF;
        output->data[8 + offset + 3] = xl & 0xFF;
        output->data[8 + offset + 4] = (xr >> 24) & 0xFF;
        output->data[8 + offset + 5] = (xr >> 16) & 0xFF;
        output->data[8 + offset + 6] = (xr >> 8) & 0xFF;
        output->data[8 + offset + 7] = xr & 0xFF;

        std::memcpy(prev_block, &output->data[8 + offset], 8);
    }

    output->size = padded_size + 8;

    secure_wipe(p_array, sizeof(p_array));
    secure_wipe(s_box, sizeof(s_box));
    secure_wipe(iv, sizeof(iv));
    secure_wipe(prev_block, sizeof(prev_block));

    return 0;
}

int decrypt(ConstBuffer key, ConstBuffer input, MutBuffer* output) {
    if (input.size < 16 || (input.size - 8) % 8 != 0 || !output || !key.data || key.size == 0) {
        return 1;
    }

    uint32_t p_array[18];
    uint32_t s_box[4][256];
    blowfish_init(key.data, key.size, p_array, s_box);

    uint8_t prev_block[8];
    std::memcpy(prev_block, input.data, 8); // Извлекаем IV из заголовка

    size_t ciphertext_size = input.size - 8;

    for (size_t offset = 0; offset < ciphertext_size; offset += 8) {
        // Безопасный каст перед сдвигом для предотвращения UB и compiler warnings
        uint32_t xl = (static_cast<uint32_t>(input.data[8 + offset + 0]) << 24) | 
                      (static_cast<uint32_t>(input.data[8 + offset + 1]) << 16) | 
                      (static_cast<uint32_t>(input.data[8 + offset + 2]) << 8)  | 
                       static_cast<uint32_t>(input.data[8 + offset + 3]);
                      
        uint32_t xr = (static_cast<uint32_t>(input.data[8 + offset + 4]) << 24) | 
                      (static_cast<uint32_t>(input.data[8 + offset + 5]) << 16) | 
                      (static_cast<uint32_t>(input.data[8 + offset + 6]) << 8)  | 
                       static_cast<uint32_t>(input.data[8 + offset + 7]);

        blowfish_decrypt_block(&xl, &xr, p_array, s_box);

        uint8_t block[8];
        block[0] = (xl >> 24) & 0xFF;
        block[1] = (xl >> 16) & 0xFF;
        block[2] = (xl >> 8) & 0xFF;
        block[3] = xl & 0xFF;
        block[4] = (xr >> 24) & 0xFF;
        block[5] = (xr >> 16) & 0xFF;
        block[6] = (xr >> 8) & 0xFF;
        block[7] = xr & 0xFF;

        for (int i = 0; i < 8; ++i) {
            output->data[offset + i] = block[i] ^ prev_block[i];
        }

        std::memcpy(prev_block, &input.data[8 + offset], 8);
    }

    uint8_t padding_val = output->data[ciphertext_size - 1];
    if (padding_val == 0 || padding_val > 8) {
        secure_wipe(p_array, sizeof(p_array));
        secure_wipe(s_box, sizeof(s_box));
        return 2; // Ошибка валидации выравнивания
    }

    for (size_t i = ciphertext_size - padding_val; i < ciphertext_size; ++i) {
        if (output->data[i] != padding_val) {
            secure_wipe(p_array, sizeof(p_array));
            secure_wipe(s_box, sizeof(s_box));
            return 2;
        }
    }

    output->size = ciphertext_size - padding_val;

    secure_wipe(p_array, sizeof(p_array));
    secure_wipe(s_box, sizeof(s_box));
    secure_wipe(prev_block, sizeof(prev_block));

    return 0;
}

extern "C" int encrypt_with_iv(ConstBuffer key, ConstBuffer iv, ConstBuffer input, MutBuffer* output) {
    (void)iv; // Игнорируем внешний iv, так как в текущей логике Blowfish.cpp он обрабатывается внутри
    return encrypt(key, input, output);
}

}
