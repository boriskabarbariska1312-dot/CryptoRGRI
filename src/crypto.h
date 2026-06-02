#ifndef CRYPTO_H
#define CRYPTO_H

#include <string>

// Наш любимый enum переезжает сюда
enum class Proto {
    Unknown,
    MTProto,
    SHA256,
    RC4,
    Blowfish,
    Atbash,
    Gronsfeld
};

// Прототипы функций (только "объявления", без самого кода)
std::string getProtoName(Proto ChoicedProto);

std::string encryptMTProto(std::string text);
std::string decryptMTProto(std::string ciphertext);

std::string encryptSHA256(std::string text);
std::string deHash(std::string HashText);

std::string encryptRC4(std::string text);
std::string decryptRC4(std::string ciphertext);

std::string encryptBlowfish(std::string text);
std::string decryptBlowfish(std::string ciphertext);

std::string encryptAtbash(std::string text);
std::string decryptAtbash(std::string ciphertext);

std::string encryptGronsfeld(std::string text);
std::string decryptGronsfeld(std::string ciphertext);

#endif // CRYPTO_H
