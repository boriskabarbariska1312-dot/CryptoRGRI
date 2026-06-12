#ifndef SHA256_H
#define SHA256_H

#include <vector>
#include <cstdint>
#include <cstddef>

// Основная функция хэширования
std::vector<uint8_t> calculate_sha256(const uint8_t* data, size_t length);

// Удобная перегрузка для работы с векторами
std::vector<uint8_t> calculate_sha256(const std::vector<uint8_t>& data);

<<<<<<< HEAD
#endif // SHA256_H
=======
#endif 
>>>>>>> cf3e457de19e1f58c7dcae7fb3fb5745a6e837c7
