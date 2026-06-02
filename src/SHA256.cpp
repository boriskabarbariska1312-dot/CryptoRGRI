#include "crypto.h"
#include <iostream>

using namespace std;

string encryptSHA256(string text) {
    return "Захэшированный пароль";
}

string deHash(string HashText) {
    return "Хэшированный пароль: \n";
}

// БЛОК ОТЛАДКИ (Раскомментируй строку ниже, чтобы протестировать ТОЛЬКО этот файл)
//
// Если строка #define DEBUG_ATBASH закомментирована, компилятор при сборке всего 
// проекта просто игнорирует код внутри #ifdef и #endif
//
// #define DEBUG_ATBASH 

#ifdef DEBUG_ATBASH
int main() {
    cout << "--- Отладка модуля SHA256 ---" << endl;
    string test;
    cin >> test;
    string enc = encryptSHA256(test);
    cout << "Тест шифра: " << enc << endl;
    cout << "Тест дешифра: " << deHash(enc) << endl;
    return 0;
}
#endif



