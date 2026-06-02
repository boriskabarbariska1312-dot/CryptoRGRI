#include "crypto.h"
#include <iostream>

using namespace std;

string encryptAtbash(string text) {
    // Здесь будет математика шифрования Atbash
    return "Зашифрованный Atbash";
}

string decryptAtbash(string ciphertext) {
    // Здесь будет математика расшифрования Atbash
    return "Расшифрованный Atbash";
}


// БЛОК ОТЛАДКИ (Раскомментируй строку ниже, чтобы протестировать ТОЛЬКО этот файл)
//
// Если строка #define DEBUG_ATBASH закомментирована, компилятор при сборке всего 
// проекта просто игнорирует код внутри #ifdef и #endif
//
// #define DEBUG_ATBASH 

#ifdef DEBUG_ATBASH
int main() {
    cout << "--- Отладка модуля Atbash ---" << endl;
    string test;
    cin >> test;
    string enc = encryptAtbash(test);
    cout << "Тест шифра: " << enc << endl;
    cout << "Тест дешифра: " << decryptAtbash(enc) << endl;
    return 0;
}
#endif

