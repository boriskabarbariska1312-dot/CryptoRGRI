#include "crypto.h"
#include <iostream>

using namespace std;

string encryptRC4(string text){
// здесь будет математика шифрования RC4
return "Зашифрованный RC4";
}

string decryptRC4(string ciphertext){
// здесь будет математика расшифрования RC4
return "Расшиврованный RC4";
}

// БЛОК ОТЛАДКИ (Раскомментируй строку ниже, чтобы протестировать ТОЛЬКО этот файл)
//
// Если строка #define DEBUG_ATBASH закомментирована, компилятор при сборке всего 
// проекта просто игнорирует код внутри #ifdef и #endif
//
// #define DEBUG_ATBASH 

#ifdef DEBUG_ATBASH
int main() {
    cout << "--- Отладка модуля RC4 ---" << endl;
    string test;
    cin >> test;
    string enc = encryptRC4(test);
    cout << "Тест шифра: " << enc << endl;
    cout << "Тест дешифра: " << decryptRC4(enc) << endl;
    return 0;
}
#endif



