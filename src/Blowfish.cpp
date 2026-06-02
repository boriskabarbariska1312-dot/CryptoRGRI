#include "crypto.h"
#include <iostream>

using namespace std;

string encryptBlowfish(string text){
// здесь будет математика шифрования Blowfish
return "Зашифрованный Blowfish";
}

string decryptBlowfish(string ciphertext){
// здесь будет математика расшифрования Blowfish
return "Расшиврованный Blowfish";
}

// БЛОК ОТЛАДКИ (Раскомментируй строку ниже, чтобы протестировать ТОЛЬКО этот файл)
//
// Если строка #define DEBUG_ATBASH закомментирована, компилятор при сборке всего 
// проекта просто игнорирует код внутри #ifdef и #endif
//
// #define DEBUG_ATBASH 

#ifdef DEBUG_ATBASH
int main() {
    cout << "--- Отладка модуля Blowfish ---" << endl;
    string test;
    cin >> test;
    string enc = encryptBlowfish(test);
    cout << "Тест шифра: " << enc << endl;
    cout << "Тест дешифра: " << decryptBlowfish(enc) << endl;
    return 0;
}
#endif


