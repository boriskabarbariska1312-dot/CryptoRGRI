#include "crypto.h"
#include <iostream>

using namespace std;

string encryptGronsfeld(string text){
// здесь будет математика шифрования Gronsfeld
return "Зашифрованный_Gronsfeld";
}

string decryptGronsfeld(string ciphertext){
// здесь будет математика расшифрования Gronsfeld
return "Расшиврованный Gronsfeld";
}


// БЛОК ОТЛАДКИ (Раскомментируй строку ниже, чтобы протестировать ТОЛЬКО этот файл)
//
// Если строка #define DEBUG_ATBASH закомментирована, компилятор при сборке всего 
// проекта просто игнорирует код внутри #ifdef и #endif
//
// #define DEBUG_ATBASH 

#ifdef DEBUG_ATBASH
int main() {
    cout << "--- Отладка модуля Gronsfeld ---" << endl;
    string test;
    cin >> test;
    string enc = encryptGronsfeld(test);
    cout << "Тест шифра: " << enc << endl;
    cout << "Тест дешифра: " << decryptGronsfeld(enc) << endl;
    return 0;
}
#endif



