#include "crypto.h"
#include <iostream>
#include <string>
#include <vector>

using namespace std;

static wstring utf8_to_wstring(const string& str) {
    wstring result;
    result.reserve(str.size());
    for (size_t i = 0; i < str.length(); ) {
        unsigned char c = str[i];
        wchar_t wc = 0;
        if (c < 0x80) {
            wc = c;
            i += 1;
        } else if ((c & 0xE0) == 0xC0) {
            if (i + 1 >= str.length()) break;
            wc = ((c & 0x1F) << 6) | (str[i+1] & 0x3F);
            i += 2;
        } else if ((c & 0xF0) == 0xE0) {
            if (i + 2 >= str.length()) break;
            wc = ((c & 0x0F) << 12) | ((str[i+1] & 0x3F) << 6) | (str[i+2] & 0x3F);
            i += 3;
        } else if ((c & 0xF8) == 0xF0) {
            if (i + 3 >= str.length()) break;
            wc = ((c & 0x07) << 18) | ((str[i+1] & 0x3F) << 12) | ((str[i+2] & 0x3F) << 6) | (str[i+3] & 0x3F);
            i += 4;
        } else {
            wc = c;
            i += 1;
        }
        result.push_back(wc);
    }
    return result;
}


string decryptAtbash(const string& ciphertext) {
    return encryptAtbash(ciphertext);
}

#ifdef DEBUG_ATBASH
int main() {
    cout << "--- Отладка модуля Atbash ---" << endl;
    cout << "Введите text для проверки: ";
    
    string test;
    getline(cin, test); 
    
    string enc = encryptAtbash(test);
    cout << "Тест шифра:   " << enc << endl;
    cout << "Тест дешифра: " << decryptAtbash(enc) << endl;
    return 0;
}
#endif