#include "crypto.h"
#include <iostream>
#include <string>
#include <vector>

using namespace std;

// Вспомогательная функция для безопасного декодирования строки из формата UTF-8 в строку широких символов wstring.
// Необходима для корректной посимвольной обработки кириллицы, так как в UTF-8 русские буквы занимают более 1 байта.
static wstring utf8_to_wstring(const string& str) {
    wstring result;
    result.reserve(str.size()); // Оптимизация памяти: резервирование места под символы
    for (size_t i = 0; i < str.length(); ) {
        unsigned char c = str[i];
        wchar_t wc = 0;
        
        // Побайтовый анализ UTF-8 маркеров для определения длины символа
        if (c < 0x80) {
            // Однобайтовый символ (стандартный ASCII)
            wc = c;
            i += 1;
        } else if ((c & 0xE0) == 0xC0) {
            // Двухбайтовый символ (основная кириллица)
            if (i + 1 >= str.length()) break;
            wc = ((c & 0x1F) << 6) | (str[i+1] & 0x3F);
            i += 2;
        } else if ((c & 0xF0) == 0xE0) {
            // Трехбайтовый символ
            if (i + 2 >= str.length()) break;
            wc = ((c & 0x0F) << 12) | ((str[i+1] & 0x3F) << 6) | (str[i+2] & 0x3F);
            i += 3;
        } else if ((c & 0xF8) == 0xF0) {
            // Четырехбайтовый символ
            if (i + 3 >= str.length()) break;
            wc = ((c & 0x07) << 18) | ((str[i+1] & 0x3F) << 12) | ((str[i+2] & 0x3F) << 6) | (str[i+3] & 0x3F);
            i += 4;
        } else {
            // Обработка некорректного байта
            wc = c;
            i += 1;
        }
        result.push_back(wc);
    }
    return result;
}

// Вспомогательная функция для кодирования строки широких символов wstring обратно в стандартный формат UTF-8.
// Используется для приведения обработанного текста к типу std::string перед возвратом из модуля.
static string wstring_to_utf8(const wstring& wstr) {
    string result;
    result.reserve(wstr.size() * 2); // Оптимизация памяти под выходную многобайтовую строку
    for (wchar_t wc : wstr) {
        // Конвертация широкого символа в соответствующую байтовую последовательность UTF-8
        if (wc < 0x80) {
            result.push_back(static_cast<char>(wc));
        } else if (wc < 0x800) {
            result.push_back(static_cast<char>(0xC0 | ((wc >> 6) & 0x1F)));
            result.push_back(static_cast<char>(0x80 | (wc & 0x3F)));
        } else if (wc < 0x10000) {
            result.push_back(static_cast<char>(0xE0 | ((wc >> 12) & 0x0F)));
            result.push_back(static_cast<char>(0x80 | ((wc >> 6) & 0x3F)));
            result.push_back(static_cast<char>(0x80 | (wc & 0x3F)));
        } else {
            result.push_back(static_cast<char>(0xF0 | ((wc >> 18) & 0x07)));
            result.push_back(static_cast<char>(0x80 | ((wc >> 12) & 0x3F)));
            result.push_back(static_cast<char>(0x80 | ((wc >> 6) & 0x3F)));
            result.push_back(static_cast<char>(0x80 | (wc & 0x3F)));
        }
    }
    return result;
}

// Основная функция для шифрования текста алгоритмом Атбаш с полной поддержкой Юникода и буквы Ё.
// Выполняет зеркальное отражение алфавита отдельно для латиницы и кириллицы с сохранением регистра символов.
string encryptAtbash(const string& text) {
    // Декодирование входной UTF-8 строки во внутреннее представление wstring
    wstring wtext = utf8_to_wstring(text);
    
    for (size_t i = 0; i < wtext.length(); ++i) {
        wchar_t ch = wtext[i];
        
        if (ch >= L'a' && ch <= L'z') {
            // Зеркальное отражение строчных букв латинского алфавита
            wtext[i] = L'z' - (ch - L'a');
        } else if (ch >= L'A' && ch <= L'Z') {
            // Зеркальное отражение прописных букв латинского алфавита
            wtext[i] = L'Z' - (ch - L'A');
        }
        else if ((ch >= L'а' && ch <= L'е') || ch == L'ё' || (ch >= L'ж' && ch <= L'я')) {
            // Обработка строчных букв кириллицы с формированием непрерывного виртуального алфавита из 33 букв
            int idx = 0;
            
            // Определение реальной позиции символа в алфавите (где буква 'ё' занимает 6-й индекс)
            if (ch >= L'а' && ch <= L'е') idx = ch - L'а';
            else if (ch == L'ё') idx = 6;
            else idx = ch - L'ж' + 7;

            // Вычисление инвертированного индекса по правилу Атбаша (32 - текущий индекс)
            int new_idx = 32 - idx;

            // Преобразование полученного зеркального индекса обратно в код Юникода
            if (new_idx <= 5) wtext[i] = L'а' + new_idx;
            else if (new_idx == 6) wtext[i] = L'ё';
            else wtext[i] = L'ж' + (new_idx - 7);
        } 
        else if ((ch >= L'А' && ch <= L'Е') || ch == L'Ё' || (ch >= L'Ж' && ch <= L'Я')) {
            // Обработка прописных букв кириллицы с формированием непрерывного виртуального алфавита из 33 букв
            int idx = 0;
            
            // Определение реальной позиции символа в алфавите (где буква 'Ё' занимает 6-й индекс)
            if (ch >= L'А' && ch <= L'Е') idx = ch - L'А';
            else if (ch == L'Ё') idx = 6;
            else idx = ch - L'Ж' + 7;

            // Вычисление инвертированного индекса по правилу Атбаша (32 - текущий индекс)
            int new_idx = 32 - idx;

            // Преобразование полученного зеркального индекса обратно в код Юникода
            if (new_idx <= 5) wtext[i] = L'А' + new_idx;
            else if (new_idx == 6) wtext[i] = L'Ё';
            else wtext[i] = L'Ж' + (new_idx - 7);
        }
    }
    
    // Кодирование зашифрованной строки wstring обратно в стандартный формат UTF-8
    return wstring_to_utf8(wtext);
}

// Функция для расшифрования текста.
// В силу взаимной обратности алгоритма Атбаш (двойное шифрование возвращает исходный текст) повторно вызывает функцию шифрования.
string decryptAtbash(const string& ciphertext) {
    return encryptAtbash(ciphertext);
}

// Вспомогательный блок для изолированной отладки модуля Атбаш (активируется при определении макроса DEBUG_ATBASH)
// #ifdef DEBUG_ATBASH
// int main() {
//     cout << "--- Отладка модуля Atbash ---" << endl;
//     cout << "Введите text для проверки: ";
    
//     string test;
//     getline(cin, test); 
    
//     string enc = encryptAtbash(test);
//     cout << "Тест шифра:   " << enc << endl;
//     cout << "Тест дешифра: " << decryptAtbash(enc) << endl;
//     return 0;
// }
// #endif