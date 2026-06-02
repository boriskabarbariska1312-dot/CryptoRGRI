#include <iostream>
#include <string>
#include "crypto.h" // Подключаем нашу карту проекта!

using namespace std;

string getProtoName(Proto ChoicedProto) {
    switch (ChoicedProto) {
        case Proto::MTProto:   return "MTProto";
        case Proto::SHA256:    return "SHA256";
        case Proto::RC4:       return "RC4";
        case Proto::Blowfish:  return "Blowfish";
        case Proto::Atbash:    return "Atbash";
        case Proto::Gronsfeld: return "Gronsfeld";
        default:               return "Unknown";
    }
}

int main() {
    cout << "Выберите протокол шифрования\n";
    cout << "1 -  MTProto\n";
    cout << "2 -  SHA256\n";
    cout << "3 -  RC4\n";
    cout << "4 -  Blowfish\n";
    cout << "5 -  Atbash\n";
    cout << "6 -  Gronsfeld\n";

    int choice;
    cin >> choice; 
    cin.ignore(); 

    Proto SelectedProto = Proto::Unknown;

    switch (choice) {
        case 1: SelectedProto = Proto::MTProto; break;
        case 2: SelectedProto = Proto::SHA256; break;
        case 3: SelectedProto = Proto::RC4; break;
        case 4: SelectedProto = Proto::Blowfish; break;
        case 5: SelectedProto = Proto::Atbash; break;
        case 6: SelectedProto = Proto::Gronsfeld; break;
        default: SelectedProto = Proto::Unknown; break; 
    }

    if (SelectedProto != Proto::SHA256) {
        cout << "\nВы выбрали " << getProtoName(SelectedProto) << ", введите ваше сообщение, которое хотите зашифровать\n";
        string message;
        getline(cin, message); 
        cout << endl;
        
        string encrypted = "";
        string decrypted = "";

        switch (SelectedProto) {
            case Proto::MTProto:
                encrypted = encryptMTProto(message);
                decrypted = decryptMTProto(encrypted);
                break;
            case Proto::RC4:
                encrypted = encryptRC4(message);
                decrypted = decryptRC4(encrypted);
                break;
            case Proto::Blowfish:
                encrypted = encryptBlowfish(message);
                decrypted = decryptBlowfish(encrypted);
                break;
            case Proto::Atbash:
                encrypted = encryptAtbash(message);
                decrypted = decryptAtbash(encrypted);
                break;
            case Proto::Gronsfeld:
                encrypted = encryptGronsfeld(message);
                decrypted = decryptGronsfeld(encrypted);
                break;
            default:
                break;
        }

        cout << "Результат шифрования: " << encrypted << endl;
        cout << "Результат Расшифрования: " << decrypted << endl;
    }
    else {
        cout << "Вы выбрали " << getProtoName(SelectedProto) << ", это хэш, а значит не подлежит дешифрованию, введите пароль: "; 
        string password;
        getline(cin, password); 
        cout << deHash(password);
    }

    return 0;
}
