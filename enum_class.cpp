#include <iostream>
#include <string>

using namespace std;

enum class Proto {
  Unknown,

  MTProto,
  SHA256,
  
  RC4,
  Blowfish,

  Atbash,
  Gronsfeld
};

string getProtoName(Proto ChoicedProto){ //помогает перевести число из choice в текст для удобства

switch (ChoicedProto){
  case Proto::MTProto:    return "MTProto";
  case Proto::SHA256:     return "SHA256";
  case Proto::RC4:        return "RC4";
  case Proto::Blowfish:   return "Blowfish";
  case Proto::Atbash:     return "Atbash";
  case Proto::Gronsfeld:  return "Gronsfeld";
  default:                return "Unknown";

  }
}


string encryptMTProto(string text){
// здесь будет математика шифрования MTProto
return "Зашифрованный MTProto";
}

string decryptMTProto(string ciphertext){
// здесь будет математика расшифрования MTProto
return "Расшиврованный MTProto";
}


string encryptSHA256(string text){
// здесь будет математика шифрования SHA256
return "Захэшированный пароль";
}

string deHash(string HashText){
return "Хэшированный пароль: \n";
}


string encryptRC4(string text){
// здесь будет математика шифрования RC4
return "Зашифрованный RC4";
}

string decryptRC4(string ciphertext){
// здесь будет математика расшифрования RC4
return "Расшиврованный RC4";
}


string encryptBlowfish(string text){
// здесь будет математика шифрования Blowfish
return "Зашифрованный Blowfish";
}

string decryptBlowfish(string ciphertext){
// здесь будет математика расшифрования Blowfish
return "Расшиврованный Blowfish";
}

string encryptAtbash(string text){
// здесь будет математика шифрования Atbash
return "Зашифрованный Atbash";
}

string decryptAtbash(string ciphertext){
// здесь будет математика расшифрования Atbash
return "Расшиврованный Atbash";
}

string encryptGronsfeld(string text){
// здесь будет математика шифрования Gronsfeld
return "Зашифрованный_Gronsfeld";
}

string decryptGronsfeld(string ciphertext){
// здесь будет математика расшифрования Gronsfeld
return "Расшиврованный Gronsfeld";
}


int main(){
  cout << "Выберите протокол шифрования\n";
  cout << "1 -  MTProto\n";
  cout << "2 -  SHA256\n";
  cout << "3 -  RC4\n";
  cout << "4 -  Blowfish\n";
  cout << "5 -  Atbash\n";
  cout << "6 -  Gronsfeld\n";

  int choice;
  cin >> choice; //пользователь пишет свой выбор
  cin.ignore(); // очищает буфер от Enter, иначе в наше сообщение он возьмется

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

if (SelectedProto != Proto::SHA256){
  cout << "\nВы выбрали " << getProtoName(SelectedProto) << ", введите ваше сообщение, которое хотите зашифровать\n";
  string message;
  getline (cin, message); // считывание целиком и с цифрами и с пробелами
  
  string encrypted = "";
  string decrypted = "";

  switch (SelectedProto){

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

  cout << encrypted << "Результат шифрования: " << encrypted << endl;
  cout << encrypted << "Результат Расшифрования: " << decrypted << endl;



}

else {
  cout << "Вы выбрали " << getProtoName(SelectedProto) << ", это хэш, а значит не подлежит дешифрованию, введите пароль"; 
  string password;
  getline(cin, password); // считывание целиком и с цифрами и с пробелами
  
  // для SHA256 логика немного другая, вызываем дехеш
  cout << deHash(password);
}


  
  return 0;
}



