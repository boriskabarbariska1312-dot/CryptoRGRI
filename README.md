STRUCTURE OF FILES
my_project/
├── .git/               # Желательно инициализировать git (Vim ищет корень по этой папке)
├── bin/                # Сюда будут собираться готовые программы (бинарники)
└── src/                # Все  файлы .cpp и .h кладем сюда
    ├── main.cpp
    ├── utils.cpp
    └── utils.h



Algorithm of program
[ Шаг 1: cin >> choice ]  (Пользователь ввел 5)
          │
          ▼
[ Шаг 2: switch (choice) ] ───> Перевел число 5 в Proto::Atbash
          │
          ▼
[ Шаг 3: if (SelectedProto != Proto::SHA256) ]
          │
          ├─► Да, это НЕ хэш! Заходим ВНУТРЬ этого IF:
          │    │
          │    ├──► getline(cin, message) (Считываем текст)
          │    │
          │    └──► [ Шаг 4: ВТОРОЙ switch (SelectedProto) ] 
          │          │
          │          └─► case Proto::Atbash:
          │               run encryptAtbash() -> сохраняем в encrypted
          │
          └─► (В блок else для SHA256 программа даже не заглядывает)


тут надо будет чтобы каждый расписал математику шифрования/дешифрования (если есть) своих приколов
