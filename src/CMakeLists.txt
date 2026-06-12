cmake_minimum_required(VERSION 3.10)
project(MultiAlgoCryptotool CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(MSVC)
    add_compile_options(/W4 /WX)
else()
    add_compile_options(-Wall -Wextra -Werror)
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,-rpath,'$ORIGIN'")
endif()

# Сборка динамических библиотек для каждого алгоритма
add_library(gronsfeld SHARED gronsfeld.cpp)
add_library(atbash SHARED atbash.cpp)
add_library(rc4 SHARED RC4.cpp)
add_library(blowfish SHARED Blowfish.cpp)

# Сборка SHA256 как отдельного плагина
add_library(sha256 SHARED SHA256.cpp)
# ИСПРАВЛЕНИЕ: Включаем макрос плагина ТОЛЬКО для этой библиотеки
target_compile_definitions(sha256 PRIVATE SHA256_PLUGIN_MODE)

# Сборка модуля MTProto (здесь SHA256.cpp скомпилируется БЕЗ макроса плагина)
add_library(mtproto SHARED MTProto.cpp AES256.cpp SHA256.cpp)

# Сборка исполняемых файлов
add_executable(cryptum main.cpp)
add_executable(cryptotests tests.cpp)

if(NOT MSVC)
    target_link_libraries(cryptum ${CMAKE_DL_LIBS})
    target_link_libraries(cryptotests ${CMAKE_DL_LIBS})
endif()