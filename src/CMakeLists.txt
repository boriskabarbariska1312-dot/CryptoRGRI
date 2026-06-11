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

add_library(gronsfeld SHARED gronsfeld.cpp)
add_library(atbash SHARED atbash.cpp)

add_executable(cryptum main.cpp)
add_executable(cryptotests tests.cpp)
