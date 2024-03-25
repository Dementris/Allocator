cmake_minimum_required(VERSION 3.27)
project(alocator C)
set(CMAKE_C_EXTENSIONS off)
set(CMAKE_C_STANDARD 11)
if(CMAKE_C_COMPILER_ID STREQUAL "GNU" OR CMAKE_C_COMPILER_ID MATCHES "Clang")
    add_compile_options(-Wall -Wextra -Wconversion -pedantic -g -O2)
endif()
add_compile_definitions(_XOPEN_SOURCE=700)
add_executable(alocator main.c
        src/block.c
        src/kernel.c
        src/alocator.c
        src/tester.c
        src/avl/avl.c
)
