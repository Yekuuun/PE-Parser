# Spécifie la version minimale de CMake requise
cmake_minimum_required(VERSION 3.5)

# Nomme votre projet et spécifie le langage C
project(PE-Parser)

# include files
include_directories(include)

set(CMAKE_CXX_STANDARD 17) # Par exemple, pour C++17
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# src files
set(SOURCES
    src/main.cpp
    src/handlePE.cpp
    src/utils.cpp
    src/manualMap.cpp
)

add_executable(parser ${SOURCES})

# Exemple : Activer les avertissements et activer le standard C11
target_compile_options(parser PRIVATE -Wall -std=c11)