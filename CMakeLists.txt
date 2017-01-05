cmake_minimum_required(VERSION 3.6)
project(ShockWave)

set(CMAKE_CXX_STANDARD 11)

set(SOURCE_FILES
        include/CLI.h
        src/CLI.cpp
        main.cpp)

add_executable(ShockWave ${SOURCE_FILES})