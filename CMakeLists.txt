cmake_minimum_required(VERSION 3.6)
project(ShockWave)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

project(ShockWave)

set(THREADS_PREFER_PTHREAD_FLAG ON)
find_library(TINS_LIBRARY tins)
find_package (Threads REQUIRED)

set(SOURCE_FILES main.cpp CLI.cpp CLI.h Network.cpp Network.h)
add_executable(ShockWave ${SOURCE_FILES})

target_link_libraries(ShockWave "${TINS_LIBRARY}")
target_link_libraries(ShockWave ${CMAKE_THREAD_LIBS_INIT})