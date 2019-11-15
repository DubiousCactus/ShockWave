cmake_minimum_required(VERSION 3.6)
project(ShockWave)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(THREADS_PREFER_PTHREAD_FLAG ON)

set(SOURCE_FILES main.cpp CLI.cpp CLI.h Network.cpp Network.h)
add_executable(${PROJECT_NAME} ${SOURCE_FILES})

message(STATUS "Looking for tins...")
find_library(TINS_LIBRARY tins)
if(TINS_LIBRARY)
    target_link_libraries(${PROJECT_NAME} ${TINS_LIBRARY})
else()
    message(FATAL_ERROR "tins library not found!")
endif()

find_package (Threads REQUIRED)
target_link_libraries(${PROJECT_NAME} ${CMAKE_THREAD_LIBS_INIT})
