cmake_minimum_required(VERSION 3.22.1)

project("secret_keys")

add_library(secret_keys SHARED secret_keys.cpp)

find_library(log-lib log)

target_link_libraries(secret_keys ${log-lib})
