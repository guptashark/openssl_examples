cmake_minimum_required(VERSION 3.18)

project(openssl_examples)

add_executable(bio_console bio_console.c)
target_link_libraries(bio_console ssl crypto)
