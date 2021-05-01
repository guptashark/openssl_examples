cmake_minimum_required(VERSION 3.18)

project(openssl_examples)

add_executable(bio_console bio_console.c)
target_link_libraries(bio_console ssl crypto)

add_executable(genrsa genrsa.c)
target_link_libraries(genrsa ssl crypto)

add_executable(x509_name_example x509_name_example.c)
target_link_libraries(x509_name_example ssl crypto)
