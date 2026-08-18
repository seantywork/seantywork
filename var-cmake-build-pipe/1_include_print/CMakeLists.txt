cmake_minimum_required(VERSION 3.2)
project(include_print)

include_directories(include)


set(SOURCES src/main.c src/something.c)


add_executable(print.out ${SOURCES})
