cmake_minimum_required(VERSION 3.2)
project(staticlink_print)
set(CMAKE_BUILD_TYPE Release)


include_directories(include)


set(SOURCES src/something.c)


add_library(something STATIC ${SOURCES})


install(TARGETS something DESTINATION /usr/lib)

