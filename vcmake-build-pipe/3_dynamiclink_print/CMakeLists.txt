cmake_minimum_required(VERSION 3.2)
project(dynamiclink_print)
set(CMAKE_BUILD_TYPE Release)

include_directories(include)

set(SOURCES src/crazything.c)

add_library(crazything SHARED ${SOURCES})

install(TARGETS crazything DESTINATION /usr/lib)
