cmake_minimum_required(VERSION 3.2)
project (cc_hello)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)


include_directories(
    include
    )


file(GLOB cc_hello_source
    "src/hello.cc"
)


add_executable(hello.out 
    ${cc_hello_source}
    )

