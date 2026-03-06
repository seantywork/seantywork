cmake_minimum_required(VERSION 3.2)
project (main_lib_print)



include_directories(
    ../2_staticlink_print/include
    ../3_dynamiclink_print/include
    )


set ( PROJECT_LINK_LIBS libsomething.a libcrazything.so)

link_directories( 
    ../2_staticlink_print/build
    ../3_dynamiclink_print/build 
    )



add_executable(main.out main.c)

target_link_libraries(main.out ${PROJECT_LINK_LIBS})
