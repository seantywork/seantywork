cmake_minimum_required(VERSION 3.2)
project (cc_asio_server)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set (BOOST_DIR boost_1_81_0/build)

set ( PROJECT_LINK_LIBS libboost_system.a)

include_directories(
    include
    "${BOOST_DIR}/include"
    )


link_directories( 
    "${BOOST_DIR}/lib"
    )


file(GLOB async_server_source
    "src/async_server.cc"
)

file(GLOB coroutine_server_source
    "src/coroutine_server.cc"
)


add_executable(async_server.out 
    main_async.cc
    ${async_server_source}
    )


add_executable(coroutine_server.out 
    main_coroutine.cc
    ${coroutine_server_source}
    )


target_link_libraries(async_server.out
    ${PROJECT_LINK_LIBS}
)

target_link_libraries(coroutine_server.out
    ${PROJECT_LINK_LIBS}
)
