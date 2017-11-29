cmake_minimum_required(VERSION 3.2)
set(CMAKE_C_COMPILER "gcc")

project(MultithreadedSocket VERSION 0.0.1 LANGUAGES C)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c11")

# Search OpenSSL
find_package(PkgConfig REQUIRED)
pkg_search_module(OPENSSL REQUIRED openssl)

if( OPENSSL_FOUND )
    include_directories(${OPENSSL_INCLUDE_DIRS})
    link_directories(${OPENSSL_LIBRARIES})
    message(STATUS "Using OpenSSL ${OPENSSL_VERSION}")
else()
    # Error; with REQUIRED, pkg_search_module() will throw an error by it's own
endif()

find_package (Threads REQUIRED)

add_executable( client client.c)
target_link_libraries(client ${OPENSSL_LIBRARIES})
add_executable( server server.c)
target_link_libraries(server ${OPENSSL_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT})
