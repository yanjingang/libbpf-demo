cmake_minimum_required(VERSION 3.16)
project(utest)

# utest exec
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Werror")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -ggdb -rdynamic") 
add_executable(utest utest.cc)
