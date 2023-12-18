cmake_minimum_required(VERSION 3.16)
project(utest)

# utest exec
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Werror -ggdb -rdynamic") 
add_executable(utest utest.cc)
