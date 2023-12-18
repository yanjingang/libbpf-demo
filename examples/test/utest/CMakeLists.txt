cmake_minimum_required(VERSION 3.16)
project(utest)

# debug
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Werror -ggdb -rdynamic") 

# proto
find_package(Protobuf REQUIRED)
FILE(GLOB protofiles "${CMAKE_CURRENT_SOURCE_DIR}/*.proto")
protobuf_generate_cpp(PROTO_SRCS PROTO_HDRS ${protofiles})
protobuf_generate_python(PY_SOURCES ${protofiles})

add_library(symbol STATIC ${PROTO_SRCS} ${PROTO_HDRS})
target_link_libraries(symbol ${PROTOBUF_LIBRARIES})

# .h
include_directories(
    ./
    /usr/local/include
    /usr/include
    ${PROTOBUF_INCLUDE_DIRS}
    ${CMAKE_CURRENT_BINARY_DIR}
)

# utest exec
add_executable(utest utest.cc)
# usymbol exec
add_executable(usymbol usymbol.cc)
target_link_libraries(usymbol protobuf elf symbol)