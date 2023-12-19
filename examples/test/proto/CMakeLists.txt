cmake_minimum_required(VERSION 3.16)

# proto
find_package(Protobuf REQUIRED)
FILE(GLOB protofiles "${CMAKE_CURRENT_SOURCE_DIR}/*.proto")
protobuf_generate_cpp(PROTO_SRCS PROTO_HDRS ${protofiles})
protobuf_generate_python(PY_SOURCES ${protofiles})

add_library(symbol_proto STATIC ${PROTO_SRCS} ${PROTO_HDRS})
target_link_libraries(symbol_proto ${PROTOBUF_LIBRARIES})
