cmake_minimum_required(VERSION 3.16)
project(ebpf_test)

# 1.symbol proto
add_subdirectory(proto)


# 2.user space test app
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Werror -ggdb -rdynamic")   # debug
# .h
include_directories(
    ./
    /usr/include
    /usr/local/include
    ${PROTOBUF_INCLUDE_DIRS}
    ${CMAKE_CURRENT_BINARY_DIR}
)
set(SYMBOL_LIBS
    protobuf
    symbol_proto
)
# utest exec
add_executable(utest utest/utest.cc)
add_executable(utest_class utest/utest_class.cc)
# usymbol exec
add_executable(usymbol utest/usymbol.cc)
target_link_libraries(usymbol elf ${SYMBOL_LIBS})


# 3. ebpf
# find BpfObject
list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/tools)

# build libbpf depend
include(ExternalProject)
ExternalProject_Add(libbpf
  PREFIX libbpf
  SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../../libbpf/src
  CONFIGURE_COMMAND ""
  BUILD_COMMAND make
    BUILD_STATIC_ONLY=1
    OBJDIR=${CMAKE_CURRENT_BINARY_DIR}/libbpf/libbpf
    DESTDIR=${CMAKE_CURRENT_BINARY_DIR}/libbpf
    INCLUDEDIR=
    LIBDIR=
    UAPIDIR=
    install install_uapi_headers
  BUILD_IN_SOURCE TRUE
  INSTALL_COMMAND ""
  STEP_TARGETS build
)

ExternalProject_Add(bpftool
  PREFIX bpftool
  SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../../bpftool/src
  CONFIGURE_COMMAND ""
  BUILD_COMMAND make bootstrap
    OUTPUT=${CMAKE_CURRENT_BINARY_DIR}/bpftool/
  BUILD_IN_SOURCE TRUE
  INSTALL_COMMAND ""
  STEP_TARGETS build
)

find_program(CARGO_EXISTS cargo)
if(CARGO_EXISTS)
  ExternalProject_Add(blazesym
    PREFIX blazesym
    SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../../blazesym
    CONFIGURE_COMMAND ""
    BUILD_COMMAND cargo build --release
    BUILD_IN_SOURCE TRUE
    INSTALL_COMMAND ""
    STEP_TARGETS build
  )
endif()

set(BPFOBJECT_BPFTOOL_EXE ${CMAKE_CURRENT_BINARY_DIR}/bpftool/bootstrap/bpftool)
set(BPFOBJECT_VMLINUX_H ${CMAKE_CURRENT_SOURCE_DIR}/../../vmlinux/${ARCH}/vmlinux.h)
set(LIBBPF_INCLUDE_DIRS ${CMAKE_CURRENT_BINARY_DIR}/libbpf)
set(LIBBPF_LIBRARIES ${CMAKE_CURRENT_BINARY_DIR}/libbpf/libbpf.a)
find_package(BpfObject REQUIRED)

# Create an executable for each application
file(GLOB apps *.bpf.c)
# if(NOT CARGO_EXISTS)
#   list(REMOVE_ITEM apps ${CMAKE_CURRENT_SOURCE_DIR}/profile.bpf.c)
# endif()
foreach(app ${apps})
  get_filename_component(app_name ${app} NAME_WE)

  # Build object skeleton and depend skeleton on libbpf build
  bpf_object(${app_name} ${app_name}.bpf.c)
  add_dependencies(${app_name}_skel libbpf-build bpftool-build)

  add_executable(${app_name} ${app_name}.cc ${TEST_SRCS})
  target_link_libraries(${app_name} ${app_name}_skel ${SYMBOL_LIBS})
  # if(${app_name} STREQUAL profile)
  #   target_include_directories(${app_name} PRIVATE
  #     ${CMAKE_CURRENT_SOURCE_DIR}/../../blazesym/include)
  #   target_link_libraries(${app_name}
  #     ${CMAKE_CURRENT_SOURCE_DIR}/../../blazesym/target/release/libblazesym.a -lpthread -lrt -ldl)
  # endif()
endforeach()

