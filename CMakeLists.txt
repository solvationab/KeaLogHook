cmake_minimum_required(VERSION 3.16)
project(kea_ip_audit LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

set(KEA_PREFIX "/usr" CACHE PATH "Kea installation prefix")
set(KEA_HOOKS_DIR "${KEA_PREFIX}/lib/kea/hooks" CACHE PATH "Where to install the hook library")

find_package(PkgConfig REQUIRED)
find_package(Boost REQUIRED)
pkg_check_modules(ZMQ REQUIRED IMPORTED_TARGET libzmq)

find_path(KEA_INCLUDE_DIR NAMES hooks/hooks.h HINTS ${KEA_PREFIX} PATH_SUFFIXES include/kea REQUIRED)
find_program(KEA_MSG_COMPILER NAMES kea-msg-compiler HINTS ${KEA_PREFIX}/sbin ${KEA_PREFIX}/bin REQUIRED)

set(KEA_LIBS "")
foreach(lib kea-dhcpsrv kea-dhcp++ kea-hooks kea-log kea-util kea-cc kea-exceptions)
    find_library(KEA_LIB_${lib} NAMES ${lib} HINTS ${KEA_PREFIX} PATH_SUFFIXES lib lib64 REQUIRED)
    list(APPEND KEA_LIBS ${KEA_LIB_${lib}})
endforeach()

set(GENERATED_DIR ${CMAKE_CURRENT_BINARY_DIR}/generated)
file(MAKE_DIRECTORY ${GENERATED_DIR})
add_custom_command(
    OUTPUT ${GENERATED_DIR}/ip_audit_messages.cc ${GENERATED_DIR}/ip_audit_messages.h
    COMMAND ${KEA_MSG_COMPILER} -d ${GENERATED_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/src/ip_audit_messages.mes
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/src/ip_audit_messages.mes
    COMMENT "Compiling Kea log messages")

add_library(dhcp_ip_audit MODULE
    src/audit_manager.cc
    src/callouts.cc
    src/config_util.cc
    src/file_sink.cc
    src/formatter.cc
    src/ip_audit_log.cc
    src/record_builder.cc
    src/sink_factory.cc
    src/zmq_sink.cc
    ${GENERATED_DIR}/ip_audit_messages.cc)

target_include_directories(dhcp_ip_audit PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${GENERATED_DIR}
    ${KEA_INCLUDE_DIR}
    ${Boost_INCLUDE_DIRS})
target_link_libraries(dhcp_ip_audit PRIVATE ${KEA_LIBS} PkgConfig::ZMQ)
target_compile_options(dhcp_ip_audit PRIVATE -Wall -Wextra)

install(TARGETS dhcp_ip_audit LIBRARY DESTINATION ${KEA_HOOKS_DIR})
