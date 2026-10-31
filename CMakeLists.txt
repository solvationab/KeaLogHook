cmake_minimum_required(VERSION 3.16)
project(kea_ip_audit VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

set(KEA_PREFIX "/usr" CACHE PATH "Kea installation prefix")
# Install next to Kea by default so packages land in /usr rather than /usr/local.
if(CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
    set(CMAKE_INSTALL_PREFIX "${KEA_PREFIX}" CACHE PATH "" FORCE)
endif()

include(GNUInstallDirs)

# Relative to the install prefix; follows the distribution layout (lib64 on RPM, lib/<multiarch> on Debian).
set(KEA_HOOKS_DIR "${CMAKE_INSTALL_LIBDIR}/kea/hooks" CACHE STRING "Hook library directory, relative to the install prefix")

find_package(PkgConfig REQUIRED)
find_package(Boost REQUIRED)
find_package(OpenSSL REQUIRED COMPONENTS Crypto)
find_package(ZLIB REQUIRED)
find_package(Threads REQUIRED)
pkg_check_modules(ZMQ REQUIRED IMPORTED_TARGET libzmq)

find_path(KEA_INCLUDE_DIR NAMES hooks/hooks.h HINTS ${KEA_PREFIX} PATH_SUFFIXES include/kea REQUIRED)
find_program(KEA_MSG_COMPILER NAMES kea-msg-compiler HINTS ${KEA_PREFIX}/sbin ${KEA_PREFIX}/bin REQUIRED)

set(KEA_LIBS "")
foreach(lib kea-dhcpsrv kea-dhcp++ kea-hooks kea-log kea-util kea-asiolink kea-cc kea-exceptions)
    set(lib_names ${lib})
    if("${lib}" STREQUAL "kea-dhcp++")
        list(APPEND lib_names kea-dhcp)
    endif()
    find_library(KEA_LIB_${lib} NAMES ${lib_names} HINTS ${KEA_PREFIX} PATH_SUFFIXES lib lib64 REQUIRED)
    list(APPEND KEA_LIBS ${KEA_LIB_${lib}})
endforeach()

set(GENERATED_DIR ${CMAKE_CURRENT_BINARY_DIR}/generated)
file(MAKE_DIRECTORY ${GENERATED_DIR})
add_custom_command(
    OUTPUT ${GENERATED_DIR}/ip_audit_messages.cc ${GENERATED_DIR}/ip_audit_messages.h
    COMMAND ${KEA_MSG_COMPILER} -d ${GENERATED_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/src/ip_audit_messages.mes
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/src/ip_audit_messages.mes
    COMMENT "Compiling Kea log messages")

# Everything except the Kea entry points, so that the unit tests can link it too.
add_library(ip_audit_core STATIC
    src/audit_manager.cc
    src/config_util.cc
    src/file_sink.cc
    src/formatter.cc
    src/ip_audit_log.cc
    src/record_builder.cc
    src/record_queue.cc
    src/sink_factory.cc
    src/zmq_sink.cc
    ${GENERATED_DIR}/ip_audit_messages.cc)

target_include_directories(ip_audit_core PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${GENERATED_DIR}
    ${KEA_INCLUDE_DIR}
    ${Boost_INCLUDE_DIRS})
target_link_libraries(ip_audit_core PUBLIC ${KEA_LIBS} OpenSSL::Crypto ZLIB::ZLIB PkgConfig::ZMQ Threads::Threads)
target_compile_options(ip_audit_core PRIVATE -Wall -Wextra)

add_library(dhcp_ip_audit MODULE src/callouts.cc)
target_link_libraries(dhcp_ip_audit PRIVATE ip_audit_core)
target_compile_options(dhcp_ip_audit PRIVATE -Wall -Wextra)

add_library(dhcp6_ip_audit MODULE src/callouts6.cc)
target_link_libraries(dhcp6_ip_audit PRIVATE ip_audit_core)
target_compile_options(dhcp6_ip_audit PRIVATE -Wall -Wextra)

option(IP_AUDIT_BUILD_TESTS "Build the unit tests" ON)
if(IP_AUDIT_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

install(TARGETS dhcp_ip_audit dhcp6_ip_audit LIBRARY DESTINATION ${KEA_HOOKS_DIR})
install(FILES examples/kea-dhcp4.conf examples/kea-dhcp6.conf DESTINATION ${CMAKE_INSTALL_DOCDIR}/examples)
install(FILES README.md DESTINATION ${CMAKE_INSTALL_DOCDIR})
install(DIRECTORY docs/ DESTINATION ${CMAKE_INSTALL_DOCDIR}/docs)

# Packaging: run `cpack -G DEB` or `cpack -G RPM` in the build directory.
set(PACKAGE_MAINTAINER "Unknown <root@localhost>" CACHE STRING "Maintainer shown in the package")
set(CPACK_PACKAGE_NAME "kea-ip-audit-hook")
set(CPACK_PACKAGE_VERSION ${PROJECT_VERSION})
set(CPACK_PACKAGE_CONTACT ${PACKAGE_MAINTAINER})
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Kea DHCPv4/v6 hook that logs lease assignments and relay data")
set(CPACK_PACKAGE_DESCRIPTION "Records which client got which IPv4 address or IPv6 address/prefix, including relay agent information, to a log file and/or a ZeroMQ PUB socket.")
set(CPACK_PACKAGING_INSTALL_PREFIX "${CMAKE_INSTALL_PREFIX}")
set(CPACK_GENERATOR "DEB;RPM")

# Library dependencies (libkea-*, libzmq) are derived automatically from the built binary.
set(CPACK_DEBIAN_PACKAGE_SHLIBDEPS ON)
set(CPACK_DEBIAN_FILE_NAME DEB-DEFAULT)
set(CPACK_DEBIAN_PACKAGE_SECTION "net")
set(CPACK_RPM_PACKAGE_AUTOREQ ON)
set(CPACK_RPM_FILE_NAME RPM-DEFAULT)
set(CPACK_RPM_PACKAGE_LICENSE "Proprietary")
set(CPACK_RPM_PACKAGE_GROUP "System Environment/Daemons")
# Files under the Kea-owned hooks directory must not be claimed as owned by this package.
set(CPACK_RPM_EXCLUDE_FROM_AUTO_FILELIST_ADDITION "${CMAKE_INSTALL_PREFIX}/${KEA_HOOKS_DIR}")
include(CPack)
