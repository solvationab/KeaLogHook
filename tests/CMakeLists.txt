find_package(GTest QUIET)
if(NOT GTest_FOUND)
    include(FetchContent)
    FetchContent_Declare(googletest
        GIT_REPOSITORY https://github.com/google/googletest.git
        GIT_TAG v1.14.0)
    FetchContent_MakeAvailable(googletest)
endif()

add_executable(ip_audit_tests
    main.cc
    audit_manager_test.cc
    config_util_test.cc
    file_sink_test.cc
    formatter_test.cc
    record_builder_test.cc
    zmq_sink_test.cc)

target_link_libraries(ip_audit_tests PRIVATE ip_audit_core GTest::gtest)
target_compile_options(ip_audit_tests PRIVATE -Wall -Wextra)

include(GoogleTest)
gtest_discover_tests(ip_audit_tests)
