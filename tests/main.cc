#include <log/logger_support.h>

#include <gtest/gtest.h>

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    // Sink failure tests log at ERROR; keep the test output readable.
    isc::log::initLogger("ip-audit-test", isc::log::FATAL);
    return RUN_ALL_TESTS();
}
