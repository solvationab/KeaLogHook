#include "config_util.h"
#include "sink_factory.h"
#include "test_util.h"

using namespace ip_audit;
using ip_audit_test::json;

namespace {

std::unique_ptr<Sink> createSink(const std::string& config) {
    return SinkFactory().create(json(config));
}

}

TEST(SyslogSink, AcceptsFacilityAndSeverityAndWritesARecord) {
    auto sink = createSink(
        R"({"type":"syslog","facility":"local3","severity":"debug","name":"test"})");
    AuditRecord record;
    record.set("event", "lease-assign");
    record.set("ip-address", "192.0.2.1");

    EXPECT_NO_THROW(sink->write(record));
}

TEST(SyslogSink, UsesDefaults) {
    EXPECT_NO_THROW(createSink(R"({"type":"syslog"})"));
}

TEST(SyslogSink, RejectsInvalidConfiguration) {
    EXPECT_THROW(createSink(R"({"type":"syslog","facility":"invalid"})"), ConfigError);
    EXPECT_THROW(createSink(R"({"type":"syslog","severity":"verbose"})"), ConfigError);
    EXPECT_THROW(createSink(R"({"type":"syslog","facility":3})"), ConfigError);
    EXPECT_THROW(createSink(R"({"type":"syslog","name":""})"), ConfigError);
    EXPECT_THROW(createSink(R"({"type":"syslog","unknown":true})"), ConfigError);
}