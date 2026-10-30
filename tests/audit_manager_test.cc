#include "audit_manager.h"

#include "config_util.h"
#include "test_util.h"

#include <sys/stat.h>

#include <filesystem>

using namespace ip_audit;
using ip_audit_test::json;
using ip_audit_test::readLines;
using ip_audit_test::TempDir;

namespace {

AuditRecord record(const std::string& event, const std::string& ip = "192.0.2.10") {
    AuditRecord r;
    r.set("event", event);
    r.set("ip-address", ip);
    return r;
}

std::string fileSink(const std::string& path, const std::string& extra = "") {
    return R"({"type":"file","path":")" + path + R"(")" + (extra.empty() ? "" : "," + extra) + "}";
}

std::string sinks(const std::vector<std::string>& list) {
    std::string out = "[";
    for (size_t i = 0; i < list.size(); ++i) {
        out += (i ? "," : "") + list[i];
    }
    return out + "]";
}

std::string errorOf(const std::string& sinksJson) {
    try {
        AuditManager::create(json(sinksJson));
    } catch (const ConfigError& ex) {
        return ex.what();
    }
    return "";
}

}

TEST(AuditManager, RejectsInvalidSinksParameter) {
    EXPECT_THROW(AuditManager::create(isc::data::ConstElementPtr()), ConfigError);
    EXPECT_THROW(AuditManager::create(json("[]")), ConfigError);
    EXPECT_THROW(AuditManager::create(json("{}")), ConfigError);
    EXPECT_THROW(AuditManager::create(json("[1]")), ConfigError);
    EXPECT_THROW(AuditManager::create(json("[{}]")), ConfigError);
}

TEST(AuditManager, RejectsUnknownSinkType) {
    EXPECT_NE(std::string::npos, errorOf(R"([{"type":"nope"}])").find("unknown sink type"));
}

TEST(AuditManager, RejectsUnknownEvent) {
    TempDir dir;
    EXPECT_NE(std::string::npos,
              errorOf(sinks({fileSink(dir.file("a.log"), R"("events":["lease-oops"])")})).find("lease-oops"));
}

TEST(AuditManager, SinkConfigErrorNamesTheSink) {
    TempDir dir;
    std::string error = errorOf(sinks({fileSink(dir.file("a.log"), R"("name":"mine","typo":1)")}));
    EXPECT_NE(std::string::npos, error.find("sink 'mine'")) << error;
    EXPECT_NE(std::string::npos, error.find("typo")) << error;
}

TEST(AuditManager, SinkThatCannotOpenFailsAtLoad) {
    TempDir dir;
    EXPECT_THROW(AuditManager::create(json(sinks({fileSink(dir.file("missing-dir/a.log"))}))),
                 ConfigError);
}

TEST(AuditManager, CountsSinks) {
    TempDir dir;
    auto manager = AuditManager::create(
        json(sinks({fileSink(dir.file("a.log")), fileSink(dir.file("b.log"))})));
    EXPECT_EQ(2u, manager->sinkCount());
}

TEST(AuditManager, PublishesToEverySinkWhenNoEventFilter) {
    TempDir dir;
    auto manager = AuditManager::create(
        json(sinks({fileSink(dir.file("a.log")), fileSink(dir.file("b.log"))})));

    manager->publish(record("lease-assign"));

    const std::vector<std::string> expected = {R"({"event":"lease-assign","ip-address":"192.0.2.10"})"};
    EXPECT_EQ(expected, readLines(dir.file("a.log")));
    EXPECT_EQ(expected, readLines(dir.file("b.log")));
}

TEST(AuditManager, AppliesPerSinkEventFilter) {
    TempDir dir;
    auto manager = AuditManager::create(json(sinks({
        fileSink(dir.file("release.log"), R"("events":["lease-release"])"),
        fileSink(dir.file("all.log")),
    })));

    manager->publish(record("lease-assign"));
    manager->publish(record("lease-release"));

    ASSERT_EQ(1u, readLines(dir.file("release.log")).size());
    EXPECT_NE(std::string::npos, readLines(dir.file("release.log"))[0].find("lease-release"));
    EXPECT_EQ(2u, readLines(dir.file("all.log")).size());
}

TEST(AuditManager, RecordWithoutEventOnlyReachesUnfilteredSinks) {
    TempDir dir;
    auto manager = AuditManager::create(json(sinks({
        fileSink(dir.file("filtered.log"), R"("events":["lease-assign"])"),
        fileSink(dir.file("all.log")),
    })));

    AuditRecord r;
    r.set("ip-address", "192.0.2.10");
    manager->publish(r);

    EXPECT_TRUE(readLines(dir.file("filtered.log")).empty());
    EXPECT_EQ(1u, readLines(dir.file("all.log")).size());
}

TEST(AuditManager, FailingSinkDoesNotAffectOtherSinks) {
    if (!std::filesystem::exists("/dev/full")) {
        GTEST_SKIP() << "/dev/full is not available";
    }
    TempDir dir;
    // Every write to /dev/full fails with ENOSPC.
    auto manager = AuditManager::create(
        json(sinks({fileSink("/dev/full"), fileSink(dir.file("ok.log"))})));

    EXPECT_NO_THROW(manager->publish(record("lease-assign")));
    EXPECT_NO_THROW(manager->publish(record("lease-renew")));

    EXPECT_EQ(2u, readLines(dir.file("ok.log")).size());
}

TEST(AuditManager, TemplateFormatPerSink) {
    TempDir dir;
    auto manager = AuditManager::create(json(sinks({fileSink(
        dir.file("t.log"),
        R"("format":{"type":"template","template":"%{event} %{ip-address}"})")})));

    manager->publish(record("lease-assign", "192.0.2.77"));

    EXPECT_EQ((std::vector<std::string>{"lease-assign 192.0.2.77"}), readLines(dir.file("t.log")));
}
