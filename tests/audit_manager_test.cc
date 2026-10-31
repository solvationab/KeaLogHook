#include "audit_manager.h"

#include "config_util.h"
#include "test_util.h"

#include <sys/stat.h>

#include <chrono>
#include <filesystem>
#include <thread>

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

AuditRecord renewalRecord(const std::string& ip, const std::string& mac,
                          const std::string& circuitId) {
    AuditRecord r = record("lease-renew", ip);
    r.set("hw-address", mac);
    r.set("client-id", "");
    r.set("duid", "");
    r.set("circuit-id", circuitId);
    r.set("remote-id", "");
    r.set("relay-suboptions", "");
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

template <typename Predicate>
bool waitFor(Predicate predicate) {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(1);
    while (!predicate() && std::chrono::steady_clock::now() < deadline) {
        std::this_thread::yield();
    }
    return predicate();
}

}

TEST(AuditManager, RejectsInvalidSinksParameter) {
    EXPECT_THROW(AuditManager::create(isc::data::ConstElementPtr()), ConfigError);
    EXPECT_THROW(AuditManager::create(json("[]")), ConfigError);
    EXPECT_THROW(AuditManager::create(json("{}")), ConfigError);
    EXPECT_THROW(AuditManager::create(json("[1]")), ConfigError);
    EXPECT_THROW(AuditManager::create(json("[{}]")), ConfigError);
    EXPECT_THROW(AuditManager::create(json(R"([{"type":"file","path":"unused"}])"), 0),
                 ConfigError);
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

TEST(AuditManager, ReportsRuntimeStatistics) {
    TempDir dir;
    auto manager = AuditManager::create(json(sinks({fileSink(dir.file("a.log"))})), 17);
    auto stats = manager->statistics();

    EXPECT_EQ(0u, stats.queueDepth);
    EXPECT_EQ(17u, stats.queueCapacity);
    EXPECT_EQ(1u, stats.sinkCount);
    EXPECT_EQ(0u, stats.droppedRecords);
    EXPECT_EQ(0u, stats.sinkWrites);
    EXPECT_EQ(0u, stats.sinkWriteFailures);

    manager->publish(record("lease-assign"));
    ASSERT_TRUE(waitFor([&] { return manager->statistics().sinkWrites == 1; }));
    stats = manager->statistics();
    EXPECT_EQ(1u, stats.sinkWrites);
    EXPECT_EQ(0u, stats.sinkWriteFailures);
    EXPECT_EQ(1u, readLines(dir.file("a.log")).size());
}

TEST(AuditManager, ReopensFileSinksAfterExternalRotation) {
    TempDir dir;
    const std::string path = dir.file("a.log");
    auto manager = AuditManager::create(json(sinks({fileSink(
        path, R"("format":{"type":"template","template":"%{event} %{ip-address}"})")})));
    manager->publish(record("lease-assign", "192.0.2.1"));
    ASSERT_TRUE(waitFor([&] { return manager->statistics().sinkWrites == 1; }));
    std::filesystem::rename(path, path + ".external");

    const auto result = manager->reopenSinks();
    EXPECT_EQ(1u, result.reopened);
    EXPECT_EQ(0u, result.unsupported);
    EXPECT_EQ(0u, result.failed);

    manager->publish(record("lease-assign", "192.0.2.2"));
    ASSERT_TRUE(waitFor([&] { return manager->statistics().sinkWrites == 2; }));
    manager.reset();

    EXPECT_EQ((std::vector<std::string>{"lease-assign 192.0.2.1"}),
              readLines(path + ".external"));
    EXPECT_EQ((std::vector<std::string>{"lease-assign 192.0.2.2"}), readLines(path));
}

TEST(AuditManager, PublishesToEverySinkWhenNoEventFilter) {
    TempDir dir;
    auto manager = AuditManager::create(
        json(sinks({fileSink(dir.file("a.log")), fileSink(dir.file("b.log"))})));

    manager->publish(record("lease-assign"));
    manager.reset();

    const std::vector<std::string> expected = {R"({"event":"lease-assign","ip-address":"192.0.2.10"})"};
    EXPECT_EQ(expected, readLines(dir.file("a.log")));
    EXPECT_EQ(expected, readLines(dir.file("b.log")));
}

TEST(AuditManager, DrainsQueuedRecordsInOrderWhenDestroyed) {
    TempDir dir;
    auto manager = AuditManager::create(json(sinks({fileSink(dir.file("a.log"))})), 128);
    for (int i = 0; i < 100; ++i) {
        manager->publish(record("lease-assign", "192.0.2." + std::to_string(i)));
    }
    manager.reset();

    auto lines = readLines(dir.file("a.log"));
    ASSERT_EQ(100u, lines.size());
    EXPECT_NE(std::string::npos, lines.front().find("192.0.2.0"));
    EXPECT_NE(std::string::npos, lines.back().find("192.0.2.99"));
}

TEST(AuditManager, AppliesPerSinkEventFilter) {
    TempDir dir;
    auto manager = AuditManager::create(json(sinks({
        fileSink(dir.file("release.log"), R"("events":["lease-release"])"),
        fileSink(dir.file("all.log")),
    })));

    manager->publish(record("lease-assign"));
    manager->publish(record("lease-release"));
    manager.reset();

    ASSERT_EQ(1u, readLines(dir.file("release.log")).size());
    EXPECT_NE(std::string::npos, readLines(dir.file("release.log"))[0].find("lease-release"));
    EXPECT_EQ(2u, readLines(dir.file("all.log")).size());
}

TEST(AuditManager, PublishesLeaseDeleteToSubscribedSink) {
    TempDir dir;
    auto manager = AuditManager::create(json(sinks({
        fileSink(dir.file("deleted.log"), R"("events":["lease-delete"])") ,
        fileSink(dir.file("all.log")),
    })));

    manager->publish(record("lease-delete"));
    manager.reset();

    EXPECT_EQ(1u, readLines(dir.file("deleted.log")).size());
    EXPECT_EQ(1u, readLines(dir.file("all.log")).size());
}

TEST(AuditManager, OptionalRenewalChangeFilterIsPerSink) {
    TempDir dir;
    auto manager = AuditManager::create(json(sinks({
        fileSink(dir.file("filtered.log"),
                 R"("renewals-on-change":true,"renewal-rate-limit":100)"),
        fileSink(dir.file("all.log")),
    })));

    manager->publish(renewalRecord("192.0.2.10", "aa:bb", "circuit-a"));
    manager->publish(renewalRecord("192.0.2.10", "aa:bb", "circuit-a"));
    manager->publish(renewalRecord("192.0.2.10", "cc:dd", "circuit-a"));
    manager->publish(renewalRecord("192.0.2.10", "cc:dd", "circuit-b"));
    manager->publish(renewalRecord("192.0.2.11", "cc:dd", "circuit-b"));
    manager->publish(record("lease-assign", "192.0.2.10"));
    manager.reset();

    EXPECT_EQ(5u, readLines(dir.file("filtered.log")).size());
    EXPECT_EQ(6u, readLines(dir.file("all.log")).size());
}

TEST(AuditManager, OptionalRenewalRateLimitIsPerSinkAndRenewalsOnly) {
    TempDir dir;
    auto manager = AuditManager::create(json(sinks({
        fileSink(dir.file("limited.log"), R"("renewal-rate-limit":1)"),
        fileSink(dir.file("all.log")),
    })));

    for (int i = 0; i < 5; ++i) {
        manager->publish(renewalRecord("192.0.2." + std::to_string(i), "aa:bb", "circuit-a"));
    }
    manager->publish(record("lease-assign"));
    manager.reset();

    EXPECT_EQ(2u, readLines(dir.file("limited.log")).size());
    EXPECT_EQ(6u, readLines(dir.file("all.log")).size());
}

TEST(AuditManager, RejectsInvalidRenewalOptions) {
    TempDir dir;
    EXPECT_NE(std::string::npos,
              errorOf(sinks({fileSink(dir.file("a.log"), R"("renewals-on-change":"true")")}))
                  .find("must be a boolean"));
    EXPECT_NE(std::string::npos,
              errorOf(sinks({fileSink(dir.file("b.log"), R"("renewal-rate-limit":-1)")}))
                  .find("between 0 and 1000000"));
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
    manager.reset();

    EXPECT_TRUE(readLines(dir.file("filtered.log")).empty());
    EXPECT_EQ(1u, readLines(dir.file("all.log")).size());
}

TEST(AuditManager, UnsubscribedRecordsDoNotConsumeQueueCapacity) {
    TempDir dir;
    auto manager = AuditManager::create(
        json(sinks({fileSink(dir.file("release.log"), R"("events":["lease-release"])")})), 1);

    for (int i = 0; i < 10; ++i) {
        manager->publish(record("lease-assign"));
    }

    EXPECT_EQ(0u, manager->droppedRecords());
    manager.reset();
    EXPECT_TRUE(readLines(dir.file("release.log")).empty());
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
    ASSERT_TRUE(waitFor([&] {
        const auto stats = manager->statistics();
        return stats.sinkWrites == 2 && stats.sinkWriteFailures == 2;
    }));
    const auto stats = manager->statistics();
    EXPECT_EQ(2u, stats.sinkWrites);
    EXPECT_EQ(2u, stats.sinkWriteFailures);
    manager.reset();

    EXPECT_EQ(2u, readLines(dir.file("ok.log")).size());
}

TEST(AuditManager, TemplateFormatPerSink) {
    TempDir dir;
    auto manager = AuditManager::create(json(sinks({fileSink(
        dir.file("t.log"),
        R"("format":{"type":"template","template":"%{event} %{ip-address}"})")})));

    manager->publish(record("lease-assign", "192.0.2.77"));
    manager.reset();

    EXPECT_EQ((std::vector<std::string>{"lease-assign 192.0.2.77"}), readLines(dir.file("t.log")));
}
