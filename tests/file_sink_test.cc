#include "sink_factory.h"

#include "config_util.h"
#include "test_util.h"

#include <sys/stat.h>

using namespace ip_audit;
using ip_audit_test::json;
using ip_audit_test::readLines;
using ip_audit_test::TempDir;

namespace {

AuditRecord record(const std::string& ip) {
    AuditRecord r;
    r.set("event", "lease-assign");
    r.set("ip-address", ip);
    return r;
}

std::unique_ptr<Sink> createSink(const std::string& cfg) {
    return SinkFactory().create(json(cfg));
}

std::string fileCfg(const TempDir& dir, const std::string& extra = "") {
    return R"({"type":"file","path":")" + dir.file("a.log") + R"(")" + (extra.empty() ? "" : "," + extra) + "}";
}

const char* kLineFormat = R"("format":{"type":"template","template":"%{event} %{ip-address}"})";

mode_t modeOf(const std::string& path) {
    struct stat st;
    EXPECT_EQ(0, ::stat(path.c_str(), &st));
    return st.st_mode & 0777;
}

}

TEST(FileSink, AppendsOneLinePerRecord) {
    TempDir dir;
    auto sink = createSink(fileCfg(dir));
    sink->write(record("192.0.2.1"));
    sink->write(record("192.0.2.2"));

    EXPECT_EQ((std::vector<std::string>{R"({"event":"lease-assign","ip-address":"192.0.2.1"})",
                                        R"({"event":"lease-assign","ip-address":"192.0.2.2"})"}),
              readLines(dir.file("a.log")));
}

TEST(FileSink, AppendsToExistingFile) {
    TempDir dir;
    createSink(fileCfg(dir, kLineFormat))->write(record("192.0.2.1"));
    createSink(fileCfg(dir, kLineFormat))->write(record("192.0.2.2"));

    EXPECT_EQ((std::vector<std::string>{"lease-assign 192.0.2.1", "lease-assign 192.0.2.2"}),
              readLines(dir.file("a.log")));
}

TEST(FileSink, DefaultFileModeIsAtMost0640) {
    TempDir dir;
    auto sink = createSink(fileCfg(dir));
    // The umask may remove further bits but must never leave "other" access.
    EXPECT_EQ(0u, modeOf(dir.file("a.log")) & ~0640u);
}

TEST(FileSink, HonoursFileMode) {
    TempDir dir;
    auto sink = createSink(fileCfg(dir, R"("file-mode":"0600")"));
    EXPECT_EQ(0600u, modeOf(dir.file("a.log")));
}

TEST(FileSink, RejectsInvalidFileMode) {
    TempDir dir;
    for (const char* mode : {"640x", "", "rw", "1777"}) {
        EXPECT_THROW(createSink(fileCfg(dir, std::string(R"("file-mode":")") + mode + "\"")), ConfigError)
            << mode;
    }
}

TEST(FileSink, RejectsInvalidConfiguration) {
    TempDir dir;
    EXPECT_THROW(createSink(R"({"type":"file"})"), ConfigError);
    EXPECT_THROW(createSink(R"({"type":"file","path":""})"), ConfigError);
    EXPECT_THROW(createSink(fileCfg(dir, R"("max-size":-1)")), ConfigError);
    EXPECT_THROW(createSink(fileCfg(dir, R"("max-files":1001)")), ConfigError);
    EXPECT_THROW(createSink(fileCfg(dir, R"("fsync":"yes")")), ConfigError);
    EXPECT_THROW(createSink(fileCfg(dir, R"("unknown":1)")), ConfigError);
}

TEST(FileSink, FsyncOptionWorks) {
    TempDir dir;
    auto sink = createSink(fileCfg(dir, R"("fsync":true)"));
    sink->write(record("192.0.2.1"));
    EXPECT_EQ(1u, readLines(dir.file("a.log")).size());
}

TEST(FileSink, RotatesBySizeAndKeepsMaxFiles) {
    TempDir dir;
    // Each line is 23 bytes, so a 50 byte limit holds two lines per file.
    auto sink = createSink(fileCfg(dir, std::string(R"("max-size":50,"max-files":2,)") + kLineFormat));
    for (int i = 1; i <= 9; ++i) {
        sink->write(record("192.0.2." + std::to_string(i)));
    }

    EXPECT_EQ((std::vector<std::string>{"lease-assign 192.0.2.9"}), readLines(dir.file("a.log")));
    EXPECT_EQ((std::vector<std::string>{"lease-assign 192.0.2.7", "lease-assign 192.0.2.8"}),
              readLines(dir.file("a.log.1")));
    EXPECT_EQ((std::vector<std::string>{"lease-assign 192.0.2.5", "lease-assign 192.0.2.6"}),
              readLines(dir.file("a.log.2")));
    EXPECT_FALSE(std::filesystem::exists(dir.file("a.log.3")));
}

TEST(FileSink, RotationWithMaxFilesZeroDiscardsOldData) {
    TempDir dir;
    auto sink = createSink(fileCfg(dir, std::string(R"("max-size":50,"max-files":0,)") + kLineFormat));
    for (int i = 1; i <= 3; ++i) {
        sink->write(record("192.0.2." + std::to_string(i)));
    }

    EXPECT_EQ((std::vector<std::string>{"lease-assign 192.0.2.3"}), readLines(dir.file("a.log")));
    EXPECT_FALSE(std::filesystem::exists(dir.file("a.log.1")));
}

TEST(FileSink, NoRotationWhenMaxSizeIsZero) {
    TempDir dir;
    auto sink = createSink(fileCfg(dir, kLineFormat));
    for (int i = 1; i <= 20; ++i) {
        sink->write(record("192.0.2." + std::to_string(i)));
    }

    EXPECT_EQ(20u, readLines(dir.file("a.log")).size());
    EXPECT_FALSE(std::filesystem::exists(dir.file("a.log.1")));
}

TEST(SinkFactory, RejectsUnknownTypeAndListsAvailableOnes) {
    try {
        createSink(R"({"type":"carrier-pigeon"})");
        FAIL() << "expected ConfigError";
    } catch (const ConfigError& ex) {
        std::string what = ex.what();
        EXPECT_NE(std::string::npos, what.find("'file'")) << what;
        EXPECT_NE(std::string::npos, what.find("'zeromq'")) << what;
    }
}

TEST(SinkFactory, RegisteredTypeIsUsed) {
    struct NullSink : Sink {
        void write(const AuditRecord&) override {}
    };
    SinkFactory factory;
    factory.registerType("null", [](const isc::data::ConstElementPtr&) {
        return std::unique_ptr<Sink>(new NullSink());
    });
    EXPECT_NE(nullptr, factory.create(json(R"({"type":"null"})")).get());
}
