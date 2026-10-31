#include "sink_factory.h"

#include "config_util.h"
#include "test_util.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <utime.h>
#include <zlib.h>

#include <ctime>
#include <fstream>
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

void writeFile(const std::string& path, const std::string& contents) {
    std::ofstream out(path, std::ios::binary);
    ASSERT_TRUE(out.good());
    out << contents;
}

void setModifiedTime(const std::string& path, std::time_t value) {
    struct utimbuf times;
    times.actime = value;
    times.modtime = value;
    ASSERT_EQ(0, ::utime(path.c_str(), &times));
}

void writeGzipFile(const std::string& path, const std::string& contents) {
    gzFile file = gzopen(path.c_str(), "wb");
    ASSERT_NE(nullptr, file);
    ASSERT_EQ(static_cast<int>(contents.size()),
              gzwrite(file, contents.data(), static_cast<unsigned>(contents.size())));
    ASSERT_EQ(Z_OK, gzclose(file));
}

std::string readGzipFile(const std::string& path) {
    gzFile file = gzopen(path.c_str(), "rb");
    EXPECT_NE(nullptr, file);
    if (!file) {
        return "";
    }
    std::string contents;
    char buffer[256];
    int count;
    while ((count = gzread(file, buffer, sizeof(buffer))) > 0) {
        contents.append(buffer, static_cast<size_t>(count));
    }
    EXPECT_EQ(0, count);
    EXPECT_EQ(Z_OK, gzclose(file));
    return contents;
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

TEST(FileSink, ReopensAfterExternalRotation) {
    TempDir dir;
    const std::string path = dir.file("a.log");
    auto sink = createSink(fileCfg(dir, kLineFormat));
    sink->write(record("192.0.2.1"));
    std::filesystem::rename(path, path + ".external");

    EXPECT_TRUE(sink->reopen());
    sink->write(record("192.0.2.2"));

    EXPECT_EQ((std::vector<std::string>{"lease-assign 192.0.2.1"}),
              readLines(path + ".external"));
    EXPECT_EQ((std::vector<std::string>{"lease-assign 192.0.2.2"}), readLines(path));
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
    EXPECT_THROW(createSink(fileCfg(dir, R"("rotation-interval":"weekly")")), ConfigError);
    EXPECT_THROW(createSink(fileCfg(dir, R"("retention-days":-1)")), ConfigError);
    EXPECT_THROW(createSink(fileCfg(dir, R"("retention-days":36501)")), ConfigError);
    EXPECT_THROW(createSink(fileCfg(dir, R"("compress-rotated":"yes")")), ConfigError);
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

TEST(FileSink, RotatesAtDailyAndHourlyBoundaries) {
    for (const auto& interval : {std::string("daily"), std::string("hourly")}) {
        TempDir dir;
        const std::string path = dir.file("a.log");
        writeFile(path, "previous period\n");
        const std::time_t age = interval == "daily" ? 2 * 86400 : 2 * 3600;
        setModifiedTime(path, std::time(nullptr) - age);

        const std::string extra = R"("rotation-interval":")" + interval +
                                  R"(","max-files":2,)" + kLineFormat;
        auto sink = createSink(fileCfg(dir, extra));
        sink->write(record("192.0.2.1"));

        EXPECT_EQ((std::vector<std::string>{"previous period"}), readLines(path + ".1"))
            << interval;
        EXPECT_EQ((std::vector<std::string>{"lease-assign 192.0.2.1"}), readLines(path))
            << interval;
    }
}

TEST(FileSink, PrunesExpiredPlainAndCompressedRotations) {
    TempDir dir;
    const std::string path = dir.file("a.log");
    writeFile(path + ".1", "expired plain\n");
    writeFile(path + ".2", "recent plain\n");
    writeGzipFile(path + ".3.gz", "expired compressed\n");
    const std::time_t now = std::time(nullptr);
    setModifiedTime(path + ".1", now - 3 * 86400);
    setModifiedTime(path + ".2", now - 3600);
    setModifiedTime(path + ".3.gz", now - 3 * 86400);

    auto sink = createSink(fileCfg(dir, R"("retention-days":1,"max-files":3)"));
    sink->write(record("192.0.2.1"));

    EXPECT_FALSE(std::filesystem::exists(path + ".1"));
    EXPECT_TRUE(std::filesystem::exists(path + ".2"));
    EXPECT_FALSE(std::filesystem::exists(path + ".3.gz"));
}

TEST(FileSink, CompressesRotationsAndPreservesNewestFirstOrder) {
    TempDir dir;
    const std::string path = dir.file("a.log");
    auto sink = createSink(fileCfg(
        dir, std::string(R"("max-size":1,"max-files":2,"compress-rotated":true,)") +
                 kLineFormat));

    sink->write(record("192.0.2.1"));
    sink->write(record("192.0.2.2"));
    sink->write(record("192.0.2.3"));

    EXPECT_EQ("lease-assign 192.0.2.2\n", readGzipFile(path + ".1.gz"));
    EXPECT_EQ("lease-assign 192.0.2.1\n", readGzipFile(path + ".2.gz"));
    EXPECT_FALSE(std::filesystem::exists(path + ".1"));
    EXPECT_FALSE(std::filesystem::exists(path + ".3.gz"));
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
