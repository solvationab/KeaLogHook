#include "file_sink.h"

#include "config_util.h"
#include "formatter.h"
#include "sink_factory.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <zlib.h>

#include <cerrno>
#include <cstring>
#include <mutex>
#include <ctime>

using isc::data::ConstElementPtr;

namespace ip_audit {

namespace {

class FileSink : public Sink {
public:
        FileSink(std::string path, mode_t mode, uint64_t maxSize, unsigned maxFiles, bool doFsync,
                         std::string rotationInterval, unsigned retentionDays, bool compressRotated,
                         std::unique_ptr<Formatter> formatter)
        : path_(std::move(path)), mode_(mode), maxSize_(maxSize), maxFiles_(maxFiles),
                    fsync_(doFsync), rotationInterval_(std::move(rotationInterval)),
                    retentionDays_(retentionDays), compressRotated_(compressRotated),
                    formatter_(std::move(formatter)) {
        open();
    }

    ~FileSink() override { close(); }

    void write(const AuditRecord& record) override {
        std::string line = formatter_->format(record);
        line += '\n';

        std::lock_guard<std::mutex> lock(mutex_);
        if (fd_ < 0) {
            open();
        }
        const std::time_t now = std::time(nullptr);
        const bool timeExpired = rotationInterval_ != "none" &&
                                 periodFor(now) != activePeriod_;
        const bool sizeExceeded = maxSize_ > 0 && size_ > 0 && size_ + line.size() > maxSize_;
        if (timeExpired || sizeExceeded) {
            rotate();
        }
        pruneExpired(now);

        const char* p = line.data();
        size_t left = line.size();
        while (left > 0) {
            ssize_t n = ::write(fd_, p, left);
            if (n < 0) {
                if (errno == EINTR) {
                    continue;
                }
                throw std::runtime_error("write to '" + path_ + "' failed: " + std::strerror(errno));
            }
            p += n;
            left -= static_cast<size_t>(n);
            size_ += static_cast<uint64_t>(n);
        }
        if (fsync_ && ::fsync(fd_) != 0) {
            throw std::runtime_error("fsync of '" + path_ + "' failed: " + std::strerror(errno));
        }
    }

private:
    void open() {
        fd_ = ::open(path_.c_str(), O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, mode_);
        if (fd_ < 0) {
            throw std::runtime_error("cannot open '" + path_ + "': " + std::strerror(errno));
        }
        struct stat st;
        if (::fstat(fd_, &st) == 0) {
            size_ = static_cast<uint64_t>(st.st_size);
            activePeriod_ = periodFor(st.st_mtime);
        } else {
            size_ = 0;
            activePeriod_ = periodFor(std::time(nullptr));
        }
    }

    void close() {
        if (fd_ >= 0) {
            ::close(fd_);
            fd_ = -1;
        }
    }

    int64_t periodFor(std::time_t time) const {
        if (rotationInterval_ == "daily") {
            return static_cast<int64_t>(time) / 86400;
        }
        if (rotationInterval_ == "hourly") {
            return static_cast<int64_t>(time) / 3600;
        }
        return 0;
    }

    bool exists(const std::string& path) const {
        struct stat st;
        if (::stat(path.c_str(), &st) == 0) {
            return true;
        }
        if (errno == ENOENT) {
            return false;
        }
        throw std::runtime_error("cannot stat '" + path + "': " + std::strerror(errno));
    }

    void removeIfExists(const std::string& path) const {
        if (::unlink(path.c_str()) != 0 && errno != ENOENT) {
            throw std::runtime_error("cannot remove '" + path + "': " + std::strerror(errno));
        }
    }

    void compressFile(const std::string& path) const {
        const std::string compressedPath = path + ".gz";
        const int input = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
        if (input < 0) {
            throw std::runtime_error("cannot open '" + path + "' for compression: " +
                                     std::strerror(errno));
        }
        gzFile output = gzopen(compressedPath.c_str(), "wb");
        if (!output) {
            ::close(input);
            throw std::runtime_error("cannot create '" + compressedPath + "'");
        }

        try {
            char buffer[16384];
            while (true) {
                ssize_t count = ::read(input, buffer, sizeof(buffer));
                if (count < 0) {
                    if (errno == EINTR) {
                        continue;
                    }
                    throw std::runtime_error("cannot read '" + path + "': " + std::strerror(errno));
                }
                if (count == 0) {
                    break;
                }
                if (gzwrite(output, buffer, static_cast<unsigned>(count)) != count) {
                    throw std::runtime_error("cannot compress '" + path + "'");
                }
            }
            const int result = gzclose(output);
            output = nullptr;
            if (result != Z_OK) {
                throw std::runtime_error("cannot finish compression of '" + path + "'");
            }
            if (::unlink(path.c_str()) != 0) {
                throw std::runtime_error("cannot remove uncompressed rotation '" + path + "': " +
                                         std::strerror(errno));
            }
        } catch (...) {
            if (output) {
                gzclose(output);
            }
            ::unlink(compressedPath.c_str());
            ::close(input);
            throw;
        }
        ::close(input);
    }

    // Keeps path.1 .. path.<maxFiles>, newest first. Compressed files retain the .gz suffix.
    void rotate() {
        close();
        try {
            if (maxFiles_ == 0) {
                removeIfExists(path_);
            } else {
                for (unsigned i = maxFiles_; i > 0; --i) {
                    const std::string destination = path_ + "." + std::to_string(i);
                    removeIfExists(destination);
                    removeIfExists(destination + ".gz");

                    const std::string sourceBase =
                        i == 1 ? path_ : path_ + "." + std::to_string(i - 1);
                    const bool sourceCompressed = i > 1 && exists(sourceBase + ".gz");
                    const std::string source = sourceCompressed ? sourceBase + ".gz" : sourceBase;
                    if (!exists(source)) {
                        continue;
                    }
                    const std::string target = destination + (sourceCompressed ? ".gz" : "");
                    if (::rename(source.c_str(), target.c_str()) != 0) {
                        throw std::runtime_error("cannot rotate '" + source + "' to '" + target +
                                                 "': " + std::strerror(errno));
                    }
                    if (compressRotated_ && !sourceCompressed) {
                        compressFile(destination);
                    }
                }
            }
            open();
        } catch (...) {
            if (fd_ < 0) {
                try {
                    open();
                } catch (...) {
                }
            }
            throw;
        }
    }

    void pruneExpired(std::time_t now) const {
        if (retentionDays_ == 0 || maxFiles_ == 0) {
            return;
        }
        const std::time_t cutoff = now - static_cast<std::time_t>(retentionDays_) * 86400;
        for (unsigned i = 1; i <= maxFiles_; ++i) {
            const std::string base = path_ + "." + std::to_string(i);
            for (const std::string& candidate : {base, base + ".gz"}) {
                struct stat st;
                if (::stat(candidate.c_str(), &st) == 0) {
                    if (st.st_mtime < cutoff && ::unlink(candidate.c_str()) != 0) {
                        throw std::runtime_error("cannot remove expired rotation '" + candidate +
                                                 "': " + std::strerror(errno));
                    }
                } else if (errno != ENOENT) {
                    throw std::runtime_error("cannot stat '" + candidate + "': " +
                                             std::strerror(errno));
                }
            }
        }
    }

    std::string path_;
    mode_t mode_;
    uint64_t maxSize_;
    unsigned maxFiles_;
    bool fsync_;
    std::string rotationInterval_;
    unsigned retentionDays_;
    bool compressRotated_;
    std::unique_ptr<Formatter> formatter_;

    std::mutex mutex_;
    int fd_ = -1;
    uint64_t size_ = 0;
    int64_t activePeriod_ = 0;
};

mode_t parseMode(const std::string& text) {
    size_t used = 0;
    unsigned long mode = 0;
    try {
        mode = std::stoul(text, &used, 8);
    } catch (const std::exception&) {
        used = 0;
    }
    if (used == 0 || used != text.size() || mode > 0777) {
        throw ConfigError("parameter 'file-mode' must be an octal string such as \"0640\"");
    }
    return static_cast<mode_t>(mode);
}

}

std::unique_ptr<Sink> createFileSink(const ConstElementPtr& cfg) {
    rejectUnknownKeys(cfg, SinkFactory::allowedKeys(
                               {"path", "file-mode", "max-size", "max-files", "fsync",
                                "rotation-interval", "retention-days", "compress-rotated"}));

    std::string path = requireString(cfg, "path");
    if (path.empty()) {
        throw ConfigError("parameter 'path' must not be empty");
    }
    mode_t mode = parseMode(optString(cfg, "file-mode", "0640"));
    int64_t maxSize = optInt(cfg, "max-size", 0, 0, INT64_MAX);
    int64_t maxFiles = optInt(cfg, "max-files", 5, 0, 1000);
    bool doFsync = optBool(cfg, "fsync", false);
    std::string rotationInterval = optString(cfg, "rotation-interval", "none");
    if (rotationInterval != "none" && rotationInterval != "daily" &&
        rotationInterval != "hourly") {
        throw ConfigError("parameter 'rotation-interval' must be 'none', 'daily' or 'hourly'");
    }
    int64_t retentionDays = optInt(cfg, "retention-days", 0, 0, 36500);
    bool compressRotated = optBool(cfg, "compress-rotated", false);

    return std::make_unique<FileSink>(std::move(path), mode, static_cast<uint64_t>(maxSize),
                                      static_cast<unsigned>(maxFiles), doFsync,
                                      std::move(rotationInterval), static_cast<unsigned>(retentionDays),
                                      compressRotated,
                                      createFormatter(cfg->get("format")));
}

}
