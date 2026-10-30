#include "file_sink.h"

#include "config_util.h"
#include "formatter.h"
#include "sink_factory.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <mutex>

using isc::data::ConstElementPtr;

namespace ip_audit {

namespace {

class FileSink : public Sink {
public:
    FileSink(std::string path, mode_t mode, uint64_t maxSize, unsigned maxFiles, bool doFsync,
             std::unique_ptr<Formatter> formatter)
        : path_(std::move(path)), mode_(mode), maxSize_(maxSize), maxFiles_(maxFiles),
          fsync_(doFsync), formatter_(std::move(formatter)) {
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
        if (maxSize_ > 0 && size_ > 0 && size_ + line.size() > maxSize_) {
            rotate();
        }

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
        size_ = (::fstat(fd_, &st) == 0) ? static_cast<uint64_t>(st.st_size) : 0;
    }

    void close() {
        if (fd_ >= 0) {
            ::close(fd_);
            fd_ = -1;
        }
    }

    // Keeps path.1 .. path.<maxFiles>, newest first.
    void rotate() {
        close();
        if (maxFiles_ == 0) {
            ::unlink(path_.c_str());
        } else {
            for (unsigned i = maxFiles_ - 1; i >= 1; --i) {
                ::rename((path_ + "." + std::to_string(i)).c_str(),
                         (path_ + "." + std::to_string(i + 1)).c_str());
            }
            ::rename(path_.c_str(), (path_ + ".1").c_str());
        }
        open();
    }

    std::string path_;
    mode_t mode_;
    uint64_t maxSize_;
    unsigned maxFiles_;
    bool fsync_;
    std::unique_ptr<Formatter> formatter_;

    std::mutex mutex_;
    int fd_ = -1;
    uint64_t size_ = 0;
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
                               {"path", "file-mode", "max-size", "max-files", "fsync"}));

    std::string path = requireString(cfg, "path");
    if (path.empty()) {
        throw ConfigError("parameter 'path' must not be empty");
    }
    mode_t mode = parseMode(optString(cfg, "file-mode", "0640"));
    int64_t maxSize = optInt(cfg, "max-size", 0, 0, INT64_MAX);
    int64_t maxFiles = optInt(cfg, "max-files", 5, 0, 1000);
    bool doFsync = optBool(cfg, "fsync", false);

    return std::make_unique<FileSink>(std::move(path), mode, static_cast<uint64_t>(maxSize),
                                      static_cast<unsigned>(maxFiles), doFsync,
                                      createFormatter(cfg->get("format")));
}

}
