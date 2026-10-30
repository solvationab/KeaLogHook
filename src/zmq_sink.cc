#include "zmq_sink.h"

#include "config_util.h"
#include "formatter.h"
#include "sink_factory.h"

#include <zmq.h>

#include <mutex>

using isc::data::ConstElementPtr;

namespace ip_audit {

namespace {

[[noreturn]] void zmqFail(const std::string& what) {
    throw std::runtime_error(what + ": " + zmq_strerror(zmq_errno()));
}

class ZmqSink : public Sink {
public:
    struct Options {
        std::string endpoint;
        bool bind;
        bool multipart;
        int sendHwm;
        int lingerMs;
        int ioThreads;
    };

    ZmqSink(Options opts, Template topic, std::unique_ptr<Formatter> formatter)
        : multipart_(opts.multipart), topic_(std::move(topic)), formatter_(std::move(formatter)) {
        ctx_ = zmq_ctx_new();
        if (!ctx_) {
            zmqFail("zmq_ctx_new");
        }
        try {
            if (zmq_ctx_set(ctx_, ZMQ_IO_THREADS, opts.ioThreads) != 0) {
                zmqFail("zmq_ctx_set(io-threads)");
            }
            sock_ = zmq_socket(ctx_, ZMQ_PUB);
            if (!sock_) {
                zmqFail("zmq_socket");
            }
            if (zmq_setsockopt(sock_, ZMQ_SNDHWM, &opts.sendHwm, sizeof(opts.sendHwm)) != 0) {
                zmqFail("zmq_setsockopt(send-hwm)");
            }
            if (zmq_setsockopt(sock_, ZMQ_LINGER, &opts.lingerMs, sizeof(opts.lingerMs)) != 0) {
                zmqFail("zmq_setsockopt(linger-ms)");
            }
            int rc = opts.bind ? zmq_bind(sock_, opts.endpoint.c_str())
                               : zmq_connect(sock_, opts.endpoint.c_str());
            if (rc != 0) {
                zmqFail(std::string(opts.bind ? "bind" : "connect") + " to '" + opts.endpoint + "'");
            }
        } catch (...) {
            release();
            throw;
        }
    }

    ~ZmqSink() override { release(); }

    void write(const AuditRecord& record) override {
        std::string topic = topic_.expand(record);
        std::string payload = formatter_->format(record);

        std::lock_guard<std::mutex> lock(mutex_);
        if (multipart_) {
            send(topic, ZMQ_SNDMORE);
            send(payload, 0);
        } else {
            send(topic.empty() ? payload : topic + " " + payload, 0);
        }
    }

private:
    void send(const std::string& data, int flags) {
        if (zmq_send(sock_, data.data(), data.size(), flags | ZMQ_DONTWAIT) < 0) {
            zmqFail("zmq_send");
        }
    }

    void release() {
        if (sock_) {
            zmq_close(sock_);
            sock_ = nullptr;
        }
        if (ctx_) {
            zmq_ctx_term(ctx_);
            ctx_ = nullptr;
        }
    }

    bool multipart_;
    Template topic_;
    std::unique_ptr<Formatter> formatter_;

    std::mutex mutex_;
    void* ctx_ = nullptr;
    void* sock_ = nullptr;
};

}

std::unique_ptr<Sink> createZmqSink(const ConstElementPtr& cfg) {
    rejectUnknownKeys(cfg, SinkFactory::allowedKeys({"endpoint", "mode", "topic", "multipart",
                                                     "send-hwm", "linger-ms", "io-threads"}));

    ZmqSink::Options opts;
    opts.endpoint = requireString(cfg, "endpoint");
    std::string mode = optString(cfg, "mode", "bind");
    if (mode != "bind" && mode != "connect") {
        throw ConfigError("parameter 'mode' must be 'bind' or 'connect'");
    }
    opts.bind = (mode == "bind");
    opts.multipart = optBool(cfg, "multipart", true);
    opts.sendHwm = static_cast<int>(optInt(cfg, "send-hwm", 1000, 0, INT32_MAX));
    opts.lingerMs = static_cast<int>(optInt(cfg, "linger-ms", 1000, -1, INT32_MAX));
    opts.ioThreads = static_cast<int>(optInt(cfg, "io-threads", 1, 1, 64));

    return std::make_unique<ZmqSink>(std::move(opts), Template(optString(cfg, "topic", "")),
                                     createFormatter(cfg->get("format")));
}

}
