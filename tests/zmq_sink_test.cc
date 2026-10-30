#include "sink_factory.h"

#include "config_util.h"
#include "test_util.h"

#include <zmq.h>

#include <algorithm>

using namespace ip_audit;
using ip_audit_test::json;
using ip_audit_test::TempDir;

namespace {

class Subscriber {
public:
    explicit Subscriber(const std::string& endpoint) {
        ctx_ = zmq_ctx_new();
        sock_ = zmq_socket(ctx_, ZMQ_SUB);
        int linger = 0;
        zmq_setsockopt(sock_, ZMQ_LINGER, &linger, sizeof(linger));
        zmq_setsockopt(sock_, ZMQ_SUBSCRIBE, "", 0);
        if (zmq_connect(sock_, endpoint.c_str()) != 0) {
            throw std::runtime_error("zmq_connect failed");
        }
    }

    ~Subscriber() {
        zmq_close(sock_);
        zmq_ctx_term(ctx_);
    }

    bool receive(std::vector<std::string>& parts, int timeoutMs) {
        zmq_pollitem_t item = {sock_, 0, ZMQ_POLLIN, 0};
        if (zmq_poll(&item, 1, timeoutMs) <= 0) {
            return false;
        }
        parts.clear();
        int more = 1;
        while (more) {
            char buf[4096];
            int n = zmq_recv(sock_, buf, sizeof(buf), 0);
            if (n < 0) {
                return false;
            }
            parts.emplace_back(buf, std::min<size_t>(static_cast<size_t>(n), sizeof(buf)));
            size_t size = sizeof(more);
            zmq_getsockopt(sock_, ZMQ_RCVMORE, &more, &size);
        }
        return true;
    }

private:
    void* ctx_;
    void* sock_;
};

// A PUB socket drops messages until the subscriber has connected, so publish until one arrives.
bool publishUntilReceived(Sink& sink, const AuditRecord& record, Subscriber& sub,
                          std::vector<std::string>& parts) {
    for (int i = 0; i < 50; ++i) {
        sink.write(record);
        if (sub.receive(parts, 100)) {
            return true;
        }
    }
    return false;
}

AuditRecord sampleRecord() {
    AuditRecord r;
    r.set("event", "lease-assign");
    r.set("ip-address", "192.0.2.10");
    return r;
}

std::string zmqCfg(const std::string& endpoint, const std::string& extra = "") {
    return R"({"type":"zeromq","linger-ms":0,"endpoint":")" + endpoint + R"(")" +
           (extra.empty() ? "" : "," + extra) + "}";
}

}

TEST(ZmqSink, PublishesTopicAndPayloadAsMultipart) {
    TempDir dir;
    std::string endpoint = "ipc://" + dir.file("zmq.sock");
    auto sink = SinkFactory().create(json(zmqCfg(endpoint, R"("topic":"ip-audit.%{event}")")));
    Subscriber sub(endpoint);

    std::vector<std::string> parts;
    ASSERT_TRUE(publishUntilReceived(*sink, sampleRecord(), sub, parts));
    EXPECT_EQ((std::vector<std::string>{"ip-audit.lease-assign",
                                        R"({"event":"lease-assign","ip-address":"192.0.2.10"})"}),
              parts);
}

TEST(ZmqSink, SinglePartPrefixesPayloadWithTopic) {
    TempDir dir;
    std::string endpoint = "ipc://" + dir.file("zmq.sock");
    auto sink = SinkFactory().create(
        json(zmqCfg(endpoint, R"("multipart":false,"topic":"ip-audit.%{event}")")));
    Subscriber sub(endpoint);

    std::vector<std::string> parts;
    ASSERT_TRUE(publishUntilReceived(*sink, sampleRecord(), sub, parts));
    EXPECT_EQ((std::vector<std::string>{
                  R"(ip-audit.lease-assign {"event":"lease-assign","ip-address":"192.0.2.10"})"}),
              parts);
}

TEST(ZmqSink, WriteWithoutSubscribersDoesNotThrow) {
    TempDir dir;
    auto sink = SinkFactory().create(json(zmqCfg("ipc://" + dir.file("zmq.sock"))));
    EXPECT_NO_THROW(sink->write(sampleRecord()));
}

TEST(ZmqSink, RejectsInvalidConfiguration) {
    TempDir dir;
    std::string endpoint = "ipc://" + dir.file("zmq.sock");
    EXPECT_THROW(SinkFactory().create(json(R"({"type":"zeromq"})")), ConfigError);
    EXPECT_THROW(SinkFactory().create(json(zmqCfg(endpoint, R"("mode":"listen")"))), ConfigError);
    EXPECT_THROW(SinkFactory().create(json(zmqCfg(endpoint, R"("io-threads":0)"))), ConfigError);
    EXPECT_THROW(SinkFactory().create(json(zmqCfg(endpoint, R"("topic":"%{nope}")"))), ConfigError);
    EXPECT_THROW(SinkFactory().create(json(zmqCfg(endpoint, R"("typo":1)"))), ConfigError);
}

TEST(ZmqSink, BindFailureIsReportedAtCreation) {
    EXPECT_THROW(SinkFactory().create(json(zmqCfg("bogus://nowhere"))), std::runtime_error);
}
