#include "sink_factory.h"

#include "config_util.h"
#include "file_sink.h"
#include "zmq_sink.h"

namespace ip_audit {

SinkFactory::SinkFactory() {
    registerType("file", createFileSink);
    registerType("zeromq", createZmqSink);
}

void SinkFactory::registerType(const std::string& type, SinkCreator creator) {
    creators_[type] = std::move(creator);
}

std::unique_ptr<Sink> SinkFactory::create(const isc::data::ConstElementPtr& cfg) const {
    std::string type = requireString(cfg, "type");
    auto it = creators_.find(type);
    if (it == creators_.end()) {
        std::string known;
        for (const auto& kv : creators_) {
            known += (known.empty() ? "'" : ", '") + kv.first + "'";
        }
        throw ConfigError("unknown sink type '" + type + "' (available: " + known + ")");
    }
    return it->second(cfg);
}

std::set<std::string> SinkFactory::allowedKeys(const std::set<std::string>& own) {
    std::set<std::string> keys = {"type", "name", "events", "format", "renewals-on-change",
                                  "renewal-rate-limit"};
    keys.insert(own.begin(), own.end());
    return keys;
}

}
