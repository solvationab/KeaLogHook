#pragma once

#include "sink.h"

#include <cc/data.h>

#include <functional>
#include <map>
#include <memory>
#include <set>
#include <string>

namespace ip_audit {

using SinkCreator = std::function<std::unique_ptr<Sink>(const isc::data::ConstElementPtr&)>;

class SinkFactory {
public:
    // Registers the built-in sinks.
    SinkFactory();

    void registerType(const std::string& type, SinkCreator creator);

    // Creates a sink from a sink object; its "type" parameter selects the implementation.
    std::unique_ptr<Sink> create(const isc::data::ConstElementPtr& cfg) const;

    // Parameters every sink object accepts, plus the sink's own.
    static std::set<std::string> allowedKeys(const std::set<std::string>& own);

private:
    std::map<std::string, SinkCreator> creators_;
};

}
