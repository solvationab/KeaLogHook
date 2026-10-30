#pragma once

#include "audit_record.h"
#include "sink.h"

#include <cc/data.h>

#include <memory>
#include <set>
#include <string>
#include <vector>

namespace ip_audit {

class AuditManager {
public:
    // sinks is the hook's "sinks" parameter: a non-empty list of sink objects.
    static std::unique_ptr<AuditManager> create(const isc::data::ConstElementPtr& sinks);

    size_t sinkCount() const { return sinks_.size(); }

    // Delivers the record to every sink subscribed to its event. Never throws.
    void publish(const AuditRecord& record) noexcept;

private:
    struct Entry {
        std::string name;
        std::set<std::string> events;  // empty = all events
        std::unique_ptr<Sink> sink;
    };

    std::vector<Entry> sinks_;
};

}
