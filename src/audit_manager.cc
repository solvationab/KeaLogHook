#include "audit_manager.h"

#include "config_util.h"
#include "ip_audit_log.h"
#include "sink_factory.h"

#include <algorithm>
#include <stdexcept>

using isc::data::ConstElementPtr;
using isc::data::Element;

namespace ip_audit {

AuditManager::AuditManager(size_t queueCapacity) : queue_(queueCapacity) {
    if (queueCapacity == 0) {
        throw ConfigError("parameter 'queue-size' must be greater than zero");
    }
}

AuditManager::~AuditManager() {
    queue_.close();
    if (worker_.joinable()) {
        worker_.join();
    }
    const uint64_t dropped = droppedRecords();
    if (dropped > 0) {
        LOG_WARN(ip_audit_logger, IP_AUDIT_QUEUE_OVERFLOW).arg(dropped);
    }
}

std::unique_ptr<AuditManager> AuditManager::create(const ConstElementPtr& sinks,
                                                  size_t queueCapacity) {
    if (!sinks || sinks->getType() != Element::list || sinks->listValue().empty()) {
        throw ConfigError("parameter 'sinks' must be a non-empty list of sink objects");
    }

    SinkFactory factory;
    auto manager = std::unique_ptr<AuditManager>(new AuditManager(queueCapacity));
    size_t index = 0;
    for (const auto& cfg : sinks->listValue()) {
        Entry entry;
        std::string type = requireString(cfg, "type");
        entry.name = optString(cfg, "name", type + "-" + std::to_string(index));

        for (const auto& ev : optStringList(cfg, "events")) {
            const auto& known = knownEventNames();
            if (std::find(known.begin(), known.end(), ev) == known.end()) {
                throw ConfigError("sink '" + entry.name + "': unknown event '" + ev + "'");
            }
            entry.events.insert(ev);
        }

        try {
            entry.sink = factory.create(cfg);
        } catch (const std::exception& ex) {
            throw ConfigError("sink '" + entry.name + "': " + ex.what());
        }
        LOG_INFO(ip_audit_logger, IP_AUDIT_SINK_CREATED).arg(entry.name).arg(type);
        manager->sinks_.push_back(std::move(entry));
        ++index;
    }
    manager->worker_ = std::thread(&AuditManager::run, manager.get());
    return manager;
}

void AuditManager::publish(AuditRecord record) noexcept {
    const AuditRecord::Field* event = record.find("event");
    bool subscribed = false;
    for (const auto& entry : sinks_) {
        if (entry.events.empty() || (event && entry.events.count(event->value) != 0)) {
            subscribed = true;
            break;
        }
    }
    if (!subscribed) {
        return;
    }

    try {
        if (!queue_.tryPush(std::move(record))) {
            return;
        }
    } catch (...) {
        enqueueErrors_.fetch_add(1);
    }
}

void AuditManager::run() {
    AuditRecord record;
    while (queue_.waitPop(record)) {
        deliver(record);
    }
}

void AuditManager::deliver(const AuditRecord& record) noexcept {
    const AuditRecord::Field* event = record.find("event");
    for (const auto& entry : sinks_) {
        if (!entry.events.empty() && (!event || entry.events.count(event->value) == 0)) {
            continue;
        }
        try {
            entry.sink->write(record);
        } catch (const std::exception& ex) {
            LOG_ERROR(ip_audit_logger, IP_AUDIT_SINK_WRITE_FAILED).arg(entry.name).arg(ex.what());
        } catch (...) {
            LOG_ERROR(ip_audit_logger, IP_AUDIT_SINK_WRITE_FAILED).arg(entry.name).arg("unknown error");
        }
    }
}

}
