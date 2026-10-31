#include "audit_manager.h"

#include "config_util.h"
#include "ip_audit_log.h"
#include "sink_factory.h"

#include <algorithm>
#include <chrono>
#include <stdexcept>
#include <stats/stats_mgr.h>
#include <vector>

using isc::data::ConstElementPtr;
using isc::data::Element;

namespace ip_audit {

namespace {

constexpr size_t kMaxRenewalCacheEntries = 100000;

std::string renewalSignature(const AuditRecord& record) {
    static const std::vector<std::string> fields = {
        "ip-address", "hw-address", "client-id", "duid", "giaddr", "relay-address",
        "circuit-id", "circuit-id-text", "remote-id", "remote-id-text", "subscriber-id",
        "subscriber-id-text", "link-selection", "relay-suboptions", "relay-interface-id",
        "relay-interface-id-text", "relay-link-address"};
    std::string signature;
    for (const auto& name : fields) {
        const auto* field = record.find(name);
        const std::string value = field ? field->value : std::string();
        signature += std::to_string(value.size());
        signature.push_back(':');
        signature += value;
    }
    return signature;
}

}

AuditManager::AuditManager(size_t queueCapacity, std::string statisticsPrefix)
    : queue_(queueCapacity), statisticsPrefix_(std::move(statisticsPrefix)) {
    if (queueCapacity == 0) {
        throw ConfigError("parameter 'queue-size' must be greater than zero");
    }
}

AuditManager::~AuditManager() {
    queue_.close();
    if (worker_.joinable()) {
        worker_.join();
    }
    if (statisticsWorker_.joinable()) {
        {
            std::lock_guard<std::mutex> lock(statisticsMutex_);
            stopStatistics_ = true;
        }
        statisticsCondition_.notify_one();
        statisticsWorker_.join();
    }
    clearStatistics();
    const uint64_t dropped = droppedRecords();
    if (dropped > 0) {
        LOG_WARN(ip_audit_logger, IP_AUDIT_QUEUE_OVERFLOW).arg(dropped);
    }
}

void AuditManager::runStatistics() noexcept {
    while (true) {
        updateStatistics();
        std::unique_lock<std::mutex> lock(statisticsMutex_);
        if (statisticsCondition_.wait_for(lock, std::chrono::seconds(1),
                                          [this] { return stopStatistics_; })) {
            return;
        }
    }
}

void AuditManager::updateStatistics() noexcept {
    try {
        const auto stats = statistics();
        auto& statsManager = isc::stats::StatsMgr::instance();
        statsManager.setValue(statisticsPrefix_ + "-queue-depth",
                              static_cast<int64_t>(stats.queueDepth));
        statsManager.setValue(statisticsPrefix_ + "-queue-capacity",
                              static_cast<int64_t>(stats.queueCapacity));
        statsManager.setValue(statisticsPrefix_ + "-sink-count",
                              static_cast<int64_t>(stats.sinkCount));
        statsManager.setValue(statisticsPrefix_ + "-records-dropped",
                              static_cast<int64_t>(stats.droppedRecords));
        statsManager.setValue(statisticsPrefix_ + "-sink-writes",
                              static_cast<int64_t>(stats.sinkWrites));
        statsManager.setValue(statisticsPrefix_ + "-sink-write-failures",
                              static_cast<int64_t>(stats.sinkWriteFailures));
    } catch (...) {
        // Metrics are best effort and must never disrupt DHCP or sink delivery.
    }
}

void AuditManager::clearStatistics() noexcept {
    if (statisticsPrefix_.empty()) {
        return;
    }
    try {
        auto& statsManager = isc::stats::StatsMgr::instance();
        for (const char* suffix : {"queue-depth", "queue-capacity", "sink-count",
                                   "records-dropped", "sink-writes", "sink-write-failures"}) {
            statsManager.del(statisticsPrefix_ + "-" + suffix);
        }
    } catch (...) {
    }
}

AuditManager::Statistics AuditManager::statistics() const {
    Statistics stats;
    stats.queueDepth = queue_.size();
    stats.queueCapacity = queue_.capacity();
    stats.sinkCount = sinks_.size();
    stats.droppedRecords = droppedRecords();
    stats.sinkWrites = sinkWrites_.load();
    stats.sinkWriteFailures = sinkWriteFailures_.load();
    return stats;
}

AuditManager::ReopenResult AuditManager::reopenSinks() {
    ReopenResult result;
    for (auto& entry : sinks_) {
        try {
            if (entry.sink->reopen()) {
                ++result.reopened;
            } else {
                ++result.unsupported;
            }
        } catch (const std::exception& ex) {
            ++result.failed;
            result.errors.push_back(entry.name + ": " + ex.what());
        } catch (...) {
            ++result.failed;
            result.errors.push_back(entry.name + ": unknown error");
        }
    }
    return result;
}

std::unique_ptr<AuditManager> AuditManager::create(const ConstElementPtr& sinks,
                                                  size_t queueCapacity,
                                                  std::string statisticsPrefix) {
    if (!sinks || sinks->getType() != Element::list || sinks->listValue().empty()) {
        throw ConfigError("parameter 'sinks' must be a non-empty list of sink objects");
    }

    SinkFactory factory;
    auto manager = std::unique_ptr<AuditManager>(
        new AuditManager(queueCapacity, std::move(statisticsPrefix)));
    size_t index = 0;
    for (const auto& cfg : sinks->listValue()) {
        Entry entry;
        std::string type = requireString(cfg, "type");
        entry.name = optString(cfg, "name", type + "-" + std::to_string(index));
        entry.renewalsOnChange = optBool(cfg, "renewals-on-change", false);
        entry.renewalRateLimit = static_cast<uint64_t>(optInt(cfg, "renewal-rate-limit", 0, 0,
                                      1000000));
        entry.renewalRateTokens = static_cast<double>(entry.renewalRateLimit);
        entry.renewalRateRefill = std::chrono::steady_clock::now();

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
    if (!manager->statisticsPrefix_.empty()) {
        manager->statisticsWorker_ = std::thread(&AuditManager::runStatistics, manager.get());
    }
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
    for (auto& entry : sinks_) {
        if (!entry.events.empty() && (!event || entry.events.count(event->value) == 0)) {
            continue;
        }
        try {
            if (!shouldDeliver(entry, record)) {
                continue;
            }
            entry.sink->write(record);
            sinkWrites_.fetch_add(1);
            rememberDelivery(entry, record);
        } catch (const std::exception& ex) {
            sinkWriteFailures_.fetch_add(1);
            LOG_ERROR(ip_audit_logger, IP_AUDIT_SINK_WRITE_FAILED).arg(entry.name).arg(ex.what());
        } catch (...) {
            sinkWriteFailures_.fetch_add(1);
            LOG_ERROR(ip_audit_logger, IP_AUDIT_SINK_WRITE_FAILED).arg(entry.name).arg("unknown error");
        }
    }
}

bool AuditManager::shouldDeliver(Entry& entry, const AuditRecord& record) {
    const auto* event = record.find("event");
    if (!event || event->value != "lease-renew") {
        return true;
    }

    const auto* ip = record.find("ip-address");
    std::string signature;
    const bool needsSignatureUpdate = entry.renewalsOnChange && ip && !ip->value.empty();
    if (needsSignatureUpdate) {
        signature = renewalSignature(record);
        auto previous = entry.renewalSignatures.find(ip->value);
        if (previous != entry.renewalSignatures.end() && previous->second == signature) {
            return false;
        }
    }

    if (entry.renewalRateLimit > 0) {
        const auto now = std::chrono::steady_clock::now();
        const double elapsed = std::chrono::duration<double>(now - entry.renewalRateRefill).count();
        entry.renewalRateTokens = std::min(
            static_cast<double>(entry.renewalRateLimit),
            entry.renewalRateTokens + elapsed * static_cast<double>(entry.renewalRateLimit));
        entry.renewalRateRefill = now;
        if (entry.renewalRateTokens < 1.0) {
            return false;
        }
        entry.renewalRateTokens -= 1.0;
    }

    return true;
}

void AuditManager::rememberDelivery(Entry& entry, const AuditRecord& record) noexcept {
    if (!entry.renewalsOnChange) {
        return;
    }
    try {
        const auto* event = record.find("event");
        const auto* ip = record.find("ip-address");
        if (!event || event->value != "lease-renew") {
            if (ip) {
                entry.renewalSignatures.erase(ip->value);
            }
            return;
        }
        if (!ip || ip->value.empty()) {
            return;
        }

        auto previous = entry.renewalSignatures.find(ip->value);
        if (previous == entry.renewalSignatures.end() &&
            entry.renewalSignatures.size() >= kMaxRenewalCacheEntries) {
            entry.renewalSignatures.erase(entry.renewalSignatures.begin());
        }
        entry.renewalSignatures[ip->value] = renewalSignature(record);
    } catch (...) {
        // A cache allocation failure only disables suppression for this renewal.
    }
}

}
