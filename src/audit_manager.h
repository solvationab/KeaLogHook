#pragma once

#include "audit_record.h"
#include "record_queue.h"
#include "sink.h"

#include <cc/data.h>

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <set>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

namespace ip_audit {

class AuditManager {
public:
    static constexpr size_t kDefaultQueueCapacity = 10000;

    struct Statistics {
        size_t queueDepth = 0;
        size_t queueCapacity = 0;
        size_t sinkCount = 0;
        uint64_t droppedRecords = 0;
        uint64_t sinkWrites = 0;
        uint64_t sinkWriteFailures = 0;
    };

    struct ReopenResult {
        size_t reopened = 0;
        size_t unsupported = 0;
        size_t failed = 0;
        std::vector<std::string> errors;
    };

    // sinks is the hook's "sinks" parameter: a non-empty list of sink objects.
    static std::unique_ptr<AuditManager> create(
        const isc::data::ConstElementPtr& sinks,
        size_t queueCapacity = kDefaultQueueCapacity);

    ~AuditManager();

    AuditManager(const AuditManager&) = delete;
    AuditManager& operator=(const AuditManager&) = delete;

    size_t sinkCount() const { return sinks_.size(); }
    uint64_t droppedRecords() const { return queue_.droppedCount() + enqueueErrors_.load(); }
    Statistics statistics() const;
    ReopenResult reopenSinks();

    // Queues the record for asynchronous delivery. Never throws.
    void publish(AuditRecord record) noexcept;

private:
    explicit AuditManager(size_t queueCapacity);
    void run();
    void deliver(const AuditRecord& record) noexcept;

    struct Entry {
        std::string name;
        std::set<std::string> events;  // empty = all events
        std::unique_ptr<Sink> sink;
        bool renewalsOnChange = false;
        uint64_t renewalRateLimit = 0;
        double renewalRateTokens = 0;
        std::chrono::steady_clock::time_point renewalRateRefill;
        std::unordered_map<std::string, std::string> renewalSignatures;
    };

    RecordQueue queue_;
    std::thread worker_;
    std::atomic<uint64_t> enqueueErrors_{0};
    std::atomic<uint64_t> sinkWrites_{0};
    std::atomic<uint64_t> sinkWriteFailures_{0};
    std::vector<Entry> sinks_;

    bool shouldDeliver(Entry& entry, const AuditRecord& record);
    void rememberDelivery(Entry& entry, const AuditRecord& record) noexcept;
};

}
