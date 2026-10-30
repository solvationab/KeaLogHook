#pragma once

#include "audit_record.h"

#include <condition_variable>
#include <cstddef>
#include <deque>
#include <mutex>
#include <cstdint>

namespace ip_audit {

class RecordQueue {
public:
    explicit RecordQueue(size_t capacity);

    bool tryPush(AuditRecord record);
    bool waitPop(AuditRecord& record);
    void close();
    size_t size() const;
    uint64_t droppedCount() const;

private:
    const size_t capacity_;
    mutable std::mutex mutex_;
    std::condition_variable ready_;
    std::deque<AuditRecord> records_;
    uint64_t dropped_ = 0;
    bool closed_ = false;
};

}