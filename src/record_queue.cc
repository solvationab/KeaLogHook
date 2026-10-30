#include "record_queue.h"

namespace ip_audit {

RecordQueue::RecordQueue(size_t capacity) : capacity_(capacity) {}

bool RecordQueue::tryPush(AuditRecord record) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (closed_ || records_.size() >= capacity_) {
        ++dropped_;
        return false;
    }
    records_.push_back(std::move(record));
    ready_.notify_one();
    return true;
}

bool RecordQueue::waitPop(AuditRecord& record) {
    std::unique_lock<std::mutex> lock(mutex_);
    ready_.wait(lock, [this] { return closed_ || !records_.empty(); });
    if (records_.empty()) {
        return false;
    }
    record = std::move(records_.front());
    records_.pop_front();
    return true;
}

void RecordQueue::close() {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        closed_ = true;
    }
    ready_.notify_all();
}

size_t RecordQueue::size() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return records_.size();
}

uint64_t RecordQueue::droppedCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return dropped_;
}

}