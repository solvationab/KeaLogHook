#include "record_queue.h"

#include <gtest/gtest.h>

#include <thread>

using namespace ip_audit;

namespace {

AuditRecord record(const std::string& value) {
    AuditRecord result;
    result.set("value", value);
    return result;
}

std::string value(const AuditRecord& item) {
    const auto* field = item.find("value");
    return field ? field->value : std::string();
}

}

TEST(RecordQueue, PreservesFifoOrder) {
    RecordQueue queue(3);
    EXPECT_TRUE(queue.tryPush(record("one")));
    EXPECT_TRUE(queue.tryPush(record("two")));
    EXPECT_TRUE(queue.tryPush(record("three")));

    AuditRecord out;
    ASSERT_TRUE(queue.waitPop(out));
    EXPECT_EQ("one", value(out));
    ASSERT_TRUE(queue.waitPop(out));
    EXPECT_EQ("two", value(out));
    ASSERT_TRUE(queue.waitPop(out));
    EXPECT_EQ("three", value(out));
}

TEST(RecordQueue, RejectsNewestRecordWhenAtCapacity) {
    RecordQueue queue(2);
    EXPECT_TRUE(queue.tryPush(record("one")));
    EXPECT_TRUE(queue.tryPush(record("two")));
    EXPECT_FALSE(queue.tryPush(record("three")));
    EXPECT_EQ(2u, queue.size());
    EXPECT_EQ(1u, queue.droppedCount());

    AuditRecord out;
    ASSERT_TRUE(queue.waitPop(out));
    EXPECT_EQ("one", value(out));
    ASSERT_TRUE(queue.waitPop(out));
    EXPECT_EQ("two", value(out));
}

TEST(RecordQueue, CloseDrainsQueuedRecordsAndRejectsNewOnes) {
    RecordQueue queue(2);
    EXPECT_TRUE(queue.tryPush(record("pending")));
    queue.close();
    EXPECT_FALSE(queue.tryPush(record("late")));
    EXPECT_EQ(1u, queue.droppedCount());

    AuditRecord out;
    ASSERT_TRUE(queue.waitPop(out));
    EXPECT_EQ("pending", value(out));
    EXPECT_FALSE(queue.waitPop(out));
}

TEST(RecordQueue, CloseWakesWaitingConsumer) {
    RecordQueue queue(1);
    bool received = true;
    std::thread consumer([&] {
        AuditRecord out;
        received = queue.waitPop(out);
    });
    queue.close();
    consumer.join();
    EXPECT_FALSE(received);
}
