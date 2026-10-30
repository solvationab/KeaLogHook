#include "record_builder.h"

#include "audit_record.h"

#include <asiolink/io_address.h>
#include <dhcp/dhcp4.h>
#include <dhcp/duid.h>
#include <dhcp/hwaddr.h>
#include <dhcp/option.h>

#include <gtest/gtest.h>

#include <regex>

using namespace ip_audit;
using namespace isc::dhcp;
using isc::asiolink::IOAddress;

namespace {

constexpr time_t kCltt = 1700000000;  // 2023-11-14T22:13:20Z

Lease4Ptr makeLease(const std::string& hostname = "") {
    HWAddrPtr hw(new HWAddr(std::vector<uint8_t>{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}, HTYPE_ETHER));
    ClientIdPtr cid(new ClientId(std::vector<uint8_t>{0x01, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}));
    return Lease4Ptr(new Lease4(IOAddress("192.0.2.10"), hw, cid, 3600, kCltt, 7, false, false, hostname));
}

OptionPtr subOption(uint16_t code, const OptionBuffer& data) {
    return OptionPtr(new Option(Option::V4, code, data));
}

Pkt4Ptr makeQuery(const OptionPtr& relayAgentInfo) {
    Pkt4Ptr query(new Pkt4(DHCPREQUEST, 0x1234));
    query->setIface("eth0");
    query->setGiaddr(IOAddress("192.0.2.1"));
    query->setRemoteAddr(IOAddress("192.0.2.1"));
    if (relayAgentInfo) {
        query->addOption(relayAgentInfo);
    }
    return query;
}

OptionPtr makeRelayAgentInfo() {
    OptionPtr rai(new Option(Option::V4, DHO_DHCP_AGENT_OPTIONS));
    rai->addOption(subOption(1, {0x00, 0x04, 0x00, 0x0a}));       // circuit-id, not printable
    rai->addOption(subOption(2, {'a', 'b', '1', '2'}));           // remote-id, printable
    rai->addOption(subOption(5, {192, 0, 2, 99}));                // link-selection
    rai->addOption(subOption(6, {'s', 'u', 'b', '1'}));           // subscriber-id, printable
    return rai;
}

std::string value(const AuditRecord& record, const std::string& name) {
    const auto* f = record.find(name);
    EXPECT_NE(nullptr, f) << "missing field " << name;
    return f ? f->value : std::string();
}

}

TEST(RecordBuilder, FieldsFollowKnownFieldNamesInOrder) {
    AuditRecord r = buildRecord("lease-assign", makeQuery(makeRelayAgentInfo()), makeLease());
    std::vector<std::string> names;
    for (const auto& f : r.fields()) {
        names.push_back(f.name);
    }
    EXPECT_EQ(knownFieldNames(), names);
}

TEST(RecordBuilder, LeaseFields) {
    Lease4Ptr lease = makeLease();
    AuditRecord r = buildRecord("lease-assign", makeQuery(OptionPtr()), lease);

    EXPECT_EQ("lease-assign", value(r, "event"));
    EXPECT_EQ("192.0.2.10", value(r, "ip-address"));
    EXPECT_EQ("aa:bb:cc:dd:ee:ff", value(r, "hw-address"));
    EXPECT_EQ(lease->client_id_->toText(), value(r, "client-id"));
    EXPECT_EQ("7", value(r, "subnet-id"));
    EXPECT_EQ("3600", value(r, "valid-lifetime"));
    EXPECT_EQ("2023-11-14T23:13:20Z", value(r, "lease-expires"));
    EXPECT_TRUE(r.find("subnet-id")->numeric);
    EXPECT_TRUE(r.find("valid-lifetime")->numeric);
    EXPECT_FALSE(r.find("ip-address")->numeric);
}

TEST(RecordBuilder, TimestampIsIso8601WithMilliseconds) {
    AuditRecord r = buildRecord("lease-assign", Pkt4Ptr(), makeLease());
    EXPECT_TRUE(std::regex_match(value(r, "timestamp"),
                                 std::regex(R"(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z)")));
}

TEST(RecordBuilder, PacketFields) {
    AuditRecord r = buildRecord("lease-assign", makeQuery(OptionPtr()), makeLease());

    EXPECT_EQ("DHCPREQUEST", value(r, "message-type"));
    EXPECT_EQ("4660", value(r, "transaction-id"));
    EXPECT_EQ("eth0", value(r, "interface"));
    EXPECT_EQ("192.0.2.1", value(r, "giaddr"));
    EXPECT_EQ("192.0.2.1", value(r, "relay-address"));
}

TEST(RecordBuilder, RelayAgentInformation) {
    AuditRecord r = buildRecord("lease-assign", makeQuery(makeRelayAgentInfo()), makeLease());

    EXPECT_EQ("0004000a", value(r, "circuit-id"));
    EXPECT_EQ("", value(r, "circuit-id-text"));
    EXPECT_EQ("61623132", value(r, "remote-id"));
    EXPECT_EQ("ab12", value(r, "remote-id-text"));
    EXPECT_EQ("73756231", value(r, "subscriber-id"));
    EXPECT_EQ("sub1", value(r, "subscriber-id-text"));
    EXPECT_EQ("192.0.2.99", value(r, "link-selection"));
    EXPECT_EQ("1=0004000a,2=61623132,5=c0000263,6=73756231", value(r, "relay-suboptions"));
}

TEST(RecordBuilder, MalformedLinkSelectionIsNotDecoded) {
    OptionPtr rai(new Option(Option::V4, DHO_DHCP_AGENT_OPTIONS));
    rai->addOption(subOption(5, {192, 0, 2}));
    AuditRecord r = buildRecord("lease-assign", makeQuery(rai), makeLease());

    EXPECT_EQ("", value(r, "link-selection"));
    EXPECT_EQ("5=c00002", value(r, "relay-suboptions"));
}

TEST(RecordBuilder, QueryWithoutOption82HasEmptyRelayFields) {
    AuditRecord r = buildRecord("lease-assign", makeQuery(OptionPtr()), makeLease());

    EXPECT_EQ("", value(r, "circuit-id"));
    EXPECT_EQ("", value(r, "remote-id"));
    EXPECT_EQ("", value(r, "relay-suboptions"));
}

TEST(RecordBuilder, NullQueryLeavesPacketAndRelayFieldsEmpty) {
    AuditRecord r = buildRecord("lease-expire", Pkt4Ptr(), makeLease());

    EXPECT_EQ("lease-expire", value(r, "event"));
    EXPECT_EQ("192.0.2.10", value(r, "ip-address"));
    for (const char* name : {"message-type", "transaction-id", "interface", "giaddr", "relay-address",
                             "circuit-id", "remote-id", "subscriber-id", "link-selection",
                             "relay-suboptions"}) {
        EXPECT_EQ("", value(r, name)) << name;
    }
}

TEST(RecordBuilder, HostnameControlCharactersAreReplaced) {
    AuditRecord r = buildRecord("lease-assign", Pkt4Ptr(), makeLease("bad\nhost\x01"));
    EXPECT_EQ("bad?host?", value(r, "hostname"));
}

TEST(RecordBuilder, LeaseWithoutHardwareAddressOrClientId) {
    Lease4Ptr lease(new Lease4());
    lease->addr_ = IOAddress("192.0.2.20");
    lease->valid_lft_ = 60;
    lease->cltt_ = kCltt;
    AuditRecord r = buildRecord("lease-expire", Pkt4Ptr(), lease);

    EXPECT_EQ("192.0.2.20", value(r, "ip-address"));
    EXPECT_EQ("", value(r, "hw-address"));
    EXPECT_EQ("", value(r, "client-id"));
}
