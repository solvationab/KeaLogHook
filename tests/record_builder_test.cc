#include "record_builder.h"

#include "audit_record.h"

#include <asiolink/io_address.h>
#include <dhcp/dhcp4.h>
#include <dhcp/dhcp6.h>
#include <dhcp/duid.h>
#include <dhcp/hwaddr.h>
#include <dhcp/option.h>
#include <dhcp/pkt6.h>

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

Lease6Ptr makeLease6(Lease::Type type, uint8_t prefixLength = 128) {
    DuidPtr duid(new DUID(std::vector<uint8_t>{0x00, 0x01, 0x02, 0x03, 0x04, 0x05}));
    HWAddrPtr hw(new HWAddr(std::vector<uint8_t>{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}, HTYPE_ETHER));
    return Lease6Ptr(new Lease6(type, IOAddress("2001:db8:1::"), duid, 1234, 1800, 3600,
                                7, false, false, "client-v6", hw, prefixLength));
}

Pkt6Ptr makeQuery6() {
    Pkt6Ptr query(new Pkt6(DHCPV6_REQUEST, 0x123456));
    query->setIface("eth1");
    query->setRemoteAddr(IOAddress("fe80::1"));

    Pkt6::RelayInfo relay;
    relay.peeraddr_ = IOAddress("fe80::2");
    relay.linkaddr_ = IOAddress("2001:db8:1::1");
    relay.hop_count_ = 1;
    relay.options_.insert(std::make_pair(D6O_INTERFACE_ID,
        OptionPtr(new Option(Option::V6, D6O_INTERFACE_ID, OptionBuffer{'p', 'o', 'r', 't'}))));
    relay.options_.insert(std::make_pair(D6O_REMOTE_ID,
        OptionPtr(new Option(Option::V6, D6O_REMOTE_ID, OptionBuffer{0x00, 0x00, 0x00, 0x01, 'r', '1'}))));
    query->addRelayInfo(relay);
    return query;
}

OptionPtr makeRelayAgentInfo() {
    OptionPtr rai(new Option(Option::V4, DHO_DHCP_AGENT_OPTIONS));
    rai->addOption(subOption(1, {0x00, 0x04, 0x00, 0x0a}));       // circuit-id, not printable
    rai->addOption(subOption(2, {'a', 'b', '1', '2'}));           // remote-id, printable
    rai->addOption(subOption(5, {192, 0, 2, 99}));                // link-selection
    rai->addOption(subOption(6, {'s', 'u', 'b', '1'}));           // subscriber-id, printable
    rai->addOption(subOption(RAI_OPTION_VSI, {0x00, 0x00, 0x01, 0x23, 0xaa, 0xbb}));
    rai->addOption(subOption(RAI_OPTION_RELAY_FLAGS, {0x01}));
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
    EXPECT_EQ(std::string(kAuditSchemaVersion), value(r, "schema-version"));
    EXPECT_FALSE(value(r, "server").empty());
}

TEST(RecordBuilder, ServerIdentityIsStableAcrossFamilies) {
    AuditRecord v4 = buildRecord("lease-assign", Pkt4Ptr(), makeLease());
    AuditRecord v6 = buildRecord("lease-assign", Pkt6Ptr(), makeLease6(Lease::TYPE_NA));

    EXPECT_EQ(value(v4, "server"), value(v6, "server"));
    EXPECT_EQ(value(v4, "schema-version"), value(v6, "schema-version"));
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
    EXPECT_EQ("1=0004000a,2=61623132,5=c0000263,6=73756231,9=00000123aabb,10=01",
              value(r, "relay-suboptions"));
    EXPECT_EQ("01", value(r, "relay-flags"));
    EXPECT_EQ("00000123aabb", value(r, "relay-vendor-specific"));
}

TEST(RecordBuilder, VendorAndUserClassOptions) {
    Pkt4Ptr query = makeQuery(makeRelayAgentInfo());
    query->addOption(OptionPtr(new Option(Option::V4, DHO_VENDOR_CLASS_IDENTIFIER,
                                          OptionBuffer{'v', 'e', 'n', 'd', 'o', 'r'})));
    query->addOption(OptionPtr(new Option(Option::V4, DHO_USER_CLASS,
                                          OptionBuffer{5, 'c', 'l', 'a', 's', 's'})));
    AuditRecord r = buildRecord("lease-assign", query, makeLease());

    EXPECT_EQ("76656e646f72", value(r, "vendor-class"));
    EXPECT_EQ("vendor", value(r, "vendor-class-text"));
    EXPECT_EQ("05636c617373", value(r, "user-class"));
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
                             "relay-suboptions", "vendor-class", "vendor-class-text", "user-class",
                             "relay-flags", "relay-vendor-specific"}) {
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

TEST(RecordBuilder, Dhcp6AddressLeaseFields) {
    AuditRecord r = buildRecord("lease-assign", makeQuery6(), makeLease6(Lease::TYPE_NA));
    std::vector<std::string> names;
    for (const auto& field : r.fields()) {
        names.push_back(field.name);
    }

    EXPECT_EQ(knownFieldNames(), names);
    EXPECT_EQ("IPv6", value(r, "address-family"));
    EXPECT_EQ("IA_NA", value(r, "lease-type"));
    EXPECT_EQ("2001:db8:1::", value(r, "ip-address"));
    EXPECT_EQ("1234", value(r, "iaid"));
    EXPECT_EQ("00:01:02:03:04:05", value(r, "duid"));
    EXPECT_EQ("", value(r, "prefix-length"));
    EXPECT_TRUE(r.find("iaid")->numeric);
    EXPECT_TRUE(r.find("prefix-length")->numeric);
    EXPECT_EQ("REQUEST", value(r, "message-type"));
    EXPECT_EQ("1193046", value(r, "transaction-id"));
    EXPECT_EQ("fe80::2", value(r, "relay-address"));
    EXPECT_EQ("2001:db8:1::1", value(r, "relay-link-address"));
    EXPECT_EQ("706f7274", value(r, "relay-interface-id"));
    EXPECT_EQ("port", value(r, "relay-interface-id-text"));
    EXPECT_EQ("000000017231", value(r, "remote-id"));
    EXPECT_EQ("0:18=706f7274,0:37=000000017231", value(r, "relay-suboptions"));
}

TEST(RecordBuilder, Dhcp6DelegatedPrefixIncludesPrefixLength) {
    Lease6Ptr lease = makeLease6(Lease::TYPE_PD, 56);
    lease->addr_ = IOAddress("2001:db8:abcd::");
    AuditRecord r = buildRecord("lease-assign", Pkt6Ptr(), lease);

    EXPECT_EQ("IA_PD", value(r, "lease-type"));
    EXPECT_EQ("2001:db8:abcd::", value(r, "ip-address"));
    EXPECT_EQ("56", value(r, "prefix-length"));
    EXPECT_EQ("", value(r, "relay-interface-id"));
    EXPECT_EQ("", value(r, "relay-link-address"));
}
