#include "record_builder.h"

#include <dhcp/dhcp4.h>
#include <dhcp/dhcp6.h>
#include <dhcp/option.h>

#include <chrono>
#include <cstdio>
#include <ctime>

using namespace isc::dhcp;

namespace ip_audit {

namespace {

// RFC 3046 / 3527 / 3993 relay agent sub-option codes.
constexpr uint16_t kCircuitId = 1;
constexpr uint16_t kRemoteId = 2;
constexpr uint16_t kLinkSelection = 5;
constexpr uint16_t kSubscriberId = 6;

std::string toHex(const std::vector<uint8_t>& data) {
    static const char digits[] = "0123456789abcdef";
    std::string out;
    out.reserve(data.size() * 2);
    for (uint8_t b : data) {
        out += digits[b >> 4];
        out += digits[b & 0x0f];
    }
    return out;
}

// Client-controlled text must not be able to inject control characters into logs.
std::string sanitize(const std::string& s) {
    std::string out = s;
    for (char& c : out) {
        unsigned char u = static_cast<unsigned char>(c);
        if (u < 0x20 || u > 0x7e) {
            c = '?';
        }
    }
    return out;
}

std::string printableOrEmpty(const std::vector<uint8_t>& data) {
    for (uint8_t b : data) {
        if (b < 0x20 || b > 0x7e) {
            return std::string();
        }
    }
    return std::string(data.begin(), data.end());
}

std::string isoTime(std::time_t secs, int millis = -1) {
    std::tm tm;
    gmtime_r(&secs, &tm);
    char buf[40];
    size_t n = std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%S", &tm);
    std::string out(buf, n);
    if (millis >= 0) {
        std::snprintf(buf, sizeof(buf), ".%03d", millis);
        out += buf;
    }
    return out + "Z";
}

std::string nowIso() {
    using namespace std::chrono;
    auto now = system_clock::now();
    auto ms = duration_cast<milliseconds>(now.time_since_epoch()).count();
    return isoTime(static_cast<std::time_t>(ms / 1000), static_cast<int>(ms % 1000));
}

}

AuditRecord buildRecord(const std::string& event, const Pkt4Ptr& query, const Lease4Ptr& lease) {
    AuditRecord r;
    r.set("timestamp", nowIso());
    r.set("event", event);
    r.set("ip-address", lease->addr_.toText());
    r.set("hw-address", lease->hwaddr_ ? lease->hwaddr_->toText(false) : "");
    r.set("client-id", lease->client_id_ ? lease->client_id_->toText() : "");
    r.set("hostname", sanitize(lease->hostname_));
    r.setNumber("subnet-id", lease->subnet_id_);
    r.setNumber("valid-lifetime", lease->valid_lft_);
    r.set("lease-expires",
          isoTime(static_cast<std::time_t>(lease->cltt_) + static_cast<std::time_t>(lease->valid_lft_)));

    std::string messageType, transactionId, iface, giaddr, relayAddress, suboptions, linkSelection;
    OptionPtr rai;
    if (query) {
        messageType = query->getName();
        transactionId = std::to_string(query->getTransid());
        iface = sanitize(query->getIface());
        giaddr = query->getGiaddr().toText();
        relayAddress = query->getRemoteAddr().toText();
        rai = query->getOption(DHO_DHCP_AGENT_OPTIONS);
    }

    auto sub = [&](uint16_t code) -> std::vector<uint8_t> {
        OptionPtr o = rai ? rai->getOption(code) : OptionPtr();
        return o ? o->toBinary() : std::vector<uint8_t>();
    };
    auto circuit = sub(kCircuitId);
    auto remote = sub(kRemoteId);
    auto subscriber = sub(kSubscriberId);
    auto link = sub(kLinkSelection);

    if (rai) {
        for (const auto& kv : rai->getOptions()) {
            if (!suboptions.empty()) {
                suboptions += ',';
            }
            suboptions += std::to_string(kv.first) + "=" + toHex(kv.second->toBinary());
        }
    }
    if (link.size() == 4) {
        linkSelection = std::to_string(link[0]) + "." + std::to_string(link[1]) + "." +
                        std::to_string(link[2]) + "." + std::to_string(link[3]);
    }

    r.set("message-type", messageType);
    r.set("transaction-id", transactionId);
    r.set("interface", iface);
    r.set("giaddr", giaddr);
    r.set("relay-address", relayAddress);
    r.set("circuit-id", toHex(circuit));
    r.set("circuit-id-text", printableOrEmpty(circuit));
    r.set("remote-id", toHex(remote));
    r.set("remote-id-text", printableOrEmpty(remote));
    r.set("subscriber-id", toHex(subscriber));
    r.set("subscriber-id-text", printableOrEmpty(subscriber));
    r.set("link-selection", linkSelection);
    r.set("relay-suboptions", suboptions);
    r.set("address-family", "IPv4");
    r.set("lease-type", "");
    r.setEmptyNumber("iaid");
    r.set("duid", "");
    r.setEmptyNumber("prefix-length");
    r.set("relay-interface-id", "");
    r.set("relay-interface-id-text", "");
    r.set("relay-link-address", "");
    return r;
}

AuditRecord buildRecord(const std::string& event, const Pkt6Ptr& query, const Lease6Ptr& lease) {
    AuditRecord r;
    r.set("timestamp", nowIso());
    r.set("event", event);
    r.set("ip-address", lease->addr_.toText());
    r.set("hw-address", lease->hwaddr_ ? lease->hwaddr_->toText(false) : "");
    r.set("client-id", "");
    r.set("hostname", sanitize(lease->hostname_));
    r.setNumber("subnet-id", lease->subnet_id_);
    r.setNumber("valid-lifetime", lease->valid_lft_);
    r.set("lease-expires",
          isoTime(static_cast<std::time_t>(lease->cltt_) + static_cast<std::time_t>(lease->valid_lft_)));

    const char* leaseType = "IA_NA";
    if (lease->type_ == Lease::TYPE_TA) {
        leaseType = "IA_TA";
    } else if (lease->type_ == Lease::TYPE_PD) {
        leaseType = "IA_PD";
    }
    std::string messageType, transactionId, iface, relayAddress, remoteId, remoteIdText;
    std::string subscriberId, subscriberIdText, interfaceId, interfaceIdText, relaySuboptions;
    std::string relayLinkAddress;
    if (query) {
        messageType = query->getName();
        transactionId = std::to_string(query->getTransid());
        iface = sanitize(query->getIface());
        relayAddress = query->getRemoteAddr().toText();
        if (!query->relay_info_.empty()) {
            const auto& outerRelay = query->relay_info_.front();
            relayAddress = outerRelay.peeraddr_.toText();
            relayLinkAddress = outerRelay.linkaddr_.toText();

            for (size_t depth = 0; depth < query->relay_info_.size(); ++depth) {
                const auto& relay = query->relay_info_[depth];
                for (const auto& option : relay.options_) {
                    if (option.first == D6O_RELAY_MSG) {
                        continue;
                    }
                    if (!relaySuboptions.empty()) {
                        relaySuboptions += ',';
                    }
                    relaySuboptions += std::to_string(depth) + ":" + std::to_string(option.first) + "=" +
                                       toHex(option.second->toBinary());
                }
            }

            // Use the relay closest to the client that supplies each identifier.
            for (auto relay = query->relay_info_.rbegin(); relay != query->relay_info_.rend(); ++relay) {
                auto getOption = [&](uint16_t code) -> OptionPtr {
                    auto option = relay->options_.find(code);
                    return option == relay->options_.end() ? OptionPtr() : option->second;
                };
                if (interfaceId.empty()) {
                    OptionPtr option = getOption(D6O_INTERFACE_ID);
                    if (option) {
                        auto data = option->toBinary();
                        interfaceId = toHex(data);
                        interfaceIdText = printableOrEmpty(data);
                    }
                }
                if (remoteId.empty()) {
                    OptionPtr option = getOption(D6O_REMOTE_ID);
                    if (option) {
                        auto data = option->toBinary();
                        remoteId = toHex(data);
                        remoteIdText = printableOrEmpty(data);
                    }
                }
                if (subscriberId.empty()) {
                    OptionPtr option = getOption(D6O_SUBSCRIBER_ID);
                    if (option) {
                        auto data = option->toBinary();
                        subscriberId = toHex(data);
                        subscriberIdText = printableOrEmpty(data);
                    }
                }
            }
        }
    }

    r.set("message-type", messageType);
    r.set("transaction-id", transactionId);
    r.set("interface", iface);
    r.set("giaddr", "");
    r.set("relay-address", relayAddress);
    r.set("circuit-id", "");
    r.set("circuit-id-text", "");
    r.set("remote-id", remoteId);
    r.set("remote-id-text", remoteIdText);
    r.set("subscriber-id", subscriberId);
    r.set("subscriber-id-text", subscriberIdText);
    r.set("link-selection", "");
    r.set("relay-suboptions", relaySuboptions);
    r.set("address-family", "IPv6");
    r.set("lease-type", leaseType);
    r.setNumber("iaid", lease->iaid_);
    r.set("duid", lease->duid_ ? lease->duid_->toText() : "");
    if (lease->type_ == Lease::TYPE_PD) {
        r.setNumber("prefix-length", lease->prefixlen_);
    } else {
        r.setEmptyNumber("prefix-length");
    }
    r.set("relay-interface-id", interfaceId);
    r.set("relay-interface-id-text", interfaceIdText);
    r.set("relay-link-address", relayLinkAddress);
    return r;
}

}
