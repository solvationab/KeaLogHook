#include "record_builder.h"

#include <dhcp/dhcp4.h>
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
    return r;
}

}
