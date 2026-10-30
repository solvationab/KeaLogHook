#pragma once

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace ip_audit {

// Order here is the order used by the record builder and the default JSON output.
inline const std::vector<std::string>& knownFieldNames() {
    static const std::vector<std::string> names = {
        "timestamp",     "event",           "ip-address",     "hw-address",
        "client-id",     "hostname",        "subnet-id",      "valid-lifetime",
        "lease-expires", "message-type",    "transaction-id", "interface",
        "giaddr",        "relay-address",   "circuit-id",     "circuit-id-text",
        "remote-id",     "remote-id-text",  "subscriber-id",  "subscriber-id-text",
        "link-selection", "relay-suboptions", "address-family", "lease-type",
        "iaid", "duid", "prefix-length", "relay-interface-id",
        "relay-interface-id-text", "relay-link-address"};
    return names;
}

inline const std::vector<std::string>& knownEventNames() {
    static const std::vector<std::string> names = {
        "lease-assign", "lease-renew", "lease-release", "lease-decline", "lease-expire"};
    return names;
}

class AuditRecord {
public:
    struct Field {
        std::string name;
        std::string value;
        bool numeric;
    };

    void set(std::string name, std::string value) {
        fields_.push_back({std::move(name), std::move(value), false});
    }

    void setNumber(std::string name, int64_t value) {
        fields_.push_back({std::move(name), std::to_string(value), true});
    }

    void setEmptyNumber(std::string name) {
        fields_.push_back({std::move(name), "", true});
    }

    const Field* find(const std::string& name) const {
        for (const auto& f : fields_) {
            if (f.name == name) {
                return &f;
            }
        }
        return nullptr;
    }

    const std::vector<Field>& fields() const { return fields_; }

private:
    std::vector<Field> fields_;
};

}
