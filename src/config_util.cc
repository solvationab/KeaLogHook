#include "config_util.h"

using isc::data::ConstElementPtr;
using isc::data::Element;

namespace ip_audit {

namespace {

ConstElementPtr lookup(const ConstElementPtr& map, const std::string& key) {
    if (!map || map->getType() != Element::map) {
        throw ConfigError("expected a JSON object");
    }
    return map->get(key);
}

}

std::string requireString(const ConstElementPtr& map, const std::string& key) {
    ConstElementPtr v = lookup(map, key);
    if (!v) {
        throw ConfigError("missing required parameter '" + key + "'");
    }
    if (v->getType() != Element::string) {
        throw ConfigError("parameter '" + key + "' must be a string");
    }
    return v->stringValue();
}

std::string optString(const ConstElementPtr& map, const std::string& key, const std::string& def) {
    return lookup(map, key) ? requireString(map, key) : def;
}

int64_t optInt(const ConstElementPtr& map, const std::string& key, int64_t def, int64_t min,
               int64_t max) {
    ConstElementPtr v = lookup(map, key);
    if (!v) {
        return def;
    }
    if (v->getType() != Element::integer) {
        throw ConfigError("parameter '" + key + "' must be an integer");
    }
    int64_t n = v->intValue();
    if (n < min || n > max) {
        throw ConfigError("parameter '" + key + "' must be between " + std::to_string(min) +
                          " and " + std::to_string(max));
    }
    return n;
}

bool optBool(const ConstElementPtr& map, const std::string& key, bool def) {
    ConstElementPtr v = lookup(map, key);
    if (!v) {
        return def;
    }
    if (v->getType() != Element::boolean) {
        throw ConfigError("parameter '" + key + "' must be a boolean");
    }
    return v->boolValue();
}

std::vector<std::string> optStringList(const ConstElementPtr& map, const std::string& key) {
    std::vector<std::string> out;
    ConstElementPtr v = lookup(map, key);
    if (!v) {
        return out;
    }
    if (v->getType() != Element::list) {
        throw ConfigError("parameter '" + key + "' must be a list of strings");
    }
    for (const auto& item : v->listValue()) {
        if (item->getType() != Element::string) {
            throw ConfigError("parameter '" + key + "' must be a list of strings");
        }
        out.push_back(item->stringValue());
    }
    return out;
}

void rejectUnknownKeys(const ConstElementPtr& map, const std::set<std::string>& allowed) {
    if (!map || map->getType() != Element::map) {
        throw ConfigError("expected a JSON object");
    }
    for (const auto& kv : map->mapValue()) {
        if (allowed.count(kv.first) == 0) {
            throw ConfigError("unknown parameter '" + kv.first + "'");
        }
    }
}

}
