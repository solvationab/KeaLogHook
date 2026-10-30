#pragma once

#include <cc/data.h>

#include <cstdint>
#include <set>
#include <stdexcept>
#include <string>
#include <vector>

namespace ip_audit {

class ConfigError : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

std::string requireString(const isc::data::ConstElementPtr& map, const std::string& key);
std::string optString(const isc::data::ConstElementPtr& map, const std::string& key,
                      const std::string& def);
int64_t optInt(const isc::data::ConstElementPtr& map, const std::string& key, int64_t def,
               int64_t min, int64_t max);
bool optBool(const isc::data::ConstElementPtr& map, const std::string& key, bool def);
std::vector<std::string> optStringList(const isc::data::ConstElementPtr& map,
                                       const std::string& key);
void rejectUnknownKeys(const isc::data::ConstElementPtr& map,
                       const std::set<std::string>& allowed);

}
