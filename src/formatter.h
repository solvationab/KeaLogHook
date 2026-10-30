#pragma once

#include "audit_record.h"

#include <cc/data.h>

#include <memory>
#include <string>
#include <vector>

namespace ip_audit {

// Text with %{field} placeholders. Validated against the known field names on construction.
class Template {
public:
    explicit Template(const std::string& text);
    std::string expand(const AuditRecord& record) const;

private:
    struct Segment {
        bool isField;
        std::string text;
    };
    std::vector<Segment> segments_;
};

class Formatter {
public:
    virtual ~Formatter() = default;
    virtual std::string format(const AuditRecord& record) const = 0;
};

// cfg is the sink's "format" parameter: absent (JSON), a string ("json"), or an object
// {"type": "json", "fields": [...], "include-empty": false} /
// {"type": "template", "template": "%{timestamp} %{ip-address} ..."}.
std::unique_ptr<Formatter> createFormatter(const isc::data::ConstElementPtr& cfg);

}
