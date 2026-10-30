#include "formatter.h"

#include "config_util.h"

#include <algorithm>
#include <cstdio>

using isc::data::ConstElementPtr;
using isc::data::Element;

namespace ip_audit {

namespace {

bool isKnownField(const std::string& name) {
    const auto& known = knownFieldNames();
    return std::find(known.begin(), known.end(), name) != known.end();
}

void appendJsonString(std::string& out, const std::string& s) {
    out += '"';
    for (unsigned char c : s) {
        switch (c) {
        case '"':
            out += "\\\"";
            break;
        case '\\':
            out += "\\\\";
            break;
        default:
            if (c < 0x20) {
                char buf[8];
                std::snprintf(buf, sizeof(buf), "\\u%04x", c);
                out += buf;
            } else {
                out += static_cast<char>(c);
            }
        }
    }
    out += '"';
}

class JsonFormatter : public Formatter {
public:
    JsonFormatter(std::vector<std::string> fields, bool includeEmpty)
        : fields_(std::move(fields)), includeEmpty_(includeEmpty) {}

    std::string format(const AuditRecord& record) const override {
        std::string out = "{";
        bool first = true;
        if (fields_.empty()) {
            for (const auto& f : record.fields()) {
                append(out, first, f);
            }
        } else {
            for (const auto& name : fields_) {
                if (const auto* f = record.find(name)) {
                    append(out, first, *f);
                }
            }
        }
        out += '}';
        return out;
    }

private:
    void append(std::string& out, bool& first, const AuditRecord::Field& f) const {
        if (f.value.empty() && !includeEmpty_) {
            return;
        }
        if (!first) {
            out += ',';
        }
        first = false;
        appendJsonString(out, f.name);
        out += ':';
        if (f.numeric) {
            out += f.value.empty() ? "null" : f.value;
        } else {
            appendJsonString(out, f.value);
        }
    }

    std::vector<std::string> fields_;
    bool includeEmpty_;
};

class TemplateFormatter : public Formatter {
public:
    explicit TemplateFormatter(const std::string& text) : template_(text) {}

    std::string format(const AuditRecord& record) const override {
        return template_.expand(record);
    }

private:
    Template template_;
};

}

Template::Template(const std::string& text) {
    std::string literal;
    size_t pos = 0;
    while (pos < text.size()) {
        size_t start = text.find("%{", pos);
        if (start == std::string::npos) {
            literal.append(text, pos, std::string::npos);
            break;
        }
        size_t end = text.find('}', start + 2);
        if (end == std::string::npos) {
            throw ConfigError("unterminated placeholder in template '" + text + "'");
        }
        std::string name = text.substr(start + 2, end - start - 2);
        if (!isKnownField(name)) {
            throw ConfigError("unknown field '" + name + "' in template '" + text + "'");
        }
        literal.append(text, pos, start - pos);
        if (!literal.empty()) {
            segments_.push_back({false, literal});
            literal.clear();
        }
        segments_.push_back({true, name});
        pos = end + 1;
    }
    if (!literal.empty()) {
        segments_.push_back({false, literal});
    }
}

std::string Template::expand(const AuditRecord& record) const {
    std::string out;
    for (const auto& seg : segments_) {
        if (!seg.isField) {
            out += seg.text;
        } else if (const auto* f = record.find(seg.text)) {
            out += f->value;
        }
    }
    return out;
}

std::unique_ptr<Formatter> createFormatter(const ConstElementPtr& cfg) {
    std::string type = "json";
    ConstElementPtr map;
    if (cfg) {
        if (cfg->getType() == Element::string) {
            type = cfg->stringValue();
        } else {
            map = cfg;
            type = optString(map, "type", "json");
        }
    }

    if (type == "json") {
        std::vector<std::string> fields;
        bool includeEmpty = false;
        if (map) {
            rejectUnknownKeys(map, {"type", "fields", "include-empty"});
            fields = optStringList(map, "fields");
            includeEmpty = optBool(map, "include-empty", false);
        }
        for (const auto& name : fields) {
            if (!isKnownField(name)) {
                throw ConfigError("unknown field '" + name + "' in format");
            }
        }
        return std::make_unique<JsonFormatter>(std::move(fields), includeEmpty);
    }

    if (type == "template") {
        if (!map) {
            throw ConfigError("format 'template' requires an object with a 'template' parameter");
        }
        rejectUnknownKeys(map, {"type", "template"});
        return std::make_unique<TemplateFormatter>(requireString(map, "template"));
    }

    throw ConfigError("unknown format type '" + type + "' (expected 'json' or 'template')");
}

}
