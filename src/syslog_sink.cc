#include "syslog_sink.h"

#include "config_util.h"
#include "formatter.h"
#include "sink_factory.h"

#include <syslog.h>

#include <map>
#include <memory>
#include <stdexcept>
#include <string>

using isc::data::ConstElementPtr;

namespace ip_audit {

namespace {

const std::map<std::string, int>& facilities() {
    static const std::map<std::string, int> values = {
        {"auth", LOG_AUTH},       {"authpriv", LOG_AUTHPRIV}, {"cron", LOG_CRON},
        {"daemon", LOG_DAEMON},   {"ftp", LOG_FTP},           {"kern", LOG_KERN},
        {"local0", LOG_LOCAL0},   {"local1", LOG_LOCAL1},     {"local2", LOG_LOCAL2},
        {"local3", LOG_LOCAL3},   {"local4", LOG_LOCAL4},     {"local5", LOG_LOCAL5},
        {"local6", LOG_LOCAL6},   {"local7", LOG_LOCAL7},     {"lpr", LOG_LPR},
        {"mail", LOG_MAIL},       {"news", LOG_NEWS},         {"syslog", LOG_SYSLOG},
        {"user", LOG_USER},       {"uucp", LOG_UUCP},
    };
    return values;
}

const std::map<std::string, int>& severities() {
    static const std::map<std::string, int> values = {
        {"emerg", LOG_EMERG},     {"alert", LOG_ALERT}, {"crit", LOG_CRIT},
        {"err", LOG_ERR},         {"warning", LOG_WARNING}, {"notice", LOG_NOTICE},
        {"info", LOG_INFO},       {"debug", LOG_DEBUG},
    };
    return values;
}

int requireChoice(const std::map<std::string, int>& choices, const std::string& value,
                  const std::string& parameter) {
    const auto found = choices.find(value);
    if (found == choices.end()) {
        std::string expected;
        for (const auto& choice : choices) {
            if (!expected.empty()) {
                expected += ", ";
            }
            expected += "'" + choice.first + "'";
        }
        throw ConfigError("parameter '" + parameter + "' must be one of: " + expected);
    }
    return found->second;
}

std::string singleLine(std::string text) {
    for (char& character : text) {
        const unsigned char value = static_cast<unsigned char>(character);
        if (value == '\n' || value == '\r' || value == '\0') {
            character = ' ';
        } else if (value < 0x20 && value != '\t') {
            character = '?';
        }
    }
    return text;
}

class SyslogSink : public Sink {
public:
    SyslogSink(std::string name, int facility, int severity,
               std::unique_ptr<Formatter> formatter)
        : name_(std::move(name)), facility_(facility), severity_(severity),
          formatter_(std::move(formatter)) {}

    void write(const AuditRecord& record) override {
        const std::string message = singleLine(formatter_->format(record));
        ::syslog(facility_ | severity_, "%s: %s", name_.c_str(), message.c_str());
    }

private:
    std::string name_;
    int facility_;
    int severity_;
    std::unique_ptr<Formatter> formatter_;
};

}

std::unique_ptr<Sink> createSyslogSink(const ConstElementPtr& cfg) {
    rejectUnknownKeys(cfg, SinkFactory::allowedKeys({"facility", "severity"}));
    const std::string facilityName = optString(cfg, "facility", "daemon");
    const std::string severityName = optString(cfg, "severity", "info");
    const int facility = requireChoice(facilities(), facilityName, "facility");
    const int severity = requireChoice(severities(), severityName, "severity");
    const std::string name = optString(cfg, "name", "kea-ip-audit");
    if (name.empty()) {
        throw ConfigError("parameter 'name' must not be empty");
    }
    return std::make_unique<SyslogSink>(name, facility, severity,
                                        createFormatter(cfg->get("format")));
}

}
