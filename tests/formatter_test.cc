#include "formatter.h"

#include "config_util.h"
#include "test_util.h"

using namespace ip_audit;
using ip_audit_test::json;

namespace {

AuditRecord sampleRecord() {
    AuditRecord r;
    r.set("timestamp", "2026-01-01T00:00:00.000Z");
    r.set("event", "lease-assign");
    r.set("ip-address", "192.0.2.10");
    r.set("client-id", "");
    r.setNumber("subnet-id", 7);
    r.set("hostname", "host\"1");
    return r;
}

std::string format(const std::string& formatConfig, const AuditRecord& record) {
    return createFormatter(json(formatConfig))->format(record);
}

}

TEST(Template, ExpandsPlaceholders) {
    Template t("%{event} ip=%{ip-address}!");
    EXPECT_EQ("lease-assign ip=192.0.2.10!", t.expand(sampleRecord()));
}

TEST(Template, LiteralTextWithoutPlaceholders) {
    EXPECT_EQ("100% plain } text", Template("100% plain } text").expand(sampleRecord()));
    EXPECT_EQ("", Template("").expand(sampleRecord()));
}

TEST(Template, KnownFieldMissingFromRecordExpandsToEmpty) {
    EXPECT_EQ("giaddr=", Template("giaddr=%{giaddr}").expand(sampleRecord()));
}

TEST(Template, AdjacentPlaceholders) {
    EXPECT_EQ("lease-assign192.0.2.10", Template("%{event}%{ip-address}").expand(sampleRecord()));
}

TEST(Template, RejectsUnknownField) {
    EXPECT_THROW(Template("%{no-such-field}"), ConfigError);
}

TEST(Template, RejectsUnterminatedPlaceholder) {
    EXPECT_THROW(Template("abc %{event"), ConfigError);
}

TEST(JsonFormatter, DefaultSkipsEmptyValuesAndKeepsRecordOrder) {
    auto f = createFormatter(isc::data::ConstElementPtr());
    EXPECT_EQ(R"({"timestamp":"2026-01-01T00:00:00.000Z","event":"lease-assign",)"
              R"("ip-address":"192.0.2.10","subnet-id":7,"hostname":"host\"1"})",
              f->format(sampleRecord()));
}

TEST(JsonFormatter, StringFormatNameSelectsJson) {
    EXPECT_EQ(R"({"timestamp":"2026-01-01T00:00:00.000Z","event":"lease-assign",)"
              R"("ip-address":"192.0.2.10","subnet-id":7,"hostname":"host\"1"})",
              format(R"("json")", sampleRecord()));
}

TEST(JsonFormatter, FieldsSelectAndOrderOutput) {
    EXPECT_EQ(R"({"ip-address":"192.0.2.10","event":"lease-assign"})",
              format(R"({"type":"json","fields":["ip-address","event"]})", sampleRecord()));
}

TEST(JsonFormatter, FieldsMissingFromRecordAreSkipped) {
    EXPECT_EQ(R"({"event":"lease-assign"})",
              format(R"({"fields":["giaddr","event"]})", sampleRecord()));
}

TEST(JsonFormatter, IncludeEmptyKeepsEmptyStrings) {
    EXPECT_EQ(R"({"client-id":"","event":"lease-assign"})",
              format(R"({"fields":["client-id","event"],"include-empty":true})", sampleRecord()));
}

TEST(JsonFormatter, NumbersAreNotQuoted) {
    EXPECT_EQ(R"({"subnet-id":7})", format(R"({"fields":["subnet-id"]})", sampleRecord()));
}

TEST(JsonFormatter, EscapesQuotesBackslashesAndControlCharacters) {
    AuditRecord r;
    r.set("hostname", std::string("a\n\\b\x01"));
    EXPECT_EQ(R"({"hostname":"a\u000a\\b\u0001"})", createFormatter(isc::data::ConstElementPtr())->format(r));
}

TEST(JsonFormatter, EmptyRecordIsEmptyObject) {
    EXPECT_EQ("{}", createFormatter(isc::data::ConstElementPtr())->format(AuditRecord()));
}

TEST(TemplateFormatter, FormatsRecord) {
    EXPECT_EQ("lease-assign 192.0.2.10",
              format(R"({"type":"template","template":"%{event} %{ip-address}"})", sampleRecord()));
}

TEST(CreateFormatter, RejectsInvalidConfigurations) {
    EXPECT_THROW(format(R"("xml")", sampleRecord()), ConfigError);
    EXPECT_THROW(format(R"("template")", sampleRecord()), ConfigError);
    EXPECT_THROW(format(R"({"type":"template"})", sampleRecord()), ConfigError);
    EXPECT_THROW(format(R"({"type":"template","template":"%{nope}"})", sampleRecord()), ConfigError);
    EXPECT_THROW(format(R"({"type":"json","template":"x"})", sampleRecord()), ConfigError);
    EXPECT_THROW(format(R"({"type":"json","fields":["nope"]})", sampleRecord()), ConfigError);
    EXPECT_THROW(format(R"({"type":"json","include-empty":"yes"})", sampleRecord()), ConfigError);
}
