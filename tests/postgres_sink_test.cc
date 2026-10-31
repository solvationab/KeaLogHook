#include "config_util.h"
#include "sink_factory.h"
#include "test_util.h"

#include <libpq-fe.h>

#include <array>
#include <cstdlib>
#include <memory>
#include <string>

using namespace ip_audit;
using ip_audit_test::json;

namespace {

class TestConnection {
public:
    explicit TestConnection(const char* connectionString) : connection_(PQconnectdb(connectionString)) {
        if (!connection_ || PQstatus(connection_) != CONNECTION_OK) {
            const std::string error = connection_ ? PQerrorMessage(connection_) : "out of memory";
            if (connection_) {
                PQfinish(connection_);
                connection_ = nullptr;
            }
            throw std::runtime_error("test PostgreSQL connection failed: " + error);
        }
    }

    ~TestConnection() { PQfinish(connection_); }

    PGresult* query(const char* sql) {
        PGresult* result = PQexec(connection_, sql);
        if (!result) {
            ADD_FAILURE() << PQerrorMessage(connection_);
            return nullptr;
        }
        EXPECT_TRUE(PQresultStatus(result) == PGRES_COMMAND_OK ||
                PQresultStatus(result) == PGRES_TUPLES_OK)
            << PQerrorMessage(connection_);
        return result;
    }

    PGresult* queryParams(const char* sql, const std::array<const char*, 1>& params) {
        PGresult* result = PQexecParams(connection_, sql, 1, nullptr, params.data(), nullptr, nullptr,
                                        0);
        EXPECT_EQ(PGRES_TUPLES_OK, PQresultStatus(result)) << PQerrorMessage(connection_);
        return result;
    }

private:
    PGconn* connection_;
};

AuditRecord record(const std::string& event, const std::string& timestamp,
                   const std::string& expiration, const std::string& clientId) {
    AuditRecord result;
    result.set("timestamp", timestamp);
    result.set("event", event);
    result.set("ip-address", "192.0.2.15");
    result.set("lease-expires", expiration);
    result.set("address-family", "IPv4");
    result.set("lease-type", "");
    result.set("client-id", clientId);
    result.set("hw-address", "aa:bb:cc:dd:ee:ff");
    result.set("duid", "");
    return result;
}

}

TEST(PostgresSink, MaintainsLeaseIntervalsAndStoresEveryEvent) {
    const char* connectionString = std::getenv("IP_AUDIT_TEST_DATABASE");
    if (!connectionString || !*connectionString) {
        GTEST_SKIP() << "IP_AUDIT_TEST_DATABASE is not configured";
    }

    TestConnection database(connectionString);
    auto sink = SinkFactory().create(json(
        std::string(R"({"type":"postgres","connection-string":")") + connectionString + "\"}"));
    PGresult* reset = database.query("TRUNCATE ip_audit_events, ip_audit_leases RESTART IDENTITY");
    PQclear(reset);

    sink->write(record("lease-assign", "2025-01-01T00:00:00Z", "2025-01-01T10:00:00Z", "client-a"));
    sink->write(record("lease-renew", "2025-01-01T01:00:00Z", "2025-01-01T20:00:00Z", "client-a"));
    sink->write(record("lease-assign", "2025-01-01T02:00:00Z", "2025-01-01T12:00:00Z", "client-b"));
    sink->write(record("lease-release", "2025-01-01T03:00:00Z", "2025-01-01T12:00:00Z", "client-a"));

    PGresult* rows = database.query(
        "SELECT client_id, start = '2025-01-01T00:00:00Z'::timestamptz, "
        "CASE WHEN client_id = 'client-a' THEN \"end\" = '2025-01-01T02:00:00Z'::timestamptz "
        "ELSE \"end\" > '2025-01-01T03:30:00Z'::timestamptz END "
        "FROM ip_audit_leases ORDER BY start");
    ASSERT_EQ(2, PQntuples(rows));
    EXPECT_EQ("client-a", std::string(PQgetvalue(rows, 0, 0)));
    EXPECT_EQ("t", std::string(PQgetvalue(rows, 0, 1)));
    EXPECT_EQ("t", std::string(PQgetvalue(rows, 0, 2)));
    EXPECT_EQ("client-b", std::string(PQgetvalue(rows, 1, 0)));
    EXPECT_EQ("t", std::string(PQgetvalue(rows, 1, 2)));
    PQclear(rows);

    PGresult* eventCount = database.query("SELECT count(*) FROM ip_audit_events");
    ASSERT_EQ(1, PQntuples(eventCount));
    EXPECT_EQ("4", std::string(PQgetvalue(eventCount, 0, 0)));
    PQclear(eventCount);

    const char* lookupIp = "192.0.2.15";
    PGresult* lookup = database.queryParams(
        "SELECT client_id FROM ip_audit_leases WHERE ip = $1::inet "
        "AND start <= '2025-01-01T03:30:00Z'::timestamptz "
        "AND \"end\" > '2025-01-01T03:30:00Z'::timestamptz",
        {lookupIp});
    ASSERT_EQ(1, PQntuples(lookup));
    EXPECT_EQ("client-b", std::string(PQgetvalue(lookup, 0, 0)));
    PQclear(lookup);
}

TEST(PostgresSink, RejectsInvalidConfiguration) {
    EXPECT_THROW(SinkFactory().create(json(R"({"type":"postgres"})")), ConfigError);
    EXPECT_THROW(SinkFactory().create(json(
                     R"({"type":"postgres","connection-string":""})")), ConfigError);
    EXPECT_THROW(SinkFactory().create(json(R"({"type":"postgres","connection-string":"unused","format":"template"})")), ConfigError);
    EXPECT_THROW(SinkFactory().create(json(
                     R"({"type":"postgres","connection-string":"unused","unknown":true})")),
                 ConfigError);
}