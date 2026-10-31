#include "postgres_sink.h"

#include "config_util.h"
#include "formatter.h"
#include "sink_factory.h"

#include <libpq-fe.h>

#include <array>
#include <mutex>
#include <stdexcept>
#include <string>
#include <vector>

using isc::data::ConstElementPtr;

namespace ip_audit {

namespace {

class PgResult {
public:
    explicit PgResult(PGresult* result) : result_(result) {}
    ~PgResult() {
        if (result_) {
            PQclear(result_);
        }
    }
    PgResult(const PgResult&) = delete;
    PgResult& operator=(const PgResult&) = delete;

    PGresult* get() const { return result_; }

private:
    PGresult* result_;
};

class PostgresSink : public Sink {
public:
    PostgresSink(std::string connectionString, std::unique_ptr<Formatter> formatter)
        : connectionString_(std::move(connectionString)), formatter_(std::move(formatter)) {
        connect();
        try {
            execute("CREATE TABLE IF NOT EXISTS ip_audit_events ("
                    "event_id bigserial PRIMARY KEY,"
                    "timestamp timestamptz NOT NULL,"
                    "event text NOT NULL,"
                    "ip inet,"
                    "record jsonb NOT NULL)");
            execute("CREATE TABLE IF NOT EXISTS ip_audit_leases ("
                    "lease_id bigserial PRIMARY KEY,"
                    "ip inet NOT NULL,"
                    "start timestamptz NOT NULL,"
                    "\"end\" timestamptz NOT NULL,"
                    "address_family text NOT NULL,"
                    "lease_type text NOT NULL,"
                    "client_id text NOT NULL,"
                    "hw_address text NOT NULL,"
                    "duid text NOT NULL,"
                    "record jsonb NOT NULL)");
            execute("CREATE INDEX IF NOT EXISTS ip_audit_leases_ip_start_end_idx "
                    "ON ip_audit_leases (ip, start, \"end\")");
        } catch (...) {
            PQfinish(connection_);
            connection_ = nullptr;
            throw;
        }
    }

    ~PostgresSink() override {
        if (connection_) {
            PQfinish(connection_);
        }
    }

    void write(const AuditRecord& record) override {
        const auto* timestamp = record.find("timestamp");
        const auto* event = record.find("event");
        if (!timestamp || timestamp->value.empty() || !event || event->value.empty()) {
            throw std::runtime_error("PostgreSQL sink requires timestamp and event fields");
        }

        std::lock_guard<std::mutex> lock(mutex_);
        ensureConnected();
        const std::string json = formatter_->format(record);
        const auto* ip = record.find("ip-address");
        const char* ipValue = ip && !ip->value.empty() ? ip->value.c_str() : nullptr;
        const std::array<const char*, 4> eventParams = {
            timestamp->value.c_str(), event->value.c_str(), ipValue, json.c_str()};

        execute("BEGIN");
        try {
            if (ipValue) {
                const std::array<const char*, 1> lockParams = {ipValue};
                executeParams("SELECT pg_advisory_xact_lock(hashtext($1)::bigint)", lockParams);
            }
            executeParams("INSERT INTO ip_audit_events (timestamp, event, ip, record) "
                          "VALUES ($1::timestamptz, $2, $3::inet, $4::jsonb)",
                          eventParams);

            if (ipValue) {
                updateLease(record, timestamp->value, event->value, ipValue, json);
            }
            execute("COMMIT");
        } catch (...) {
            try {
                execute("ROLLBACK");
            } catch (...) {
            }
            throw;
        }
    }

private:
    void connect() {
        connection_ = PQconnectdb(connectionString_.c_str());
        if (!connection_ || PQstatus(connection_) != CONNECTION_OK) {
            const std::string error = connection_ ? PQerrorMessage(connection_) : "out of memory";
            if (connection_) {
                PQfinish(connection_);
                connection_ = nullptr;
            }
            throw std::runtime_error("PostgreSQL connection failed: " + error);
        }
    }

    void ensureConnected() {
        if (connection_ && PQstatus(connection_) == CONNECTION_OK) {
            return;
        }
        if (connection_) {
            PQreset(connection_);
        } else {
            connect();
        }
        if (!connection_ || PQstatus(connection_) != CONNECTION_OK) {
            throw std::runtime_error("PostgreSQL reconnect failed: " +
                                     std::string(connection_ ? PQerrorMessage(connection_)
                                                             : "out of memory"));
        }
    }

    void execute(const char* sql) {
        PgResult result(PQexec(connection_, sql));
        if (!result.get() || PQresultStatus(result.get()) != PGRES_COMMAND_OK) {
            throw std::runtime_error("PostgreSQL query failed: " +
                                     std::string(PQerrorMessage(connection_)));
        }
    }

    template <size_t N>
    void executeParams(const char* sql, const std::array<const char*, N>& params) {
        PgResult result(PQexecParams(connection_, sql, static_cast<int>(N), nullptr,
                                     params.data(), nullptr, nullptr, 0));
        if (!result.get() || (PQresultStatus(result.get()) != PGRES_COMMAND_OK &&
                             PQresultStatus(result.get()) != PGRES_TUPLES_OK)) {
            throw std::runtime_error("PostgreSQL query failed: " +
                                     std::string(PQerrorMessage(connection_)));
        }
    }

    void updateLease(const AuditRecord& record, const std::string& timestamp,
                     const std::string& event, const char* ip, const std::string& json) {
        const auto* family = record.find("address-family");
        const auto* type = record.find("lease-type");
        const auto* expiration = record.find("lease-expires");
        if (!family || !expiration || expiration->value.empty()) {
            return;
        }
        const std::string empty;
        const auto* client = record.find("client-id");
        const auto* hardware = record.find("hw-address");
        const auto* duid = record.find("duid");
        const char* familyValue = family->value.c_str();
        const char* typeValue = type ? type->value.c_str() : empty.c_str();
        const char* clientValue = client ? client->value.c_str() : empty.c_str();
        const char* hardwareValue = hardware ? hardware->value.c_str() : empty.c_str();
        const char* duidValue = duid ? duid->value.c_str() : empty.c_str();

        const std::array<const char*, 4> selectParams = {ip, familyValue, typeValue,
                                                         timestamp.c_str()};
        PgResult selected(PQexecParams(
            connection_,
            "SELECT lease_id, client_id, hw_address, duid FROM ip_audit_leases "
            "WHERE ip = $1::inet AND address_family = $2 AND lease_type = $3 "
            "AND start <= $4::timestamptz AND \"end\" > $4::timestamptz "
            "ORDER BY start DESC LIMIT 1 FOR UPDATE",
            static_cast<int>(selectParams.size()), nullptr, selectParams.data(), nullptr, nullptr,
            0));
        if (!selected.get() || PQresultStatus(selected.get()) != PGRES_TUPLES_OK) {
            throw std::runtime_error("PostgreSQL lease lookup failed: " +
                                     std::string(PQerrorMessage(connection_)));
        }

        const bool found = PQntuples(selected.get()) == 1;
        const bool sameClient =
            found && std::string(PQgetvalue(selected.get(), 0, 1)) == clientValue &&
            std::string(PQgetvalue(selected.get(), 0, 2)) == hardwareValue &&
            std::string(PQgetvalue(selected.get(), 0, 3)) == duidValue;
        if (found) {
            const std::string id = PQgetvalue(selected.get(), 0, 0);
            const bool opening = event == "lease-assign" || event == "lease-renew";
            const std::array<const char*, 3> updateParams = {
                id.c_str(), opening && sameClient ? expiration->value.c_str() : timestamp.c_str(),
                json.c_str()};
            if (opening && sameClient) {
                executeParams("UPDATE ip_audit_leases SET \"end\" = GREATEST(\"end\", "
                              "$2::timestamptz), record = $3::jsonb WHERE lease_id = $1::bigint",
                              updateParams);
                return;
            }
            if (opening) {
                const std::array<const char*, 2> closeParams = {id.c_str(), timestamp.c_str()};
                executeParams("UPDATE ip_audit_leases SET \"end\" = $2::timestamptz "
                              "WHERE lease_id = $1::bigint",
                              closeParams);
            } else if (sameClient) {
                executeParams("UPDATE ip_audit_leases SET \"end\" = $2::timestamptz, "
                              "record = $3::jsonb WHERE lease_id = $1::bigint",
                              updateParams);
                return;
            } else {
                return;
            }
        }

        if (event == "lease-assign" || event == "lease-renew") {
            const std::array<const char*, 9> insertParams = {
                ip, timestamp.c_str(), expiration->value.c_str(), familyValue, typeValue,
                clientValue, hardwareValue, duidValue, json.c_str()};
            executeParams("INSERT INTO ip_audit_leases "
                          "(ip, start, \"end\", address_family, lease_type, client_id, "
                          "hw_address, duid, record) VALUES ($1::inet, $2::timestamptz, "
                          "$3::timestamptz, $4, $5, $6, $7, $8, $9::jsonb)",
                          insertParams);
        }
    }

    std::string connectionString_;
    PGconn* connection_ = nullptr;
    std::unique_ptr<Formatter> formatter_;
    std::mutex mutex_;
};

}

std::unique_ptr<Sink> createPostgresSink(const ConstElementPtr& cfg) {
    rejectUnknownKeys(cfg, SinkFactory::allowedKeys({"connection-string"}));
    std::string connectionString = requireString(cfg, "connection-string");
    if (connectionString.empty()) {
        throw ConfigError("parameter 'connection-string' must not be empty");
    }
    ConstElementPtr format = cfg->get("format");
    std::string formatType = "json";
    if (format && format->getType() == isc::data::Element::string) {
        formatType = format->stringValue();
    } else if (format && format->getType() == isc::data::Element::map) {
        formatType = optString(format, "type", "json");
    }
    if (formatType != "json") {
        throw ConfigError("PostgreSQL sink requires JSON format");
    }
    return std::make_unique<PostgresSink>(std::move(connectionString), createFormatter(format));
}

}