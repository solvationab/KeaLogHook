# Roadmap: suggested improvements for ISP use

Suggestions for hardening the hook and making it fit an ISP's traceability and compliance
needs. Items are grouped by theme; subtasks use parent.subtask identifiers. Completed work is
marked `[x]`, and planned work is marked `[ ]`. The suggested order of implementation is at
the end.

## Reliability and performance

1. **Tests and CI.**
     - [x] **1.1** Unit tests for config validation, the formatters, the `Template` engine, the record
         builder, the sinks and `AuditManager`.
     - [x] **1.2** Integration test with a real Kea and a simulated relay.
     - [x] **1.3** GitHub Actions workflow that runs both (see [operations.md](operations.md#testing)).
        - [x] **1.4** CI covers Ubuntu 24.04 and 26.04, using each distribution's packaged Kea version.
     - [ ] **1.5** Add sanitizer (ASan/UBSan) and `-Werror` builds.
     - [x] **1.6** Configure CI to build DEB/RPM packages and upload them as artifacts.
     - [ ] **1.7** Add a multi-threaded stress test.
2. **Non-blocking delivery.**
     - [x] **2.1** `AuditManager` sends records to a bounded FIFO queue and one sink worker; callouts
         do not wait for sink writes. `queue-size` defaults to 10,000 (maximum 1,000,000); when
         full, the newest record is dropped and the cumulative count is logged on unload.
         Accepted records are drained during unload. See
         [configuration.md](configuration.md#top-level-parameters).
3. **Renewal noise reduction.**
     - [x] **3.1** Optional per-sink `renewals-on-change` suppresses unchanged renewals by IP,
         client identity and relay metadata. The per-sink cache is bounded to 100,000 IPs.
     - [x] **3.2** Optional per-sink `renewal-rate-limit` caps `lease-renew` records per second;
         `0` disables it. Both settings default to disabled.
4. **Spool and retry for remote sinks.** PostgreSQL and other remote sinks can fail while
    DHCP continues. Add durable local spooling and retry/replay so transient outages do not
    lose records; retain the file sink as the authoritative copy until delivery is confirmed.

## Traceability coverage

5. **DHCPv6 and prefix delegation.**
     - [x] **5.1** DHCPv6 hook module records IA_NA, IA_TA and IA_PD lease events, including DUID/IAID,
         delegated prefix length, relay interface-id and remote-id. A separate library is built
         for `kea-dhcp6`.
6. **Lease-delete event.**
     - [x] **6.1** Emit `lease-delete` for every old lease in `deleted_leases4` at
         `leases4_committed`. The record describes the deleted lease and its timestamp marks
         the end of the old assignment.
7. **More fields.**
    - [x] **7.1** Record DHCPv4 vendor class (option 60) and user class (option 77).
    - [x] **7.2** Expose option-82 relay flags and vendor-specific information as fields.
    - [x] **7.3** Read string `pop` and `site` values from subnet `user-context` for DHCPv4/v6.
8. **Server identity for HA.**
    - [x] **8.1** Include the local server host name in every record to identify its source when merging HA logs.
9. **Schema version.**
    - [x] **9.1** Add the `1.0.0` `schema-version` field to DHCPv4 and DHCPv6 records.
    - [x] **9.2** Publish a JSON Schema for default JSON output and document versioning.

## Compliance and security

10. **Retention.**
    - [x] **10.1** Optional daily/hourly UTC rotation in addition to size-based rotation.
    - [x] **10.2** Optional age-based deletion of numbered rotations.
    - [x] **10.3** Optional gzip compression of numbered rotations.
    - [ ] **10.4** Define PostgreSQL retention and partitioning for event and lease-history
        tables, including archive/export and coordinated cleanup so retained intervals remain
        queryable and old personal data is not kept indefinitely.
11. **Tamper evidence.** Hash chaining or signing of log lines. Document `chattr +a` and
    shipping to write-once storage.
12. **Privacy controls.** Optional field-level pseudonymisation (for example a keyed hash of
    the MAC address) for sinks that feed non-forensic consumers. Relevant under GDPR and
    similar data-protection rules.
13. **ZeroMQ security.** The PUB sink has no authentication or encryption. Add CURVE support
    (server key and a client public-key allow-list), or document an SSH, stunnel or
    WireGuard path.

## Operations

14. **Reopen and control commands.**
    - [x] **14.1** Register `ip-audit-reopen` to reopen file sinks after external rotation.
    - [x] **14.2** Register `ip-audit-stats` for queue and sink write counters.
15. **Metrics.**
    - [x] **15.1** Publish queue depth/capacity, sink count, dropped records, writes and failures through Kea's statistics manager.
    - [x] **15.2** Publish protocol-specific metric names and remove observations on unload.
16. **Config dry-run.** A small CLI that validates the `parameters` JSON without starting
    Kea, for use in deployment pipelines.
17. **Operations files.** Ship a sample `logrotate` configuration, a `systemd` drop-in and
    examples of log shipping (rsyslog, Filebeat).

## Additional sinks

18. **Database sink.** [x] PostgreSQL event and lease-history tables with an index on
    `(ip, start, end)` support direct "who had IP X at time T" lookups. See
    [configuration.md](configuration.md#postgres-sink).
19. **Syslog/journald, Kafka or HTTP sinks.** These suit central log platforms and fit the
    existing `Sink` interface (see [extending.md](extending.md)).

## Query tooling

20. **Lookup CLI.** [x] `ip-audit-lookup <ip> <timestamp> <log>` reconstructs lease intervals
    from JSON logs and numbered/compressed rotations. See
    [operations.md](operations.md#looking-up-lease-history).

## Suggested order

The PostgreSQL sink (18) and lookup CLI (20) are implemented. The remaining work is best
sequenced by risk and operational value:

1. **Bound database growth and define data lifecycle:** retention/partitioning for PostgreSQL
    history (10.4), including how exports and cleanup preserve valid lookups.
2. **Strengthen delivery guarantees:** durable spooling and replay for remote sinks (4), then
    exercise queue and worker concurrency with the stress test (1.7).
3. **Harden build quality:** add sanitizer and `-Werror` CI builds (1.5).
4. **Address compliance controls:** tamper evidence (11), followed by field-level privacy
    controls (12).
5. **Improve deployment operations:** config dry-run (16) and the sample operations files (17).
6. **Extend integrations based on deployment demand:** ZeroMQ security (13) and additional
    sinks (19).
