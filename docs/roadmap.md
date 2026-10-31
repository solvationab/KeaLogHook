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
     - [ ] **1.4** Run CI against more Kea versions and distributions, including Ubuntu 26.04.
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
4. **Spool and retry for network sinks.** Write to local disk first and ship from there, so
   a remote outage loses nothing. ZeroMQ PUB is lossy by design, so the file sink should
   remain the authoritative record.

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
11. **Tamper evidence.** Hash chaining or signing of log lines. Document `chattr +a` and
    shipping to write-once storage.
12. **Privacy controls.** Optional field-level pseudonymisation (for example a keyed hash of
    the MAC address) for sinks that feed non-forensic consumers. Relevant under GDPR and
    similar data-protection rules.
13. **ZeroMQ security.** The PUB sink has no authentication or encryption. Add CURVE support
    (server key and a client public-key allow-list), or document an SSH, stunnel or
    WireGuard path.

## Operations

14. **Reopen and control commands.** Register Kea control-channel commands such as
    `ip-audit-reopen` (for logrotate) and `ip-audit-stats`. This removes the current
    limitation that the file sink does not follow external rotation.
15. **Metrics.** Expose counters (records written, failed, dropped, queue depth) through
    Kea's statistics manager so they can be scraped, for example with a Kea Prometheus
    exporter.
16. **Config dry-run.** A small CLI that validates the `parameters` JSON without starting
    Kea, for use in deployment pipelines.
17. **Operations files.** Ship a sample `logrotate` configuration, a `systemd` drop-in and
    examples of log shipping (rsyslog, Filebeat).

## Additional sinks

18. **Database sink.** A PostgreSQL sink with a lease table and an index on
    `(ip, start, end)` answers "who had IP X at time T" directly.
19. **Syslog/journald, Kafka or HTTP sinks.** These suit central log platforms and fit the
    existing `Sink` interface (see [extending.md](extending.md)).

## Query tooling

20. **Lookup CLI.** A tool such as `ip-audit-lookup <ip> <timestamp>` that reads the log
    files and reconstructs the lease timeline, including rotated and compressed files, for
    abuse and legal teams.

## Suggested order

Continue with item 14 (item 1 is largely done). It hardens the core without changing its design.
Then add retention (10), HA identity (8), metrics (15) and a database sink (18).
