# Roadmap: suggested improvements for ISP use

Suggestions for hardening the hook and making it fit an ISP's traceability and compliance
needs. None of these are implemented yet. They are grouped by theme; the suggested order
of implementation is at the end.

## Reliability and performance

1. **Tests and CI.** There are no unit or integration tests yet. Start with the formatters,
   the `Template` placeholder engine, config validation and the record builder. Add an
   integration test that runs a real Kea with a simulated relay (for example `perfdhcp` or
   a small packet generator). The code has not been built against a real Kea yet, so this
   is the most important item.
2. **Non-blocking delivery.** `Sink::write()` currently runs on the DHCP path, so a slow
   disk, `fsync: true` or a blocked network sink slows lease handling. Put a bounded
   in-memory queue and a writer thread between `AuditManager` and the sinks, and count
   records dropped when the queue overflows.
3. **Renewal noise reduction.** After an outage, tens of thousands of clients renew at
   once and every renewal produces a record. Add per-sink options such as "log renewals
   only when the MAC, option 82 or IP changed", or a rate limit. This needs a small
   in-memory cache keyed by IP address.
4. **Spool and retry for network sinks.** Write to local disk first and ship from there, so
   a remote outage loses nothing. ZeroMQ PUB is lossy by design, so the file sink should
   remain the authoritative record.

## Traceability coverage

5. **DHCPv6 and prefix delegation.** Dual-stack ISPs also need to know who held which IPv6
   address or delegated prefix (IA_NA, IA_PD), with relay data such as interface-id
   (option 18) and remote-id (option 37). This is the largest functional gap and needs
   hooks for `kea-dhcp6`.
6. **Lease-delete event.** Kea's `deleted_leases4` argument of `leases4_committed` shows
   when a client's old address is dropped because it received a new one. That gives a clean
   end time for the old assignment.
7. **More fields.** Vendor class (option 60), user class (option 77), the relay-agent
   flags and vendor-specific sub-options of option 82, and subnet metadata taken from
   Kea's `user-context` (for example POP or site name).
8. **Server identity for HA.** Add a `server` field (hostname or server-id). With Kea HA,
   two nodes write separate logs and you need to know which node produced each record when
   merging them.
9. **Schema version.** Add a `schema-version` field and a documented JSON schema so
   downstream consumers can rely on the format.

## Compliance and security

10. **Retention.** Retention in days with automatic deletion, time-based rotation (daily or
    hourly) in addition to size-based rotation, and compression of rotated files.
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

Start with items 1, 2, 3, 6 and 14. They harden the core without changing its design.
Then add retention (10), HA identity (8) and metrics (15), followed by DHCPv6 (5) and a
database sink (18).
