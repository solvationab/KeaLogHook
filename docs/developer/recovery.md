# Delivery, recovery and security

## Delivery guarantees

ZeroMQ delivery is best effort. Messages can be lost before a subscriber's connection and
subscription are established, while disconnected, or when a subscriber falls behind the
send high-water mark. Reconnection restores future delivery, not missed history. Raising
high-water marks changes buffering, not durability; unlimited queues risk memory exhaustion.

The hook also has a bounded in-memory queue before sink writes. A full queue drops newer
records; a process crash loses queued records. Sink failures are isolated so DHCP processing
continues. Successful ZeroMQ sends do not acknowledge subscriber receipt or application
commit. Hook write metrics cannot count every PUB/SUB drop or prove stream completeness.

Consumers should keep the socket receive path fast, bound downstream queues, define an
overflow policy, and monitor rejected records, processing lag, queue depth and disconnects.
One owner should use each ZeroMQ socket; move decoded work to other threads rather than
sharing a socket across arbitrary worker threads. Use socket-monitor facilities if connection
status matters; a poll timeout or a lack of lease traffic is not a heartbeat.

## Ordering and repeated records

The hook drains accepted records through one FIFO worker per loaded manager. That is queue
order, not a guaranteed total order of DHCP events by timestamp across concurrent callouts,
DHCPv4/DHCPv6 processes, HA peers, or separate publishers. Received multipart frames remain
together, but do not infer completeness from their arrival order.

There is currently no stable event ID, publisher-instance ID, sequence number, replay cursor,
acknowledgement or snapshot boundary in the wire protocol. `server` identifies a host, not a
particular process lifetime. Timestamps are not unique IDs and may be affected by clock skew.
ZeroMQ is not advertised as an at-least-once stream; application retries, combining multiple
sinks or HA feeds, and replay can nevertheless present repeated or overlapping records.

Make state updates idempotent where possible and retain provenance (source file/database,
publisher endpoint and ingestion time). A fingerprint of a full record can help detect exact
duplicates, but cannot reliably distinguish two genuine identical events or correlate records
whose field projections differ. Do not promise exactly-once processing with the current data.

## Recovery plan

Keep an appropriately protected and retained file sink, PostgreSQL history, or another
durable ingestion path in parallel with ZeroMQ. The file sink is the recommended historical
copy, but it is not immune to queue loss, disk errors, retention expiry or power loss; choose
`fsync` and retention according to your requirements. PostgreSQL writes can also fail and
currently have no durable hook retry spool. Monitor both sources before relying on recovery.

For a stateful consumer:

1. Establish the live subscription and buffer incoming records in a bounded staging area.
2. Read an overlapping historical interval from retained JSON logs/rotations or PostgreSQL
   `ip_audit_events`, including full identity and lease-expiry fields.
3. Reconcile historical and buffered records using source provenance and idempotent updates.
   Treat the handover as approximate: there is no atomic snapshot/live boundary or cursor.
4. Mark state uncertain when gaps or conflicting data cannot be resolved; reconcile against
   Kea's lease database or a separate supported lease-query interface when actual current
   leases are required. This hook does not expose a live lease snapshot API.

Do not use event timestamps as a lossless incremental database cursor: multiple records can
share a timestamp, and clocks or insertion order can differ. Coordinate any database cursor
and export behavior with the database owner. The audit CLI commands can inspect retained
history, but their allocation lists are reconstructed evidence, not live Kea queries.

Per-sink event filters, `renewals-on-change` and `renewal-rate-limit` can intentionally omit
events. Agree those policies before interpreting a missing renewal as an outage or subscriber
departure. A consumer needing precise expiry extensions should retain every renewal or define
another authoritative refresh mechanism. An expiry timestamp is evidence of a lease's validity
at that event, not a guarantee no later renewal occurred.

Test startup races, publisher and listener restarts, slow processing, malformed messages,
unknown schema versions, HA overlap, and recovery-source outages. The
[fixture publisher](integration.md#fixtures-and-consumer-tests) exercises transport/parser
behavior, not durable replay or proof of a complete audit trail.

## Security and privacy

The current sink has no authentication, encryption, or subscriber authorization. Bind to
loopback for local consumers or use a protected IPC path with appropriate filesystem access
controls. For remote use, deploy an authenticated encrypted tunnel or secured proxy and limit
network access; do not expose the raw PUB endpoint to an untrusted network. Topic filters are
not access controls: a subscriber can request every topic.

Treat messages as untrusted input. Bound application payload sizes and work queues, validate
types, and never execute templates or interpret client-controlled text as code. The reference
listener is a small demonstration, not a hardened service with authentication or comprehensive
resource limits. Restrict record storage and error logs: IPs, DUIDs, MACs, relay identifiers,
hostnames and complete JSON envelopes may contain personal data. Apply retention policies to
consumer databases and debugging captures as well as the hook's output.