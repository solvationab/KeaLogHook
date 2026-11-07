# Record compatibility policy

The hook currently emits `schema-version: "1.0.0"`. The
[published JSON Schema](../audit-record.schema.json) describes default all-fields JSON output
for that exact version. It is intentionally strict: unknown properties are rejected and
the version and event list are pinned. Use it for producer conformance tests and the
provided fixtures, not as a promise that an old strict validator accepts future releases.

## Version handling

The [field reference](../fields.md) defines semantic versioning: additive fields increment
the minor version, incompatible changes increment the major, and structural clarifications
increment the patch. Topic/framing settings are configuration, not encoded by this version.
Check both configuration and payload version when onboarding a publisher.

A production consumer should choose and document one of these policies:

- **Exact validation:** require the precise schema shipped with the producer release. Upgrade
  the schema and consumer together. The example listener's `--strict-schema` uses this policy.
- **Compatible reading:** require the core fields and supported major version, validate known
  field types, and preserve unknown properties without assigning meaning to them. The reference
  listener accepts `1.x.y` this way; it derives a local reader schema from the published schema
  without changing the producer schema.

The compatible example accepts unknown non-empty event names so it can retain and display
them. This is not permission to map them to `lease-assign` or another known event. A
stateful application should quarantine unknown event types or retain them for later handling,
emit a metric, and avoid changing lease state until their semantics are understood. Likewise,
new values in known constrained fields may still be rejected by an older reader; compatibility
is a deliberate policy, not a blanket guarantee for every future change.

Unsupported major versions, missing versions and malformed versions should be rejected or
quarantined, not guessed. Log rejection reasons without copying personal record contents into
unrestricted error logs. Maintain accepted/rejected/unknown-event counters and alert on changes
after a hook upgrade. Pin the producer schema from the same release when strict validation is
required; the release documentation archive contains it alongside these examples.

## Required, optional and projected fields

The default schema requires `timestamp`, `event`, `schema-version` and `ip-address`.
Other fields can be absent: no relay packet is available for expiry events, DHCPv4 and DHCPv6
carry different identity fields, and values can be empty. Do not use missing relay metadata
as proof that a subscriber's identity changed. With `include-empty`, numeric absence is `null`
and text absence is `""`, not the same thing as a numeric zero.

Custom `format.fields` selections may omit required properties; they are intentional
projections, not necessarily corrupted default records. Agree a projection-specific schema
and required business fields with the publisher. The reference listener rejects projections
missing the four core fields. Retain these fields, plus `server`, `address-family` and the
identity/expiry fields your application needs, in an integration configuration. Arbitrary
templates require their own parser and cannot be validated as audit JSON.

## Application modeling

Parse IP addresses and timestamps with standard libraries. Preserve the original JSON for
investigation, but compare UTC instants rather than timestamp text. Keep address family,
lease type and prefix length when modeling DHCPv6: an IA_PD address is a network address,
not a single host allocation. IAID must be interpreted with DUID and lease type, not alone.

Use the binary identity fields for exact matching. Text companions exist for display and may
be absent or contain literal escaped bytes. MAC addresses are not universally available,
and an IP address alone does not identify a subscriber or publisher. Consult
[Events and fields](../fields.md) for the event-specific semantics and
[Recovery](recovery.md) before using this stream as a source of current state.