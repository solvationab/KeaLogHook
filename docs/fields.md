# Events and fields

## Events

| Event | Emitted when |
|-------|--------------|
| `lease-assign` | A lease was committed for a client that did not have one (DHCPACK, or DHCPDISCOVER with rapid commit). |
| `lease-renew` | An existing lease was renewed. |
| `lease-release` | The client released its lease (DHCPRELEASE). |
| `lease-decline` | The client declined the address (DHCPDECLINE). |
| `lease-expire` | The server reclaimed an expired lease. No relay information is available. |

A sink can subscribe to a subset with the `events` parameter.

## Fields

Fields are present in every record in this order. A field that has no value is empty and
is omitted from JSON output unless `include-empty` is set.

| Field | Type | Description |
|-------|------|-------------|
| `timestamp` | string | Time of the event, UTC, ISO 8601 with milliseconds (`2026-10-30T12:00:00.123Z`). |
| `event` | string | One of the events above. |
| `ip-address` | string | The leased IPv4 address. |
| `hw-address` | string | Client MAC address, lowercase hex with colons. |
| `client-id` | string | DHCP client identifier (option 61) as hex with colons. |
| `hostname` | string | Hostname stored with the lease. Non-printable characters are replaced by `?`. |
| `subnet-id` | number | Kea subnet id of the lease. |
| `valid-lifetime` | number | Lease lifetime in seconds. |
| `lease-expires` | string | Lease expiry time, UTC, ISO 8601. |
| `message-type` | string | DHCP message that triggered the event, e.g. `DHCPREQUEST`. |
| `transaction-id` | string | DHCP `xid` as a decimal number. |
| `interface` | string | Server interface that received the packet. |
| `giaddr` | string | Relay agent address from the packet header. |
| `relay-address` | string | Source IP of the packet (the relay when relayed, otherwise the client). |
| `circuit-id` | string | Option 82 sub-option 1 (Agent Circuit ID) as lowercase hex without separators. |
| `circuit-id-text` | string | Same value as text, only if every byte is printable ASCII; otherwise empty. |
| `remote-id` | string | Option 82 sub-option 2 (Agent Remote ID), hex. |
| `remote-id-text` | string | Printable-ASCII form of `remote-id`, or empty. |
| `subscriber-id` | string | Option 82 sub-option 6 (Subscriber ID), hex. |
| `subscriber-id-text` | string | Printable-ASCII form of `subscriber-id`, or empty. |
| `link-selection` | string | Option 82 sub-option 5 as a dotted IPv4 address. |
| `relay-suboptions` | string | All option 82 sub-options as `code=hex` pairs separated by commas, e.g. `1=0004000a0001,2=0a1b2c3d4e5f`. Useful for vendor-specific sub-options not covered above. |

## Which fields identify a subscriber?

An ISP usually correlates `ip-address` and the time range
(`timestamp` ... `lease-expires`, or the matching `lease-release`) with `circuit-id` and/or
`remote-id` set by the access equipment, plus `hw-address` as a fallback. Which of these
are present depends on how the relay agent / DSLAM / OLT is configured.
