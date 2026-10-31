# Events and fields

## Events

| Event | Emitted when |
|-------|--------------|
| `lease-assign` | A lease was committed for a client that did not have one (DHCPACK or DHCPv6 Reply). |
| `lease-renew` | An existing lease was renewed or rebound. |
| `lease-delete` | An old DHCPv4 lease was deleted when the client's new lease was committed. The record describes the deleted lease, and its timestamp marks the deletion. |
| `lease-release` | The client released its lease. |
| `lease-decline` | The client declined its lease. |
| `lease-expire` | The server reclaimed an expired lease. No packet or relay information is available. |

A sink can subscribe to a subset with the `events` parameter.

## Fields

Fields are present in every record in this order. A field that has no value is empty and
is omitted from JSON output unless `include-empty` is set.

| Field | Type | Description |
|-------|------|-------------|
| `timestamp` | string | Time of the event, UTC, ISO 8601 with milliseconds (`2026-10-30T12:00:00.123Z`). |
| `event` | string | One of the events above. |
| `server` | string | Sanitized local host name, cached by the process to identify which HA server wrote the record. |
| `ip-address` | string | The leased IPv4/IPv6 address, or the network address of a delegated prefix. |
| `hw-address` | string | Client MAC address, lowercase hex with colons. |
| `client-id` | string | DHCPv4 client identifier (option 61) as hex with colons. |
| `hostname` | string | Hostname stored with the lease. Non-printable characters are replaced by `?`. |
| `vendor-class` | string | DHCPv4 option 60 payload as lowercase hex. |
| `vendor-class-text` | string | Printable-ASCII form of option 60, or empty if any byte is not printable. |
| `user-class` | string | DHCPv4 option 77 payload, including its length-prefixed class data, as lowercase hex. |
| `subnet-id` | number | Kea subnet id of the lease. |
| `pop` | string | Sanitized string value of the subnet's `user-context.pop`; absent or non-string values are empty. |
| `site` | string | Sanitized string value of the subnet's `user-context.site`; absent or non-string values are empty. |
| `valid-lifetime` | number | Lease lifetime in seconds. |
| `lease-expires` | string | Lease expiry time, UTC, ISO 8601. |
| `message-type` | string | DHCP message that triggered the event, e.g. `DHCPREQUEST`. |
| `transaction-id` | string | DHCP `xid` as a decimal number. |
| `interface` | string | Server interface that received the packet. |
| `giaddr` | string | Relay agent address from the packet header. |
| `relay-address` | string | Packet source address; for relayed DHCPv6, the outer relay's peer address. |
| `circuit-id` | string | Option 82 sub-option 1 (Agent Circuit ID) as lowercase hex without separators. |
| `circuit-id-text` | string | Same value as text, only if every byte is printable ASCII; otherwise empty. |
| `remote-id` | string | DHCPv4 option 82 sub-option 2 or DHCPv6 relay option 37, hex. |
| `remote-id-text` | string | Printable-ASCII form of `remote-id`, or empty. |
| `subscriber-id` | string | DHCPv4 option 82 sub-option 6 or DHCPv6 relay option 38, hex. |
| `subscriber-id-text` | string | Printable-ASCII form of `subscriber-id`, or empty. |
| `link-selection` | string | Option 82 sub-option 5 as a dotted IPv4 address. |
| `relay-suboptions` | string | DHCPv4 option 82 sub-options as `code=hex` pairs; DHCPv6 relay options as `depth:code=hex` pairs. DHCPv6 depth 0 is the outermost relay. |
| `relay-flags` | string | Option 82 sub-option 10 (Relay Agent Flags) as lowercase hex. |
| `relay-vendor-specific` | string | Option 82 sub-option 9 (Vendor-Specific Information) as lowercase hex. |
| `address-family` | string | `IPv4` or `IPv6`. |
| `lease-type` | string | DHCPv6 IA type: `IA_NA`, `IA_TA` or `IA_PD`; empty for DHCPv4. |
| `iaid` | number | DHCPv6 Identity Association Identifier; empty for DHCPv4. |
| `duid` | string | DHCPv6 client DUID as hex with colons; empty for DHCPv4. |
| `prefix-length` | number | Delegated prefix length for IA_PD; empty for addresses and DHCPv4. |
| `relay-interface-id` | string | DHCPv6 option 18 from the relay closest to the client, as lowercase hex. |
| `relay-interface-id-text` | string | Printable-ASCII form of `relay-interface-id`, or empty. |
| `relay-link-address` | string | Link address from the outermost DHCPv6 relay. |

## Which fields identify a subscriber?

An ISP usually correlates `ip-address` and the time range
(`timestamp` ... `lease-expires`, or the matching `lease-release`) with `circuit-id` and/or
`remote-id` set by the access equipment, plus `hw-address` as a fallback. Which of these
are present depends on how the relay agent / DSLAM / OLT is configured.
