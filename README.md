# Kea IP Audit Hook

A hook library for the [Kea DHCPv4 server](https://www.isc.org/kea/) that records
**who got which IP address and when**, including the DHCP relay agent information
(option 82) that identifies the subscriber's port or line.

It is intended for ISPs that need to trace an IP address back to a subscriber
(for example for abuse handling or legal data retention requirements).

## What it does

Every time Kea assigns, renews, releases, declines or expires an IPv4 lease, the hook
builds an *audit record* and hands it to one or more configurable **sinks**. A record
contains the IP address, client MAC, client-id, hostname, lease times, relay address,
and all option 82 sub-options (circuit-id, remote-id, subscriber-id, link-selection, ...).

Two sinks are included:

| Sink type | Purpose |
|-----------|---------|
| `file`    | Appends records to a log file, with size-based rotation. |
| `zeromq`  | Publishes records on a ZeroMQ PUB socket for real-time consumers. |

Sinks are pluggable: new ways of storing records can be added without touching the
hook logic (see [docs/extending.md](docs/extending.md)). Everything is controlled from
the hook `parameters` in the Kea configuration; no recompilation is needed to change
what is logged, where, or in which format.

```mermaid
flowchart LR
    K[Kea DHCPv4] -->|hook callouts| C[callouts.cc]
    C --> B[record builder]
    B --> M[AuditManager]
    M -->|event filter| S1[file sink]
    M -->|event filter| S2[zeromq sink]
    S1 --> F[(log file)]
    S2 --> Z[ZeroMQ subscribers]
```

## Quick start

1. Build and install (Linux, requires Kea development files, libzmq and Boost headers):

   ```sh
   cmake -S . -B build -DKEA_PREFIX=/usr
   cmake --build build
   sudo cmake --install build
   ```

   Or build a DEB/RPM package for easy installation on servers (`cd build && cpack -G DEB`,
   see [docs/operations.md](docs/operations.md#building-install-packages)).

2. Add the library to the `Dhcp4` section of `kea-dhcp4.conf`:

   ```json
   "hooks-libraries": [
     {
       "library": "/usr/lib/kea/hooks/libdhcp_ip_audit.so",
       "parameters": {
         "sinks": [
           { "type": "file", "path": "/var/log/kea/ip-audit.log" }
         ]
       }
     }
   ]
   ```

3. Restart or reconfigure Kea. Each lease event now produces one JSON line:

   ```json
   {"timestamp":"2026-10-30T12:00:00.123Z","event":"lease-assign","ip-address":"192.0.2.10","hw-address":"aa:bb:cc:dd:ee:ff","subnet-id":1,"valid-lifetime":3600,"circuit-id":"0004000a0001","remote-id":"0a1b2c3d4e5f","giaddr":"192.0.2.1"}
   ```

A complete example with both sinks is in [examples/kea-dhcp4.conf](examples/kea-dhcp4.conf).

## Documentation

- [docs/architecture.md](docs/architecture.md) - how the hook works internally
- [docs/configuration.md](docs/configuration.md) - every configuration parameter
- [docs/fields.md](docs/fields.md) - the fields and events in an audit record
- [docs/extending.md](docs/extending.md) - adding a new sink
- [docs/operations.md](docs/operations.md) - building, deploying, consuming data, privacy and limitations
- [docs/roadmap.md](docs/roadmap.md) - suggested improvements for ISP use

## Requirements

- Kea DHCPv4 with hooks support (development headers and `kea-msg-compiler`)
- libzmq
- Boost (headers only)
- A C++17 compiler and CMake 3.16+
- Linux or another POSIX system (the file sink uses POSIX I/O)
