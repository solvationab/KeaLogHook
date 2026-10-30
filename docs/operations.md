# Building, operating and limitations

## Building

Requirements: Kea development headers and libraries (`kea-dhcpsrv`, `kea-dhcp++`,
`kea-hooks`, `kea-log`, `kea-util`, `kea-cc`, `kea-exceptions`), `kea-msg-compiler`,
libzmq (found through `pkg-config`), Boost headers, a C++17 compiler, CMake 3.16+.

```sh
cmake -S . -B build -DKEA_PREFIX=/usr
cmake --build build
sudo cmake --install build
```

| CMake variable | Default | Meaning |
|----------------|---------|---------|
| `KEA_PREFIX` | `/usr` | Where Kea is installed. |
| `KEA_HOOKS_DIR` | `${KEA_PREFIX}/lib/kea/hooks` | Install location of `libdhcp_ip_audit.so`. |

The hook must be built against the same Kea version that loads it. Rebuild it when Kea is
upgraded.

During the build, `src/ip_audit_messages.mes` is compiled into the logging headers by
`kea-msg-compiler`.

## Logging

The hook logs through Kea's logging framework with the logger name `ip-audit-hooks`
(so it is covered by the `kea-dhcp4` logger configuration). Messages:

| Message | Meaning |
|---------|---------|
| `IP_AUDIT_LOAD_OK` | Library loaded; shows the number of sinks. |
| `IP_AUDIT_LOAD_FAILED` | Invalid configuration or a sink could not be created. Kea will not load the library. |
| `IP_AUDIT_SINK_CREATED` | A sink was created. |
| `IP_AUDIT_SINK_WRITE_FAILED` | A sink failed to store a record. |
| `IP_AUDIT_CALLOUT_FAILED` | A record could not be built. |
| `IP_AUDIT_UNLOAD` | Library unloaded. |

## Consuming ZeroMQ records

A minimal Python subscriber for the default multipart configuration:

```python
import zmq

ctx = zmq.Context()
sock = ctx.socket(zmq.SUB)
sock.connect("tcp://127.0.0.1:5556")
sock.setsockopt_string(zmq.SUBSCRIBE, "ip-audit.")  # topic prefix; "" for everything

while True:
    topic, payload = sock.recv_multipart()
    print(topic.decode(), payload.decode())
```

## Log file rotation

Use the built-in rotation (`max-size`, `max-files`). The file sink keeps its file open and
does not reopen it on a signal, so rotating it externally by renaming the file leaves the
hook writing to the renamed file. If you must use an external tool, use a
copy-and-truncate strategy (for example logrotate `copytruncate`).

## Privacy and security

Audit records are personal data. Restrict access accordingly:

- The file sink creates files with mode `0640` by default; change `file-mode` if needed.
- The ZeroMQ sink has no authentication or encryption. Bind to loopback or a `ipc://`
  endpoint, or place a proxy or tunnel in front of it, rather than exposing it to a network.
- Define a retention period and delete or archive old files accordingly.
- Hostnames and other client-controlled text are sanitised so that a client cannot inject
  control characters or fake log lines.

## Limitations

- **Delivery is best effort for ZeroMQ.** A PUB socket drops messages when there are no
  subscribers (they join later) or when a subscriber is slower than `send-hwm` allows. Use
  the file sink for the authoritative record and ZeroMQ for real-time consumers.
- **Expiry events lack relay data** because no client packet is involved.
- **Renewal detection relies on Kea sharing the callout context** between `lease4_renew`
  and `leases4_committed` for the same packet. If this does not hold in your Kea version,
  renewals are logged as `lease-assign`.
- **DHCPv4 only.** DHCPv6 is not supported.
- **POSIX only.** The file sink uses POSIX system calls.
- **Configuration changes** take effect when Kea reloads its configuration, which unloads
  and reloads the library and its sinks.
