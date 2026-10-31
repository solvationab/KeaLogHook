# Building, operating and limitations

## Building

Requirements: Kea development headers and libraries (`kea-dhcpsrv`, `kea-dhcp++`,
`kea-hooks`, `kea-log`, `kea-stats`, `kea-util`, `kea-cc`, `kea-exceptions`), `kea-msg-compiler`,
libzmq (found through `pkg-config`), libpq, Boost headers, OpenSSL Crypto and zlib development files,
a C++17 compiler, CMake 3.16+.

```sh
cmake -S . -B build -DKEA_PREFIX=/usr
cmake --build build
sudo cmake --install build
```

| CMake variable | Default | Meaning |
|----------------|---------|---------|
| `KEA_PREFIX` | `/usr` | Where Kea is installed. Also the default install prefix. |
| `KEA_HOOKS_DIR` | `<libdir>/kea/hooks` | Hook directory relative to the install prefix. `<libdir>` follows the distribution (`lib64` on RPM systems, `lib/<multiarch>` on Debian). |
| `KEA_IP_AUDIT_VERSION` | `0.1.0` | Numeric `MAJOR.MINOR.PATCH` version used in DEB/RPM package metadata. |
| `PACKAGE_MAINTAINER` | placeholder | Maintainer shown in DEB/RPM metadata. |

The hook must be built against the same Kea version that loads it. Rebuild it when Kea is
upgraded.

## Testing

The unit tests use GoogleTest (`libgtest-dev`; it is downloaded automatically if not
installed) and are built by default. Disable them with `-DIP_AUDIT_BUILD_TESTS=OFF`.

```sh
ctest --test-dir build --output-on-failure
```

They cover config validation, the formatters and the `Template` engine, the record builder
(including IPv4 client classes, option 82, subnet context and DHCPv6 IA/relay fields), the file,
PostgreSQL and ZeroMQ sinks, and
`AuditManager` (event filters including `lease-delete`, renewal filtering and rate limiting,
queue overflow accounting, StatsMgr metrics, shutdown draining and sink failure isolation).
The file sink failure test uses `/dev/full`.
The PostgreSQL sink test uses the database named by `IP_AUDIT_TEST_DATABASE`; it is skipped
when that variable is unset. CI supplies a PostgreSQL 16 service.

The integration test starts a real `kea-dhcp4` with the installed hook and drives it with a
simulated relay agent (`tests/integration/relay_client.py`) in a separate network namespace.
The relay performs DISCOVER, REQUEST, a renewal and a RELEASE with option 82, and
`check_audit_log.py` verifies assignment, renewal, lease-delete and release records. It needs
root, `iproute2`, `python3` and
`kea-dhcp4`, and uses a veth pair named `ipa-kea` / `ipa-relay` and the network `10.99.0.0/24`.

## Statistics

The hook publishes queue depth/capacity, sink count, dropped records, successful sink writes,
and write failures to Kea's statistics manager once per second. Kea controls how many samples
are retained. Metrics are prefixed with
`ip-audit-dhcp4-` or `ip-audit-dhcp6-`; they are removed when the corresponding hook unloads.
Collect them with Kea's `statistic-get` command or a compatible statistics exporter.

```sh
sudo cmake --install build
sudo bash tests/integration/run.sh
```

Both run in CI on every push and pull request (`.github/workflows/ci.yml`) on Ubuntu 24.04
and 26.04, using each runner's packaged Kea version.

## Building install packages

DEB and RPM packages are produced with CPack. Build on a machine of the same distribution
and Kea version as the target servers.

```sh
cmake -S . -B build -DPACKAGE_MAINTAINER="Name <name@example.com>" \
  -DKEA_IP_AUDIT_VERSION=1.2.3
cmake --build build
cd build
cpack -G DEB    # kea-ip-audit-hook_1.2.3_amd64.deb
cpack -G RPM    # kea-ip-audit-hook-1.2.3-1.x86_64.rpm
```

The package installs both libraries into Kea's hooks directory and the README, docs and
example configurations under `<prefix>/share/doc`. Dependencies on runtime libraries (Kea,
libzmq and libpq) are detected automatically from the built binary (`dpkg-shlibdeps` is required for
DEB; `rpmbuild` for RPM). The package does not modify Kea configuration; add the appropriate
`hooks-libraries` entry to `Dhcp4` or `Dhcp6` yourself and restart Kea.

Install on the target with `apt install ./kea-ip-audit-hook_*.deb` or
`dnf install ./kea-ip-audit-hook-*.rpm`.

`KEA_IP_AUDIT_VERSION` must be numeric `MAJOR.MINOR.PATCH`; it defaults to `0.1.0`. Because
the hook is tied to the Kea hooks API version, build one package per Kea release series and
distribution, ideally in an environment matching each target.

During the build, `src/ip_audit_messages.mes` is compiled into the logging headers by
`kea-msg-compiler`.

CI builds DEBs on Ubuntu 24.04 (`noble`) and 26.04 (`resolute`), and builds the EL9 RPM in a
Rocky Linux 9 container against EPEL's Kea packages. The Ubuntu jobs run on branch pushes,
pull requests, and version tags; non-release builds use version `0.1.0`. The EL9 RPM job runs
only for valid version tags. All release artifacts use the version from the tag and are
uploaded for the publishing job.

## Publishing releases to Cloudsmith

Push a tag named `vMAJOR.MINOR.PATCH` (for example `v1.2.3`) to trigger the release pipeline.
The pipeline runs the Ubuntu build/test matrix, builds the EL9 RPM, then publishes packages
only after those jobs succeed:

- Ubuntu 24.04 DEB to `ubuntu/noble`
- Ubuntu 26.04 DEB to `ubuntu/resolute`
- Enterprise Linux 9 RPM to `el/9`

Configure these GitHub repository variables:

| Variable | Value |
| ---------- | ------- |
| `CLOUDSMITH_WORKSPACE` | Cloudsmith workspace slug. |
| `CLOUDSMITH_REPOSITORY` | Repository slug receiving release packages. |
| `CLOUDSMITH_SERVICE_SLUG` | Dedicated Cloudsmith service-account slug. |

Create a Cloudsmith service account with push access only to the target repository. Configure
Cloudsmith OIDC trust for this GitHub repository and the `cloudsmith-release` GitHub
environment, and protect that environment with the desired approval rule. The workflow uses
Cloudsmith's OIDC GitHub Action and does not store a long-lived API key in GitHub. See the
[Cloudsmith GitHub OIDC setup guide](https://docs.cloudsmith.com/authentication/setup-cloudsmith-to-authenticate-with-oidc-in-github-actions).

## Logging

The hook logs through Kea's logging framework with the logger name `ip-audit-hooks`
(so it is covered by the `kea-dhcp4` or `kea-dhcp6` logger configuration). Messages:

| Message | Meaning |
|---------|---------|
| `IP_AUDIT_LOAD_OK` | Library loaded; shows the number of sinks. |
| `IP_AUDIT_LOAD_FAILED` | Invalid configuration or a sink could not be created. Kea will not load the library. |
| `IP_AUDIT_SINK_CREATED` | A sink was created. |
| `IP_AUDIT_SINK_WRITE_FAILED` | A sink failed to store a record. |
| `IP_AUDIT_QUEUE_OVERFLOW` | Number of records dropped because the bounded queue filled, reported when the hook unloads. |
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

Use the built-in rotation (`max-size`, `max-files`, `rotation-interval`) where possible. If
an external tool renames the active file, send the Kea control command `ip-audit-reopen` so
the file sink opens the new path. This command requires Kea's control socket; see
[configuration.md](configuration.md#control-channel-commands). `ip-audit-stats` reports queue
depth, dropped records, sink write successes and failures.

## Privacy and security

Audit records are personal data. Restrict access accordingly:

- The file sink creates files with mode `0640` by default; change `file-mode` if needed.
- The ZeroMQ sink has no authentication or encryption. Bind to loopback or a `ipc://`
  endpoint, or place a proxy or tunnel in front of it, rather than exposing it to a network.
- Define a retention period and delete or archive old files accordingly.
- Hostnames and other client-controlled text are sanitised so that a client cannot inject
  control characters or fake log lines.

## Limitations

- **Bounded asynchronous delivery.** `queue-size` limits records waiting for the worker.
  When sinks cannot keep up, new records are dropped and the total is reported at unload.
  Accepted records are drained during unload, so a blocked sink can delay shutdown. The
  queue is in memory; a process crash can lose queued records. Use the file sink as the
  authoritative record and size the queue for expected short-term bursts.
- **Delivery is best effort for ZeroMQ.** A PUB socket drops messages when there are no
  subscribers (they join later) or when a subscriber is slower than `send-hwm` allows. Use
  the file sink for the authoritative record and ZeroMQ for real-time consumers.
- **Expiry events lack relay data** because no client packet is involved.
- **Renewal detection relies on Kea sharing the callout context** between the family-specific
  renew/rebind hook and the committed hook for the same packet. If this does not hold in your
  Kea version, renewals are logged as `lease-assign`.
- **POSIX only.** The file sink uses POSIX system calls.
- **Configuration changes** take effect when Kea reloads its configuration, which unloads
  and reloads the library and its sinks.
