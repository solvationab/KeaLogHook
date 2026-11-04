# Building, operating and limitations

## Installing release packages

Start with the [README quick start](../README.md#quick-start) to install, configure,
and verify the hook. Download packages and matching documentation from
[GitHub Releases](https://github.com/solvationab/KeaLogHook/releases).

| Target | Release asset suffix | Cloudsmith target | Typical DHCPv4 unit |
| ------ | -------------------- | ----------------- | ------------------- |
| Ubuntu 24.04, x86-64 | `_noble.deb` | `ubuntu/noble` | `kea-dhcp4-server` |
| Ubuntu 26.04, x86-64 | `_resolute.deb` | `ubuntu/resolute` | `kea-dhcp4-server` |
| EL9, x86-64 | `_el9.rpm` | `el/9` | `kea-dhcp4` |

Use the package for your distribution, architecture, and installed Kea version. Release
packages use the distribution's Kea libraries (EPEL Kea on EL9), not arbitrary ISC or
third-party builds. Install the Kea DHCP server separately if it is not already present.
Build from source for other targets. Rebuild the hook whenever Kea is upgraded.

### Install from Cloudsmith

Each release links to the configured Cloudsmith repository and its **Set Me Up** page.
Select Debian/Ubuntu or RPM instructions for your target and follow the generated signing-key
and repository setup steps. For a private repository, use the access method supplied by
your administrator; never commit repository credentials to configuration examples.

Once the repository is configured, run only the command for your distribution:

```sh
sudo apt update
sudo apt install kea-ip-audit-hook          # Ubuntu
sudo dnf install kea-ip-audit-hook          # EL9
```

You can inspect package metadata before installation with `apt show kea-ip-audit-hook`
or `dnf info kea-ip-audit-hook`. Homepage/URL and description fields link back to GitHub
and the getting-started documentation. The Cloudsmith package named `kea-ip-audit-docs`
contains the README, docs and examples for a specific release.

### Install a downloaded package

Download a single matching DEB or RPM and `SHA256SUMS` from the same GitHub release.
To verify that one download matches its published checksum:

```sh
sha256sum --ignore-missing -c SHA256SUMS
sudo apt install ./kea-ip-audit-hook_*_noble.deb    # Ubuntu 24.04 example
sudo dnf install ./kea-ip-audit-hook-*_el9.rpm      # EL9 alternative
```

Run the matching install command, not both. Checksums detect download corruption;
they are not independent publisher signatures. Use Cloudsmith's signing-key/repository
instructions for normal package-manager verification. If the required Kea dependencies
cannot be resolved, check the target distribution and Kea package source rather than
forcing installation or bypassing dependency checks.

Packages do not edit Kea configuration, create log directories, change log ownership, or
restart DHCP. Follow the [quick start](../README.md#quick-start) after installation.
Find installed examples and docs with `dpkg-query -L kea-ip-audit-hook` or
`rpm -ql kea-ip-audit-hook`; they are under `/usr/share/doc` in release packages.

### Troubleshooting first startup

- **Hook does not load:** look for `IP_AUDIT_LOAD_FAILED` before Kea's generic
  `HOOKS_LOAD_ERROR`. It contains the sink or configuration failure.
- **Permission denied:** inspect `systemctl show <unit> -p User -p Group` and
  `namei -l /var/log/kea/ip-audit.log`. The service account needs directory traversal
  and write access for log creation/rotation. If the directory is absent, create it
  using the verified daemon account: on Ubuntu with `_kea`, for example,
  `sudo install -d -o _kea -g _kea -m 0750 /var/log/kea`. Do not change ownership of an
  existing shared log directory blindly or use world-writable permissions.
- **Permissions look correct:** check `journalctl -k -b` for a Kea AppArmor or SELinux
  denial. See [Package security policy](#package-security-policy). Do not disable enforcement.
- **Library not found:** use the absolute path from the package file list. Ubuntu uses
  multiarch paths; EL9 normally uses `/usr/lib64/kea/hooks`.
- **CLI command not found:** check the package file list for `/usr/bin/ip-audit-lookup`
  and `/usr/bin/ip-audit-list`, then check `PATH`. Older packages or installations of only
  the `.so` files may not contain the commands.
- **No records yet:** the hook records new lease events, not a startup dump of all
  existing leases. Check sink event/field filters and wait for an allocation or renewal.
- **No CID/RID:** option 82 must actually be supplied by a DHCPv4 relay. Binary IDs
  appear as hex plus escaped ASCII, not decoded vendor-specific structures.
- **Listing is incomplete:** preserve all events and `lease-expires` plus client
  identities; use JSON logs and include rotations. Audit snapshots are not live lease queries.

## Building

Requirements: Kea development headers and libraries (`kea-dhcpsrv`, `kea-dhcp++`,
`kea-hooks`, `kea-log`, `kea-stats`, `kea-util`, `kea-cc`, `kea-exceptions`), `kea-msg-compiler`,
libzmq (found through `pkg-config`), libpq, Boost headers, OpenSSL Crypto and zlib development files,
a C++17 compiler, CMake 3.16+.

On Ubuntu, install the build dependencies first:

```sh
sudo apt update
sudo apt install git build-essential cmake pkg-config kea-dev kea-dhcp4-server \
  libzmq3-dev libpq-dev libboost-dev libssl-dev zlib1g-dev libgtest-dev dpkg-dev python3
git clone https://github.com/solvationab/KeaLogHook.git
cd KeaLogHook
```

```sh
cmake -S . -B build -DKEA_PREFIX=/usr
cmake --build build
sudo cmake --install build
```

| CMake variable | Default | Meaning |
| ---------------- | --------- | --------- |
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
The lookup/list CLI tests use only the Python standard library and run with
`python3 tests/test_lookup.py`. Both installed commands require Python 3.7+.
Package lifecycle and mocked release-documentation tests run with
`sh tests/package_policy_test.sh` and `bash tests/release_docs_test.sh`.

The integration test starts a real `kea-dhcp4` with the installed hook and drives it with a
simulated relay agent (`tests/integration/relay_client.py`) in a separate network namespace.
The relay performs DISCOVER, REQUEST, a renewal and a RELEASE with option 82, and
`check_audit_log.py` verifies assignment, renewal, lease-delete and release records. It needs
root, `iproute2`, `python3` and
`kea-dhcp4`, and uses a veth pair named `ipa-kea` / `ipa-relay` and the network `10.99.0.0/24`.

```sh
sudo cmake --install build
sudo bash tests/integration/run.sh
```

Tests run in CI on every push and pull request (`.github/workflows/ci.yml`) on Ubuntu 24.04
and 26.04, using each runner's packaged Kea version.

## Statistics

The hook publishes queue depth/capacity, sink count, dropped records, successful sink writes,
and write failures to Kea's statistics manager once per second. Kea controls how many samples
are retained. Metrics are prefixed with
`ip-audit-dhcp4-` or `ip-audit-dhcp6-`; they are removed when the corresponding hook unloads.
Collect them with Kea's `statistic-get` command or a compatible statistics exporter.

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

The package installs both libraries into Kea's hooks directory, both CLI commands into
`<prefix>/bin`, and the README, docs and
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

After package uploads succeed, it also publishes `kea-ip-audit-docs` as a versioned raw
Cloudsmith package and creates or updates the GitHub release for the tag. Release assets
include distro-qualified DEBs/RPMs (so Ubuntu assets do not collide), a documentation
archive, and `SHA256SUMS`. Generated release notes link to the tag's quick start,
configuration, fields, and operations guide, plus Cloudsmith packages and **Set Me Up**.
The same notes appear in the GitHub Actions job summary. Rerunning the documentation step
replaces its raw documentation package, generated GitHub notes, and matching release assets.

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

The service account needs permission to push DEB, RPM and raw documentation packages to
this repository. GitHub's built-in token needs `contents: write` in the publishing job
to manage releases; the workflow grants it only there. Allow release creation in your
repository/organization policies. No Cloudsmith repository settings are changed: its
visibility, description, signing keys and consumer access remain administrator-managed.

Validate the mocked publishing flow locally with `bash tests/release_docs_test.sh`.
Actual uploads and release creation require a tagged GitHub run with the variables,
OIDC trust, and token permissions above; local tests do not publish anything.

## Logging

The hook logs through Kea's logging framework with the logger name `ip-audit-hooks`
(so it is covered by the `kea-dhcp4` or `kea-dhcp6` logger configuration). Messages:

| Message | Meaning |
| --------- | --------- |
| `IP_AUDIT_LOAD_OK` | Library loaded; shows the number of sinks. |
| `IP_AUDIT_LOAD_FAILED` | Invalid configuration or a sink could not be created. Kea will not load the library. |
| `IP_AUDIT_SINK_CREATED` | A sink was created. |
| `IP_AUDIT_SINK_WRITE_FAILED` | A sink failed to store a record. |
| `IP_AUDIT_QUEUE_OVERFLOW` | Number of records dropped because the bounded queue filled, reported when the hook unloads. |
| `IP_AUDIT_CALLOUT_FAILED` | A record could not be built. |
| `IP_AUDIT_UNLOAD` | Library unloaded. |

## Consuming ZeroMQ records

Circuit and remote identifiers retain their original hex fields and also have
`circuit-id-text` and `remote-id-text` representations. Printable ASCII is retained;
other bytes become lowercase `\xNN` escapes, and literal backslashes are doubled.
For example, bytes `00 70 6f 72 74` become `\x00port`. JSON additionally escapes
backslashes, so this appears as `"circuit-id-text":"\\x00port"` in a JSON record.
This applies to file, ZeroMQ, and PostgreSQL JSON output. Custom field lists and
templates must include the text fields explicitly. Missing or empty IDs remain empty.

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

## Package security policy

DEB and RPM packages install an AppArmor snippet permitting reads and writes to
`/var/log/kea/ip-audit.log`, `/var/log/kea/ip-audit6.log`, and their dot-suffixed
rotations (including compressed files). No other log paths are granted access.
Installation and upgrades add an optional include to the existing Kea DHCPv4/v6
local overrides and reload the corresponding profiles when AppArmor is enabled.
Removal deletes only that include and reloads the profiles; existing administrator
rules and audit logs are retained. Packages never restart DHCP services.

Supported profile filenames are `kea-dhcp4`, `kea-dhcp6`, `usr.sbin.kea-dhcp4`, and
`usr.sbin.kea-dhcp6` under `/etc/apparmor.d`. Each must include its matching
`local/<profile-filename>` override. Missing profiles are skipped; unsupported
includes produce a warning. If Kea or AppArmor is installed later, reinstall the
hook package to activate the integration. If `apparmor_parser` is unavailable,
reload the affected profiles manually after installing it.

Custom log paths require administrator-managed AppArmor rules. Ordinary file
permissions still apply: the Kea service user needs directory traversal and write
access to create and rotate logs. Packages do not change log ownership or modes.

EL9 normally uses SELinux rather than AppArmor. The RPM's AppArmor integration is
inactive when no supported profiles exist. No additional SELinux permissions or
file-context overrides are installed: SELinux-enforcing log creation and rotation
have not been certified. Check AVC denials and the distribution's Kea policy before
adding site-specific persistent contexts or policy. Do not disable enforcement.

Plain `cmake --install` installs the snippet and helper but does not execute package
lifecycle scripts. Run `<libexecdir>/kea-ip-audit/security-policy configure` as root
to activate it, and `security-policy remove` before manually uninstalling it.

## Looking up lease history

Release DEB/RPM packages install `/usr/bin/ip-audit-lookup` and require Python 3.7
or newer. For source installations, the command is installed under the configured
`CMAKE_INSTALL_PREFIX` and `CMAKE_INSTALL_BINDIR` instead.

If the shell reports `command not found`, check the installed package's file list:

```sh
dpkg-query -L kea-ip-audit-hook | grep ip-audit-lookup  # Debian/Ubuntu
rpm -ql kea-ip-audit-hook | grep ip-audit-lookup        # RPM distributions
```

If no file is listed, upgrade to a package containing the CLI. If the file is listed
and exists, try its absolute path and check that its directory is on `PATH`.
Installing only the hook `.so` files does not install the lookup command.

The installed `ip-audit-lookup` command reads JSON audit records and reconstructs lease
intervals from assignment, renewal and lease-ending events. Pass a base log path to include
that file plus sibling rotations (for example `ip-audit.log.1` and `ip-audit.log.1.gz`), or
pass explicit files or a quoted glob pattern. Gzip rotations are read directly.

```sh
ip-audit-lookup 192.0.2.10 2026-10-31T12:00:00Z /var/log/kea/ip-audit.log
```

The timestamp must include a timezone. Assignments open an interval through `lease-expires`;
renewals by the same client extend it. A different client closes the prior interval and opens
a new one. Release, delete, decline and expiry events close a matching client interval, so a
stale ending event for a previous client does not close a reassignment. Delegated IPv6
prefixes match addresses within the prefix. Intervals use a start-inclusive, end-exclusive
range. The tool prints matching intervals and source-file locations for relevant events.

Exit status is `0` when a lease matches the query time, `1` when no lease matches, and `2`
for invalid input or unreadable/malformed logs. Custom JSON field selections must retain the
fields needed for reconstruction (`timestamp`, `event`, `ip-address`, and ideally
`lease-expires` plus client identity fields); missing expiry or identity fields limit the
timeline's precision.

## Listing current allocations

The installed `ip-audit-list` command outputs a JSON snapshot of unexpired allocations
inferred from audit logs. It accepts the same base paths, numbered/gzip rotations, and
quoted glob patterns as `ip-audit-lookup`:

```sh
ip-audit-list /var/log/kea/ip-audit.log /var/log/kea/ip-audit6.log
ip-audit-list /var/log/kea/ip-audit.log --at 2026-11-04T12:00:00Z
ip-audit-list /var/log/kea/ip-audit.log > allocations.json
```

The default snapshot time is now (UTC); `--at` selects an explicit timezone-aware time.
Events after that time are ignored. Output contains `as-of`, `source` (`audit-logs`),
`count`, and `leases`. Each lease has `network` (an address as /32 or /128, or a delegated
prefix), reconstructed `start` and `end`, and the complete latest audit `record`, including
hex and escaped-ASCII CID/RID fields when present. Entries are sorted numerically by
address, IPv4 before IPv6.

Renewals extend allocations; release, delete, decline, expiry, and reassignment close them.
An allocation is excluded at its expiry time. Unknown expiry is excluded with a warning
on stderr. Empty results return success (`0`); unreadable logs, invalid JSON, and invalid
timestamps return `2` without a partial JSON result.

This command does not query Kea and cannot guarantee an authoritative current lease list.
Missing, filtered, dropped, or not-yet-written events can make the snapshot incomplete or
stale. Use JSON logs with all events and `lease-expires` plus client identity fields retained.
Input must describe a single allocation domain; independent servers or networks with
overlapping addresses should be queried separately. Full logs are loaded into memory.
Both release packages install `/usr/bin/ip-audit-list` alongside `/usr/bin/ip-audit-lookup`.

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
