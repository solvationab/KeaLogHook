# Kea IP Audit Hook

C++17 hook library for `kea-dhcp4` that records lease events (with DHCP option 82 relay data) to pluggable sinks (`file`, `zeromq`). Source is in `src/`, docs in `docs/`, example config in `examples/`.

## Language

- Write everything in English (code, comments, docs, log messages, commit messages), even if the user writes in another language.

## Build

- CMake 3.16+, Linux/POSIX target. Requires Kea dev headers, `kea-msg-compiler`, libzmq and Boost headers.
- `cmake -S . -B build -DKEA_PREFIX=/usr && cmake --build build`
- Log messages in `src/ip_audit_messages.mes` are compiled to `build/generated/`; never edit generated files.
- New `.cc` files must be added to `add_library(dhcp_ip_audit ...)` in `CMakeLists.txt`.
- There are no tests yet and the code has not been built against a real Kea (see `docs/roadmap.md`). Do not claim a change is verified by a build or test run unless it was actually run.

## Architecture

- `callouts.cc` -> `record_builder` -> `AuditManager` -> `Sink` -> `Formatter`. See `docs/architecture.md`.
- Callouts must never throw into Kea. Sink failures are logged (`IP_AUDIT_SINK_WRITE_FAILED`) and must not affect other sinks or DHCP processing.
- Configuration errors must throw at load time (`ConfigError`) so `load()` fails instead of silently not logging.
- Config parsing is strict: reject unknown keys (`rejectUnknownKeys`) and validate values with the helpers in `src/config_util.h`.
- The library is multi-threading compatible: each sink protects its own resource with a mutex; format outside the lock.
- `Sink::write()` runs on the DHCP path, so keep it fast.

## Extending

- New sink: implement `Sink`, write a creator using `config_util.h` helpers, register it in the `SinkFactory` constructor (`src/sink_factory.cc`). See `docs/extending.md`.
- New field: add it to `knownFieldNames()` in `src/audit_record.h` and set it in `buildRecord()` in `src/record_builder.cc` in the same position.
- New event: add it to `knownEventNames()`, register a callout in `src/callouts.cc`.
- New format: add a branch in `createFormatter()` in `src/formatter.cc`.

## Documentation

- Keep docs in sync with behavior changes: `docs/configuration.md` for parameters, `docs/fields.md` for fields and events, `docs/architecture.md` for structure, `README.md` for the overview.
- Mark items in `docs/roadmap.md` as done or remove them when implemented.
