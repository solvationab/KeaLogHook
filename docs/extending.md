# Adding a new sink

A sink is a destination for audit records. The hook logic does not know which sinks
exist; it only talks to the `Sink` interface, so adding one (a database, syslog, Kafka,
an HTTP endpoint, ...) requires no changes to the callouts or the record builder.

## 1. Implement the interface

```cpp
// src/sink.h
class Sink {
public:
    virtual ~Sink() = default;
    virtual void write(const AuditRecord& record) = 0;
};
```

Requirements:

- `write()` may be called concurrently from several threads. Protect shared state.
- Throw an exception (preferably `std::runtime_error`) when a record cannot be stored.
  `AuditManager` logs it and continues with the other sinks.
- Do not block for long. `write()` runs on the DHCP processing path.
- Acquire resources in the constructor and throw on failure, so that a bad
  configuration is detected when the library loads.

## 2. Write a creator function

The creator receives the sink's JSON object. Use the helpers in `src/config_util.h` to
read and validate parameters, reject unknown keys, and create the formatter:

```cpp
std::unique_ptr<Sink> createMySink(const isc::data::ConstElementPtr& cfg) {
    rejectUnknownKeys(cfg, SinkFactory::allowedKeys({"url", "timeout-ms"}));
    std::string url = requireString(cfg, "url");
    int64_t timeout = optInt(cfg, "timeout-ms", 1000, 1, 60000);
    return std::make_unique<MySink>(url, timeout, createFormatter(cfg->get("format")));
}
```

`SinkFactory::allowedKeys()` adds the common keys (`type`, `name`, `events`, `format`).
Throw `ConfigError` for invalid values.

Use `createFormatter()` and `Formatter::format()` if your sink writes text. A sink that
needs structured data (for example a SQL insert) can read fields directly with
`AuditRecord::find()` / `AuditRecord::fields()`.

## 3. Register it

Add one line to the `SinkFactory` constructor in `src/sink_factory.cc`:

```cpp
registerType("mysink", createMySink);
```

and add the new source file to `add_library(...)` in `CMakeLists.txt`.

The sink can now be used from the Kea configuration with `"type": "mysink"`.

## Adding a field or event

- **Field:** add its name to `knownFieldNames()` in `src/audit_record.h` and set it in
  `buildRecord()` in `src/record_builder.cc`, in the same position. Names listed in
  `knownFieldNames()` are what `fields` lists and `%{...}` templates are validated against.
- **Event:** add its name to `knownEventNames()`, register a callout in
  `src/callouts.cc` and publish a record from it.

## Adding a format

Implement `Formatter` in `src/formatter.cc` and add a branch for the new `type` in
`createFormatter()`. All sinks gain the format automatically.
