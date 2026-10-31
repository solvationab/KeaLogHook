#pragma once

#include "audit_record.h"

namespace ip_audit {

// Implement this to add a new way of storing audit records, then register it in
// SinkFactory. write() may be called concurrently and must be thread-safe.
class Sink {
public:
    virtual ~Sink() = default;
    virtual void write(const AuditRecord& record) = 0;

    // Returns true if this sink supports reopening an external resource.
    virtual bool reopen() { return false; }
};

}
