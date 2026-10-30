#pragma once

#include "audit_record.h"

#include <dhcp/pkt4.h>
#include <dhcp/pkt6.h>
#include <dhcpsrv/lease.h>

#include <string>

namespace ip_audit {

// query may be null (e.g. lease expiry), in which case relay and packet fields are empty.
AuditRecord buildRecord(const std::string& event, const isc::dhcp::Pkt4Ptr& query,
                        const isc::dhcp::Lease4Ptr& lease);
AuditRecord buildRecord(const std::string& event, const isc::dhcp::Pkt6Ptr& query,
                        const isc::dhcp::Lease6Ptr& lease);

}
