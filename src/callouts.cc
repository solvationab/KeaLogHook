#include "audit_manager.h"
#include "config_util.h"
#include "ip_audit_log.h"
#include "record_builder.h"

#include <dhcp/pkt4.h>
#include <dhcpsrv/lease.h>
#include <hooks/hooks.h>

#include <memory>

using namespace isc::dhcp;
using namespace isc::hooks;

namespace {

std::unique_ptr<ip_audit::AuditManager> manager;

void publish(const char* event, const Pkt4Ptr& query, const Lease4Ptr& lease) {
    if (!manager || !lease) {
        return;
    }
    try {
        manager->publish(ip_audit::buildRecord(event, query, lease));
    } catch (const std::exception& ex) {
        LOG_ERROR(ip_audit::ip_audit_logger, ip_audit::IP_AUDIT_CALLOUT_FAILED).arg(event).arg(ex.what());
    }
}

// Marks the packet so leases4_committed can tell a renewal from a new assignment.
int lease4_renew(CalloutHandle& handle) {
    handle.setContext("ip_audit_renewal", true);
    return 0;
}

int leases4_committed(CalloutHandle& handle) {
    Pkt4Ptr query;
    Lease4CollectionPtr leases;
    handle.getArgument("query4", query);
    handle.getArgument("leases4", leases);
    if (!leases) {
        return 0;
    }

    bool renewal = false;
    try {
        handle.getContext("ip_audit_renewal", renewal);
    } catch (const NoSuchCalloutContext&) {
    }

    for (const auto& lease : *leases) {
        publish(renewal ? "lease-renew" : "lease-assign", query, lease);
    }
    return 0;
}

int lease4_release(CalloutHandle& handle) {
    Pkt4Ptr query;
    Lease4Ptr lease;
    handle.getArgument("query4", query);
    handle.getArgument("lease4", lease);
    publish("lease-release", query, lease);
    return 0;
}

int lease4_decline(CalloutHandle& handle) {
    Pkt4Ptr query;
    Lease4Ptr lease;
    handle.getArgument("query4", query);
    handle.getArgument("lease4", lease);
    publish("lease-decline", query, lease);
    return 0;
}

// No client packet is involved in expiry, so relay information is not available.
int lease4_expire(CalloutHandle& handle) {
    Lease4Ptr lease;
    handle.getArgument("lease4", lease);
    publish("lease-expire", Pkt4Ptr(), lease);
    return 0;
}

}

extern "C" {

int version() {
    return KEA_HOOKS_VERSION;
}

int multi_threading_compatible() {
    return 1;
}

int load(LibraryHandle& handle) {
    try {
        int64_t queueSize = ip_audit::optInt(handle.getParameters(), "queue-size",
                                             ip_audit::AuditManager::kDefaultQueueCapacity,
                                             1, 1000000);
        manager = ip_audit::AuditManager::create(handle.getParameter("sinks"), queueSize);
        handle.registerCallout("lease4_renew", lease4_renew);
        handle.registerCallout("leases4_committed", leases4_committed);
        handle.registerCallout("lease4_release", lease4_release);
        handle.registerCallout("lease4_decline", lease4_decline);
        handle.registerCallout("lease4_expire", lease4_expire);
    } catch (const std::exception& ex) {
        manager.reset();
        LOG_ERROR(ip_audit::ip_audit_logger, ip_audit::IP_AUDIT_LOAD_FAILED).arg(ex.what());
        return 1;
    }
    LOG_INFO(ip_audit::ip_audit_logger, ip_audit::IP_AUDIT_LOAD_OK).arg(manager->sinkCount());
    return 0;
}

int unload() {
    manager.reset();
    LOG_INFO(ip_audit::ip_audit_logger, ip_audit::IP_AUDIT_UNLOAD);
    return 0;
}

}
