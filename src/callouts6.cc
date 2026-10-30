#include "audit_manager.h"
#include "config_util.h"
#include "ip_audit_log.h"
#include "record_builder.h"

#include <dhcp/pkt6.h>
#include <dhcpsrv/lease.h>
#include <hooks/hooks.h>

#include <memory>

using namespace isc::dhcp;
using namespace isc::hooks;

namespace {

std::unique_ptr<ip_audit::AuditManager> manager;

void publish(const char* event, const Pkt6Ptr& query, const Lease6Ptr& lease) {
    if (!manager || !lease) {
        return;
    }
    try {
        manager->publish(ip_audit::buildRecord(event, query, lease));
    } catch (const std::exception& ex) {
        LOG_ERROR(ip_audit::ip_audit_logger, ip_audit::IP_AUDIT_CALLOUT_FAILED).arg(event).arg(ex.what());
    }
}

int markRenewal(CalloutHandle& handle) {
    handle.setContext("ip_audit_renewal", true);
    return 0;
}

int lease6_renew(CalloutHandle& handle) {
    return markRenewal(handle);
}

int lease6_rebind(CalloutHandle& handle) {
    return markRenewal(handle);
}

int leases6_committed(CalloutHandle& handle) {
    Pkt6Ptr query;
    Lease6CollectionPtr leases;
    handle.getArgument("query6", query);
    handle.getArgument("leases6", leases);
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

int lease6_release(CalloutHandle& handle) {
    Pkt6Ptr query;
    Lease6Ptr lease;
    handle.getArgument("query6", query);
    handle.getArgument("lease6", lease);
    publish("lease-release", query, lease);
    return 0;
}

int lease6_decline(CalloutHandle& handle) {
    Pkt6Ptr query;
    Lease6Ptr lease;
    handle.getArgument("query6", query);
    handle.getArgument("lease6", lease);
    publish("lease-decline", query, lease);
    return 0;
}

int lease6_expire(CalloutHandle& handle) {
    Lease6Ptr lease;
    handle.getArgument("lease6", lease);
    publish("lease-expire", Pkt6Ptr(), lease);
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
        handle.registerCallout("lease6_renew", lease6_renew);
        handle.registerCallout("lease6_rebind", lease6_rebind);
        handle.registerCallout("leases6_committed", leases6_committed);
        handle.registerCallout("lease6_release", lease6_release);
        handle.registerCallout("lease6_decline", lease6_decline);
        handle.registerCallout("lease6_expire", lease6_expire);
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