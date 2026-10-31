#pragma once

#include "audit_manager.h"

#include <cc/command_interpreter.h>
#include <cc/data.h>
#include <hooks/callout_handle.h>

#include <exception>
#include <string>

namespace ip_audit {

inline int setCommandError(isc::hooks::CalloutHandle& handle, const std::string& message) {
    const auto response = isc::config::createAnswer(isc::config::CONTROL_RESULT_ERROR, message);
    handle.setArgument("response", response);
    return 0;
}

inline int handleReopenCommand(isc::hooks::CalloutHandle& handle, AuditManager* manager) {
    if (!manager) {
        return setCommandError(handle, "audit manager is not loaded");
    }

    try {
        const auto result = manager->reopenSinks();
        auto arguments = isc::data::Element::createMap();
        arguments->set("reopened", isc::data::Element::create(
                                        static_cast<long long>(result.reopened)));
        arguments->set("unsupported", isc::data::Element::create(
                                           static_cast<long long>(result.unsupported)));
        arguments->set("failed", isc::data::Element::create(
                                     static_cast<long long>(result.failed)));
        auto errors = isc::data::Element::createList();
        for (const auto& error : result.errors) {
            errors->add(isc::data::Element::create(error));
        }
        arguments->set("errors", errors);

        const int status = result.failed == 0 ? isc::config::CONTROL_RESULT_SUCCESS
                                               : isc::config::CONTROL_RESULT_ERROR;
        const std::string text = result.failed == 0 ? "sink reopen complete"
                                                     : "one or more sinks failed to reopen";
        const auto response = isc::config::createAnswer(status, text, arguments);
        handle.setArgument("response", response);
    } catch (const std::exception& ex) {
        return setCommandError(handle, ex.what());
    } catch (...) {
        return setCommandError(handle, "unknown error while reopening sinks");
    }
    return 0;
}

inline int handleStatsCommand(isc::hooks::CalloutHandle& handle, AuditManager* manager) {
    if (!manager) {
        return setCommandError(handle, "audit manager is not loaded");
    }

    try {
        const auto stats = manager->statistics();
        auto arguments = isc::data::Element::createMap();
        arguments->set("queue-depth", isc::data::Element::create(
                                          static_cast<long long>(stats.queueDepth)));
        arguments->set("queue-capacity", isc::data::Element::create(
                                             static_cast<long long>(stats.queueCapacity)));
        arguments->set("sink-count", isc::data::Element::create(
                                         static_cast<long long>(stats.sinkCount)));
        arguments->set("dropped-records", isc::data::Element::create(
                                             static_cast<long long>(stats.droppedRecords)));
        arguments->set("sink-writes", isc::data::Element::create(
                                          static_cast<long long>(stats.sinkWrites)));
        arguments->set("sink-write-failures", isc::data::Element::create(
                                                  static_cast<long long>(stats.sinkWriteFailures)));
        const auto response = isc::config::createAnswer(isc::config::CONTROL_RESULT_SUCCESS,
                                                         arguments);
        handle.setArgument("response", response);
    } catch (const std::exception& ex) {
        return setCommandError(handle, ex.what());
    } catch (...) {
        return setCommandError(handle, "unknown error while collecting audit statistics");
    }
    return 0;
}

}