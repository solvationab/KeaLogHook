#pragma once

#include "sink.h"

#include <cc/data.h>

#include <memory>

namespace ip_audit {

// Publishes records on a ZeroMQ PUB socket.
// Parameters: endpoint (required), mode ("bind"|"connect"), format, topic (a template, may use
// %{field}), multipart (topic as its own frame), send-hwm, linger-ms, io-threads.
std::unique_ptr<Sink> createZmqSink(const isc::data::ConstElementPtr& cfg);

}
