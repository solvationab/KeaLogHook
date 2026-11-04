#pragma once

#include "sink.h"

#include <cc/data.h>

#include <memory>

namespace ip_audit {

std::unique_ptr<Sink> createSyslogSink(const isc::data::ConstElementPtr& cfg);

}
