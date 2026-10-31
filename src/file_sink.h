#pragma once

#include "sink.h"

#include <cc/data.h>

#include <memory>

namespace ip_audit {

// Parameters: path (required), format, file-mode, max-size, max-files, fsync, rotation-interval,
// retention-days and compress-rotated.
std::unique_ptr<Sink> createFileSink(const isc::data::ConstElementPtr& cfg);

}
