#pragma once

#include "sink.h"

#include <cc/data.h>

#include <memory>

namespace ip_audit {

// Parameters: path (required), format, file-mode ("0640"), max-size (bytes, 0 = no rotation),
// max-files (rotated files to keep), fsync (bool).
std::unique_ptr<Sink> createFileSink(const isc::data::ConstElementPtr& cfg);

}
