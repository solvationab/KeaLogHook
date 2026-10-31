#pragma once

#include "sink.h"

#include <cc/data.h>

#include <memory>

namespace ip_audit {

std::unique_ptr<Sink> createPostgresSink(const isc::data::ConstElementPtr& cfg);

}