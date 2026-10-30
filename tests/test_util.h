#pragma once

#include <cc/data.h>

#include <gtest/gtest.h>

#include <stdlib.h>

#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

namespace ip_audit_test {

inline isc::data::ConstElementPtr json(const std::string& text) {
    return isc::data::Element::fromJSON(text);
}

// Scratch directory that is removed again when the object goes out of scope.
class TempDir {
public:
    TempDir() {
        std::string pattern = (std::filesystem::temp_directory_path() / "ip-audit-test-XXXXXX").string();
        if (!mkdtemp(&pattern[0])) {
            throw std::runtime_error("mkdtemp failed");
        }
        path_ = pattern;
    }

    ~TempDir() {
        std::error_code ec;
        std::filesystem::remove_all(path_, ec);
    }

    TempDir(const TempDir&) = delete;
    TempDir& operator=(const TempDir&) = delete;

    std::string file(const std::string& name) const { return (path_ / name).string(); }

private:
    std::filesystem::path path_;
};

inline std::vector<std::string> readLines(const std::string& path) {
    std::vector<std::string> lines;
    std::ifstream in(path);
    std::string line;
    while (std::getline(in, line)) {
        lines.push_back(line);
    }
    return lines;
}

}
