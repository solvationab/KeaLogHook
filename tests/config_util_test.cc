#include "config_util.h"

#include "test_util.h"

using namespace ip_audit;
using ip_audit_test::json;

TEST(ConfigUtil, RequireStringReturnsValue) {
    EXPECT_EQ("abc", requireString(json(R"({"k":"abc"})"), "k"));
}

TEST(ConfigUtil, RequireStringRejectsMissingAndWrongType) {
    EXPECT_THROW(requireString(json("{}"), "k"), ConfigError);
    EXPECT_THROW(requireString(json(R"({"k":1})"), "k"), ConfigError);
}

TEST(ConfigUtil, AccessorsRejectNonObject) {
    EXPECT_THROW(requireString(json("[]"), "k"), ConfigError);
    EXPECT_THROW(optBool(json("1"), "k", false), ConfigError);
    EXPECT_THROW(optStringList(isc::data::ConstElementPtr(), "k"), ConfigError);
}

TEST(ConfigUtil, OptStringUsesDefault) {
    EXPECT_EQ("def", optString(json("{}"), "k", "def"));
    EXPECT_EQ("x", optString(json(R"({"k":"x"})"), "k", "def"));
    EXPECT_THROW(optString(json(R"({"k":true})"), "k", "def"), ConfigError);
}

TEST(ConfigUtil, OptIntUsesDefaultAndChecksRange) {
    EXPECT_EQ(5, optInt(json("{}"), "k", 5, 0, 10));
    EXPECT_EQ(0, optInt(json(R"({"k":0})"), "k", 5, 0, 10));
    EXPECT_EQ(10, optInt(json(R"({"k":10})"), "k", 5, 0, 10));
    EXPECT_THROW(optInt(json(R"({"k":-1})"), "k", 5, 0, 10), ConfigError);
    EXPECT_THROW(optInt(json(R"({"k":11})"), "k", 5, 0, 10), ConfigError);
}

TEST(ConfigUtil, OptIntRejectsWrongType) {
    EXPECT_THROW(optInt(json(R"({"k":"3"})"), "k", 5, 0, 10), ConfigError);
    EXPECT_THROW(optInt(json(R"({"k":1.5})"), "k", 5, 0, 10), ConfigError);
}

TEST(ConfigUtil, OptBool) {
    EXPECT_TRUE(optBool(json("{}"), "k", true));
    EXPECT_FALSE(optBool(json(R"({"k":false})"), "k", true));
    EXPECT_THROW(optBool(json(R"({"k":"true"})"), "k", false), ConfigError);
}

TEST(ConfigUtil, OptStringList) {
    EXPECT_TRUE(optStringList(json("{}"), "k").empty());
    EXPECT_EQ((std::vector<std::string>{"a", "b"}), optStringList(json(R"({"k":["a","b"]})"), "k"));
    EXPECT_THROW(optStringList(json(R"({"k":"a"})"), "k"), ConfigError);
    EXPECT_THROW(optStringList(json(R"({"k":["a",1]})"), "k"), ConfigError);
}

TEST(ConfigUtil, RejectUnknownKeys) {
    EXPECT_NO_THROW(rejectUnknownKeys(json(R"({"a":1})"), {"a", "b"}));
    EXPECT_NO_THROW(rejectUnknownKeys(json("{}"), {"a"}));
    EXPECT_THROW(rejectUnknownKeys(json(R"({"a":1,"typo":2})"), {"a", "b"}), ConfigError);
    EXPECT_THROW(rejectUnknownKeys(json("[]"), {"a"}), ConfigError);
}

TEST(ConfigUtil, RejectUnknownKeysNamesTheKey) {
    try {
        rejectUnknownKeys(json(R"({"typo":2})"), {"a"});
        FAIL() << "expected ConfigError";
    } catch (const ConfigError& ex) {
        EXPECT_NE(std::string::npos, std::string(ex.what()).find("typo"));
    }
}
