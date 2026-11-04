// Fuzzes Kudu's rapidjson wrapper (util/jsonreader.cc): parse + typed field extraction.
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include <rapidjson/document.h>

#include "kudu/util/jsonreader.h"
#include "kudu/util/status.h"

static void Walk(const kudu::JsonReader& r, const rapidjson::Value* v, int depth) {
  if (depth > 8) return;
  bool b; int32_t i32; uint32_t u32; int64_t i64; uint64_t u64; double d; float f; std::string s;
  (void)r.ExtractBool(v, nullptr, &b);
  (void)r.ExtractInt32(v, nullptr, &i32);
  (void)r.ExtractUint32(v, nullptr, &u32);
  (void)r.ExtractInt64(v, nullptr, &i64);
  (void)r.ExtractUint64(v, nullptr, &u64);
  (void)r.ExtractDouble(v, nullptr, &d);
  (void)r.ExtractFloat(v, nullptr, &f);
  (void)r.ExtractString(v, nullptr, &s);
  if (v->IsObject()) {
    for (auto it = v->MemberBegin(); it != v->MemberEnd(); ++it) {
      const rapidjson::Value* child = nullptr;
      if (r.ExtractObject(v, it->name.GetString(), &child).ok()) Walk(r, child, depth + 1);
      (void)r.ExtractString(v, it->name.GetString(), &s);
      (void)r.ExtractInt64(v, it->name.GetString(), &i64);
    }
  } else if (v->IsArray()) {
    std::vector<const rapidjson::Value*> elems;
    if (r.ExtractObjectArray(v, nullptr, &elems).ok()) {
      for (const auto* e : elems) Walk(r, e, depth + 1);
    }
  }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  kudu::JsonReader reader(std::string(reinterpret_cast<const char*>(data), size));
  if (!reader.Init().ok()) return -1;
  Walk(reader, reader.root(), 0);
  return 0;
}
