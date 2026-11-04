// Fuzzes Kudu's varint decoders (util/coding.cc, util/memcmpable_varint.cc, util/group_varint-inl.h).
#include <cstddef>
#include <cstdint>
#include <vector>

#include <fuzzer/FuzzedDataProvider.h>

#include "kudu/util/coding.h"
#include "kudu/util/faststring.h"
#include "kudu/util/group_varint-inl.h"
#include "kudu/util/memcmpable_varint.h"
#include "kudu/util/slice.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  FuzzedDataProvider p(data, size);
  const uint8_t sel = p.ConsumeIntegral<uint8_t>();
  const std::vector<uint8_t> buf = p.ConsumeRemainingBytes<uint8_t>();
  kudu::Slice in(buf.data(), buf.size());

  switch (sel % 6) {
    case 0: {
      uint32_t v;
      while (kudu::GetVarint32(&in, &v)) {}
      break;
    }
    case 1: {
      uint64_t v;
      while (kudu::GetVarint64(&in, &v)) {}
      break;
    }
    case 2: {
      kudu::Slice out;
      while (kudu::GetLengthPrefixedSlice(&in, &out)) {}
      break;
    }
    case 3: {
      uint64_t v;
      while (kudu::GetMemcmpableVarint64(&in, &v)) {
        kudu::faststring enc;
        kudu::PutMemcmpableVarint64(&enc, v);
        kudu::Slice s(enc.data(), enc.size());
        uint64_t back = 0;
        if (!kudu::GetMemcmpableVarint64(&s, &back) || back != v) __builtin_trap();
      }
      break;
    }
    case 4: {
      uint32_t a, b, c, d;
      const uint8_t* ptr = buf.data();
      const uint8_t* end = buf.data() + buf.size();
      while (ptr < end && kudu::coding::DecodeGroupVarInt32_GetGroupSize(ptr) <= static_cast<size_t>(end - ptr)) {
        ptr = kudu::coding::DecodeGroupVarInt32_SlowButSafe(ptr, &a, &b, &c, &d);
      }
      break;
    }
    case 5: {
      kudu::Slice s(buf.data(), buf.size());
      uint32_t v32 = 0;
      uint64_t v64 = 0;
      (void)kudu::GetVarint32Ptr(buf.data(), buf.data() + buf.size(), &v32);
      (void)kudu::GetVarint64Ptr(buf.data(), buf.data() + buf.size(), &v64);
      break;
    }
  }
  return 0;
}
