// Fuzzes Kudu's gutil string<->number parsing (safe_strto*, SimpleAtoi, ParseLeading*).
// atoi_kmgt() is deliberately not exercised: it LOG(FATAL)s on any unknown size suffix by design.
#include <cstddef>
#include <cstdint>
#include <string>

#include <fuzzer/FuzzedDataProvider.h>

#include "kudu/gutil/integral_types.h"
#include "kudu/gutil/strings/numbers.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  FuzzedDataProvider p(data, size);
  const uint8_t sel = p.ConsumeIntegral<uint8_t>();
  static const int kBases[] = {0, 2, 8, 10, 16, 36};
  const int base = kBases[p.ConsumeIntegralInRange<size_t>(0, 5)];
  const std::string s = p.ConsumeRemainingBytesAsString();

  int32 i32 = 0;
  int64 i64 = 0;
  uint32 u32 = 0;
  uint64 u64 = 0;
  double d = 0;
  float f = 0;
  switch (sel % 18) {
    case 0: (void)safe_strto32(s, &i32); break;
    case 1: (void)safe_strto64(s, &i64); break;
    case 2: (void)safe_strtou32(s, &u32); break;
    case 3: (void)safe_strtou64(s, &u64); break;
    case 4: (void)safe_strtod(s, &d); break;
    case 5: (void)safe_strtof(s, &f); break;
    case 6: (void)safe_strto32_base(s, &i32, base); break;
    case 7: (void)safe_strto64_base(s, &i64, base); break;
    case 8: (void)safe_strtou32_base(s, &u32, base); break;
    case 9: (void)safe_strtou64_base(s, &u64, base); break;
    case 10: (void)safe_strto32(s.data(), static_cast<int>(s.size()), &i32); break;
    case 11: (void)safe_strto64_base(s.data(), static_cast<int>(s.size()), &i64, base); break;
    case 12: (void)SimpleItoaWithCommas(static_cast<int32>(s.size()) * 1000003); break;
    case 13: {
      (void)ParseLeadingInt32Value(s, 0);
      (void)ParseLeadingUInt32Value(s, 0);
      (void)ParseLeadingDec32Value(s, 0);
      (void)ParseLeadingUDec32Value(s, 0);
      (void)ParseLeadingInt64Value(s, 0);
      (void)ParseLeadingUInt64Value(s, 0);
      (void)ParseLeadingHex64Value(s, 0);
      (void)ParseLeadingDec64Value(s, 0);
      (void)ParseLeadingUDec64Value(s, 0);
      break;
    }
    case 14: {
      (void)ParseLeadingDoubleValue(s, 0);
      (void)ParseLeadingBoolValue(s, false);
      break;
    }
    case 15: {
      (void)SimpleAtoi(s, &i32);
      (void)SimpleAtoi(s, &i64);
      (void)SimpleAtoi(s, &u32);
      (void)SimpleAtoi(s, &u64);
      break;
    }
    case 16: {
      std::string t = s;
      ConsumeStrayLeadingZeroes(&t);
      (void)HexDigitsPrefix(s.c_str(), static_cast<int>(s.size() % 17));
      break;
    }
    case 17: {
      // Round trip: formatting a parsed value must parse back to the same value.
      if (safe_strto64(s, &i64)) {
        int64 back = 0;
        if (!safe_strto64(SimpleItoa(i64), &back) || back != i64) __builtin_trap();
      }
      (void)SimpleDtoa(d);
      (void)SimpleFtoa(f);
      break;
    }
  }
  return 0;
}
