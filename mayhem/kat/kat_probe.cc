// Known-answer probe over the same Kudu sources the fuzz targets exercise. Built WITHOUT sanitizers
// and dynamically linked so mayhem/test.sh can assert its exact stdout (and fail if it is neutered).
#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

#include <rapidjson/document.h>

#include "kudu/gutil/strings/escaping.h"
#include "kudu/gutil/strings/numbers.h"
#include "kudu/util/coding.h"
#include "kudu/util/faststring.h"
#include "kudu/util/group_varint-inl.h"
#include "kudu/util/jsonreader.h"
#include "kudu/util/memcmpable_varint.h"
#include "kudu/util/rle-encoding.h"
#include "kudu/util/slice.h"
#include "kudu/util/url-coding.h"
#include "kudu/util/version_util.h"

static std::string Hex(const uint8_t* p, size_t n) {
  static const char* d = "0123456789abcdef";
  std::string s;
  for (size_t i = 0; i < n; i++) { s += d[p[i] >> 4]; s += d[p[i] & 15]; }
  return s;
}

int main() {
  int32_t i32 = 0; uint64_t u64 = 0; int64_t i64 = 0;
  bool ok = safe_strto32("-12345", &i32);
  printf("strto32 %d %d\n", ok, i32);
  ok = safe_strtou64("18446744073709551615", &u64);
  printf("strtou64 %d %llu\n", ok, static_cast<unsigned long long>(u64));
  ok = safe_strto64("9223372036854775808", &i64);
  printf("strto64_overflow %d\n", ok);
  printf("itoa_commas %s\n", SimpleItoaWithCommas(1234567).c_str());
  printf("itoa %s\n", SimpleItoa(static_cast<int64_t>(-9007199254740993LL)).c_str());

  printf("cescape %s\n", strings::CEscape(std::string("a\n\t\"b\\\x01", 7)).c_str());
  std::string un;
  strings::CUnescape("a\\n\\x41\\101", &un, nullptr);
  printf("cunescape %s\n", Hex(reinterpret_cast<const uint8_t*>(un.data()), un.size()).c_str());

  std::string enc;
  kudu::UrlEncode("hello world&a=b/c", &enc, false);
  printf("urlencode %s\n", enc.c_str());
  std::string dec;
  bool dok = kudu::UrlDecode("hello%20world%26a%3Db+c", &dec, false);
  printf("urldecode %d %s\n", dok, dec.c_str());
  dok = kudu::UrlDecode("a+b%2B", &dec, true);
  printf("urldecode_hive %d %s\n", dok, dec.c_str());
  kudu::Base64Encode("hello, kudu", &enc);
  printf("base64 %s\n", enc.c_str());
  dok = kudu::Base64Decode("aGVsbG8sIGt1ZHU=", &dec);
  printf("base64dec %d %s\n", dok, dec.c_str());
  printf("html %s\n", kudu::EscapeForHtmlToString("<a href=\"x\">&</a>").c_str());

  kudu::faststring f;
  kudu::PutVarint32(&f, 300);
  kudu::PutVarint64(&f, 1ULL << 40);
  printf("varint %s\n", Hex(f.data(), f.size()).c_str());
  kudu::Slice in(f.data(), f.size());
  uint32_t v32 = 0; uint64_t v64 = 0;
  bool g1 = kudu::GetVarint32(&in, &v32), g2 = kudu::GetVarint64(&in, &v64);
  printf("varint_dec %d %u %d %llu %zu\n", g1, v32, g2, static_cast<unsigned long long>(v64), in.size());
  kudu::faststring m;
  kudu::PutMemcmpableVarint64(&m, 1000);
  printf("memcmpable %s\n", Hex(m.data(), m.size()).c_str());
  kudu::faststring gv;
  kudu::coding::AppendGroupVarInt32(&gv, 1, 256, 65536, 16777216);
  printf("groupvarint %s\n", Hex(gv.data(), gv.size()).c_str());

  kudu::Version v;
  kudu::Status s = kudu::ParseVersion("3.1.2-SNAPSHOT", &v);
  printf("version %d %s\n", s.ok(), s.ok() ? v.ToString().c_str() : "-");
  printf("version_bad %d\n", kudu::ParseVersion("x.y", &v).ok());

  kudu::JsonReader r("{\"n\": 42, \"s\": \"kudu\", \"a\": [1,2,3]}");
  s = r.Init();
  int32_t n = 0; std::string str;
  bool nok = s.ok() && r.ExtractInt32(r.root(), "n", &n).ok();
  bool sok = s.ok() && r.ExtractString(r.root(), "s", &str).ok();
  printf("json %d %d %d %s\n", s.ok(), nok, n, sok ? str.c_str() : "-");
  kudu::JsonReader bad("{\"n\": ");
  printf("json_bad %d\n", bad.Init().ok());

  kudu::faststring rle;
  kudu::RleEncoder<uint8_t, 3> e(&rle);
  for (int i = 0; i < 8; i++) e.Put(1);
  for (int i = 0; i < 8; i++) e.Put(i % 8);
  e.Flush();
  printf("rle %s\n", Hex(rle.data(), rle.size()).c_str());
  kudu::RleDecoder<uint8_t, 3> d(rle.data(), static_cast<int>(rle.size()));
  std::string got;
  uint8_t x;
  while (d.Get(&x)) got += static_cast<char>('0' + x);
  printf("rle_dec %s\n", got.c_str());
  return 0;
}
