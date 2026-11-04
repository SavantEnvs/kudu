// Fuzzes Kudu's version-string parser (util/version_util.cc), used for HMS/Ranger/Kerberos versions.
#include <cstddef>
#include <cstdint>
#include <string>

#include <fuzzer/FuzzedDataProvider.h>

#include "kudu/util/status.h"
#include "kudu/util/version_util.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  FuzzedDataProvider p(data, size);
  const std::string a = p.ConsumeRandomLengthString();
  const std::string b = p.ConsumeRemainingBytesAsString();
  kudu::Version va, vb;
  const bool ok_a = kudu::ParseVersion(a, &va).ok();
  const bool ok_b = kudu::ParseVersion(b, &vb).ok();
  if (ok_a) (void)va.ToString();
  if (ok_a && ok_b) {
    (void)(va == vb);
  }
  return 0;
}
