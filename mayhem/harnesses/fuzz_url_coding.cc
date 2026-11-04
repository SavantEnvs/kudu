// Fuzzes Kudu's URL / base64 / HTML coding helpers (util/url-coding.cc), used by the web UI.
#include <cstddef>
#include <cstdint>
#include <sstream>
#include <string>

#include <fuzzer/FuzzedDataProvider.h>

#include "kudu/util/url-coding.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  FuzzedDataProvider p(data, size);
  const uint8_t sel = p.ConsumeIntegral<uint8_t>();
  const std::string s = p.ConsumeRemainingBytesAsString();
  std::string out;

  switch (sel % 5) {
    case 0:
      (void)kudu::UrlDecode(s, &out, false);
      break;
    case 1:
      (void)kudu::UrlDecode(s, &out, true);
      break;
    case 2: {
      // Not a round-trip check: UrlEncode emits '%A' / '%FFFFFF80' for bytes <0x10 / >=0x80.
      kudu::UrlEncode(s, &out, (sel & 0x80) != 0);
      std::string back;
      (void)kudu::UrlDecode(out, &back, (sel & 0x80) != 0);
      break;
    }
    case 3: {
      // Base64Decode DCHECKs on padded input whose dropped bytes are non-zero (non-canonical
      // padding, see mayhem/KNOWN_FINDINGS.md), so arbitrary decode runs on unpadded input only.
      if (s.find('=') == std::string::npos) (void)kudu::Base64Decode(s, &out);
      std::string enc;
      kudu::Base64Encode(s, &enc);
      std::string back;
      if (!kudu::Base64Decode(enc, &back) || back != s) __builtin_trap();
      break;
    }
    case 4:
      (void)kudu::EscapeForHtmlToString(s);
      break;
  }
  return 0;
}
