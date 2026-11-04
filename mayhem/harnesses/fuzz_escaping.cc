// Fuzzes Kudu's gutil escaping/unescaping routines (C escapes, base64/base32, quoted-printable).
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include <fuzzer/FuzzedDataProvider.h>

#include "kudu/gutil/strings/escaping.h"
#include "kudu/gutil/strings/stringpiece.h"

using namespace strings;
using std::string;
using std::vector;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  FuzzedDataProvider p(data, size);
  const uint8_t sel = p.ConsumeIntegral<uint8_t>();
  const string s = p.ConsumeRemainingBytesAsString();
  string out, err;

  switch (sel % 11) {
    case 0:
      (void)CUnescape(StringPiece(s), &out, &err);
      break;
    case 1:
      (void)CUnescapeForNullTerminatedString(StringPiece(s), &out, &err);
      break;
    case 2: {
      // CEscapeInternal prints a signed char >= 0x80 as an 11-digit octal/8-digit hex and overflows
      // its buffer (KNOWN_FINDINGS.md), so the round trip is only asserted for 7-bit input.
      bool ascii = true;
      for (char c : s) ascii &= static_cast<unsigned char>(c) < 0x80;
      string e = CEscape(s);
      string back;
      if (ascii && (!CUnescape(StringPiece(e), &back, &err) || back != s)) __builtin_trap();
      (void)Utf8SafeCEscape(s);
      (void)CHexEscape(s);
      (void)Utf8SafeCHexEscape(s);
      break;
    }
    case 3:
      (void)Base64Unescape(s.data(), static_cast<int>(s.size()), &out);
      break;
    case 4:
      (void)WebSafeBase64Unescape(s.data(), static_cast<int>(s.size()), &out);
      break;
    case 5: {
      string e;
      Base64Escape(s, &e);
      string back;
      if (!Base64Unescape(e.data(), static_cast<int>(e.size()), &back) || back != s) __builtin_trap();
      WebSafeBase64Escape(s, &e);
      WebSafeBase64EscapeWithPadding(s, &e);
      break;
    }
    case 6:
      (void)Base32Unescape(s.data(), static_cast<int>(s.size()), &out);
      break;
    case 7: {
      string e;
      if (Base32Escape(s, &e)) {
        string back;
        if (!Base32Unescape(e.data(), static_cast<int>(e.size()), &back) || back != s) __builtin_trap();
      }
      break;
    }
    case 8: {
      vector<char> dest(s.size() + 1);
      (void)QuotedPrintableUnescape(s.data(), static_cast<int>(s.size()), dest.data(),
                                    static_cast<int>(dest.size()));
      (void)QEncodingUnescape(s.data(), static_cast<int>(s.size()), dest.data(),
                              static_cast<int>(dest.size()));
      break;
    }
    case 9: {
      vector<char> dest(s.size() * 2 + 1);
      (void)EscapeStrForCSV(s.c_str(), dest.data(), static_cast<int>(dest.size()));
      break;
    }
    case 10: {
      (void)UnescapeCEscapeString(s, &out);
      (void)UnescapeCEscapeString(s);
      break;
    }
  }
  return 0;
}
