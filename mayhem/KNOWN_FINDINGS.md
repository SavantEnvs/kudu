# Known findings and harness decisions

Targets compile the Kudu sources they fuzz directly (see `build.sh`); Kudu's CMake/thirdparty build is not
available air-gapped. Kudu itself is built `-fsigned-char` on aarch64 and signed-by-default on x86_64.

## Real defects the targets reach
- `strings::Base64Unescape` (`src/kudu/gutil/strings/escaping.cc`, `Base64UnescapeInternal`): a
  signed `char` indexes the decode table, so any byte >= 0x80 reads out of bounds
  (ASan global-buffer-overflow; crash input `\x81\x9d`). `fuzz_escaping` reports it.
- `kudu::Base64Decode` (`util/url-coding.cc`): `DCHECK_EQ('\0', *it)` fires for padded input whose
  dropped bytes are non-zero (non-canonical padding). `fuzz_url_coding` only decodes unpadded
  input to stay clear of it; the encode/decode round trip is still checked.
- `kudu::BitReader::GetVlqInt` (`util/bit-stream-utils.inline.h:203`): `(byte & 0x7F) << shift` is a
  signed-int shift whose `shift` grows by 7 per byte, and the only bound is
  `DCHECK_LE(++num_bytes, MAX_VLQ_BYTE_LEN)` *after* the shift. A VLQ longer than 4 bytes in an untrusted RLE
  run header therefore trips UBSan's halting shift check (`shift >= 28`) before the DCHECK can fire. This is
  the dominant `fuzz_rle` defect (10 of its 11 reported ones) and is valid on malformed cfile data.
- `RleDecoder::ReadHeader` (`util/rle-encoding.h:240`): `literal_count_ = (indicator_value >> 1) * 8` is a
  signed `int32_t` multiplication that overflows for a literal-run indicator >= 2^28 (UBSan halting
  signed-integer-overflow). A single `fuzz_rle` defect, reached through the same malformed run header as the
  `GetVlqInt` one.
- `RleDecoder<bool,1>::Get` (`util/rle-encoding.h:267`): `DCHECK(result)` fires when a repeated run's value is
  truncated, and `DCHECK_GT(repeat_count_, 0)` on a zero run indicator. One `fuzz_rle` defect.
- `strings::CEscape` / `CHexEscape` / `Utf8SafeCEscape` (`src/kudu/gutil/strings/escaping.cc:542`,
  `CEscapeInternal`): `sprintf(dest + used, "\\%03o" or "\\x%02x", *src)` passes a signed `char` >= 0x80
  promoted to `int`, which prints as `37777777600` / `ffffff80` (11 / 8 characters) into a slot sized for 4, so
  the 4-bytes-per-input-byte buffer overflows (ASan heap-buffer-overflow). Any input containing a byte >= 0x80
  triggers it, e.g. the 2-byte `\x80\x02` for `fuzz_escaping` (the selector is its last byte); reproduced with
  `fuzz_escaping-standalone`. `Utf8SafeCEscape` is hit too because its `*src < 0x80` test is also on a signed
  `char`. `fuzz_escaping` reports it. The harness's former `CUnescape(CEscape(s)) == s` trap on non-ASCII input
  was a downstream symptom of this bug (the escaped text is wrong), so the round trip is now asserted for 7-bit
  input only (3000 random 7-bit inputs round-trip cleanly); `CEscape` is still called on every input so the
  overflow stays reachable.

## Deliberate harness choices
- `atoi_kmgt()` is not fuzzed: it `LOG(FATAL)`s on an unknown suffix by design.
- `RleDecoder::Skip` is not driven past the end of data (documented precondition, `DCHECK`ed).
- `UrlEncode`/`UrlDecode` is not asserted to round-trip: `UrlEncode` emits `%A` for bytes < 0x10 and
  `%FFFFFF80` for bytes >= 0x80 (signed `char` streamed as `uint32_t`), which `UrlDecode` does not invert.
- UBSan `alignment` and `pointer-overflow` are relaxed (`-fno-sanitize=`) on the Kudu objects: gutil's
  hash and string code use benign unaligned loads and pointer arithmetic. ASan and the rest of UBSan halt.
