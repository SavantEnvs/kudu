// Fuzzes Kudu's RLE/bit-packing decoder (util/rle-encoding.h) over attacker-controlled bytes,
// as used by the cfile RLE/bool/dictionary block decoders; also round-trips the encoder.
#include <cstddef>
#include <cstdint>
#include <vector>

#include <fuzzer/FuzzedDataProvider.h>

#include "kudu/util/faststring.h"
#include "kudu/util/rle-encoding.h"

namespace {

template <typename T, uint8_t W>
void DecodeAll(const uint8_t* buf, size_t len, uint8_t ops) {
  kudu::RleDecoder<T, W> dec(buf, static_cast<int>(len));
  T v;
  switch (ops % 4) {
    case 0:
      while (dec.Get(&v)) {}
      break;
    case 1: {
      size_t total = 0;
      while (true) {
        size_t n = dec.GetNextRun(&v, 1 + (total % 61));
        if (n == 0) break;
        total += n;
      }
      break;
    }
    case 2: {
      // Skip() DCHECKs that the caller never skips past the end of the data, so count with Get().
      size_t avail = 0;
      while (dec.Get(&v) && avail < 100000) avail++;
      kudu::RleDecoder<T, W> dec2(buf, static_cast<int>(len));
      size_t guard = 0;
      while (avail > 0 && guard++ < 4096) {
        size_t n = 1 + (guard % 33);
        if (n > avail) n = avail;
        avail -= dec2.Skip(n);
      }
      break;
    }
    case 3: {
      size_t n = 0;
      while (dec.Get(&v)) {
        if (++n % 5 == 0) dec.RewindOne();
        if (n > 100000) break;
      }
      break;
    }
  }
}

template <typename T, uint8_t W>
void RoundTrip(FuzzedDataProvider* p) {
  const size_t n = p->ConsumeIntegralInRange<size_t>(0, 512);
  std::vector<T> vals;
  const uint64_t mask = W == 64 ? ~0ULL : ((1ULL << W) - 1);
  for (size_t i = 0; i < n; i++) {
    T v = static_cast<T>(p->ConsumeIntegral<uint64_t>() & mask);
    size_t run = p->ConsumeIntegralInRange<size_t>(1, 20);
    for (size_t j = 0; j < run && vals.size() < 4096; j++) vals.push_back(v);
  }
  kudu::faststring buf;
  kudu::RleEncoder<T, W> enc(&buf);
  for (const T& v : vals) enc.Put(v);
  enc.Flush();
  kudu::RleDecoder<T, W> dec(buf.data(), static_cast<int>(buf.size()));
  for (const T& want : vals) {
    T got;
    if (!dec.Get(&got) || got != want) __builtin_trap();
  }
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (size < 2) return -1;
  FuzzedDataProvider p(data, size);
  const uint8_t cfg = p.ConsumeIntegral<uint8_t>();
  const uint8_t ops = p.ConsumeIntegral<uint8_t>();
  const bool round_trip = (cfg & 0x80) != 0;
  std::vector<uint8_t> rest = p.ConsumeRemainingBytes<uint8_t>();
  // A real caller never hands the decoder a null buffer; keep the pointer valid for empty input.
  rest.reserve(1);
  FuzzedDataProvider q(rest.data(), rest.size());
  switch (cfg & 0x0f) {
    case 0:  round_trip ? RoundTrip<bool, 1>(&q)       : DecodeAll<bool, 1>(rest.data(), rest.size(), ops); break;
    case 1:  round_trip ? RoundTrip<uint8_t, 3>(&q)    : DecodeAll<uint8_t, 3>(rest.data(), rest.size(), ops); break;
    case 2:  round_trip ? RoundTrip<uint8_t, 8>(&q)    : DecodeAll<uint8_t, 8>(rest.data(), rest.size(), ops); break;
    case 3:  round_trip ? RoundTrip<uint16_t, 5>(&q)   : DecodeAll<uint16_t, 5>(rest.data(), rest.size(), ops); break;
    case 4:  round_trip ? RoundTrip<uint16_t, 16>(&q)  : DecodeAll<uint16_t, 16>(rest.data(), rest.size(), ops); break;
    case 5:  round_trip ? RoundTrip<uint32_t, 7>(&q)   : DecodeAll<uint32_t, 7>(rest.data(), rest.size(), ops); break;
    case 6:  round_trip ? RoundTrip<uint32_t, 13>(&q)  : DecodeAll<uint32_t, 13>(rest.data(), rest.size(), ops); break;
    case 7:  round_trip ? RoundTrip<uint32_t, 32>(&q)  : DecodeAll<uint32_t, 32>(rest.data(), rest.size(), ops); break;
    case 8:  round_trip ? RoundTrip<int32_t, 17>(&q)   : DecodeAll<int32_t, 17>(rest.data(), rest.size(), ops); break;
    case 9:  round_trip ? RoundTrip<uint64_t, 21>(&q)  : DecodeAll<uint64_t, 21>(rest.data(), rest.size(), ops); break;
    case 10: round_trip ? RoundTrip<uint64_t, 64>(&q)  : DecodeAll<uint64_t, 64>(rest.data(), rest.size(), ops); break;
    default: round_trip ? RoundTrip<uint32_t, 2>(&q)   : DecodeAll<uint32_t, 2>(rest.data(), rest.size(), ops); break;
  }
  return 0;
}
