// Definitions of the two redaction globals that util/slice.cc and friends reference.
// They live in util/logging.cc upstream, which drags in the whole server runtime.
#include "kudu/util/logging.h"

namespace kudu {
thread_local bool tls_redact_user_data = true;
RedactContext g_should_redact = RedactContext::NONE;
const char* const kRedactionMessage = "<redacted>";
}  // namespace kudu
