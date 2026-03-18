/**
 * @file pqc_log.h
 * @brief Pluggable logging interface for the PQC Migration Engine.
 *
 * Default: logs to stderr. Override by defining PQC_LOG_CUSTOM before
 * including this header and providing your own log_message() implementation.
 */
#ifndef PQC_LOG_H
#define PQC_LOG_H

#include <stdarg.h>
#include <stdio.h>
#include <time.h>

#ifndef PQC_LOG_CUSTOM

/**
 * Default log_message: simple timestamped stderr output.
 * Matches the Higgaion log_message(level, module, fmt, ...) signature.
 */
static inline void log_message(const char *level, const char *module,
                               const char *fmt, ...) {
  time_t now = time(NULL);
  struct tm tm_buf;
  gmtime_r(&now, &tm_buf);
  char ts[20];
  strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%S", &tm_buf);

  fprintf(stderr, "[%s] [%s] [%s] ", ts, level, module);
  va_list ap;
  va_start(ap, fmt);
  /* flawfinder: ignore */
  vfprintf(stderr, fmt, ap);
  va_end(ap);
  fprintf(stderr, "\n");
}

#else
/* When PQC_LOG_CUSTOM is defined, the user provides log_message(). */
void log_message(const char *level, const char *module, const char *fmt, ...);
#endif

#endif /* PQC_LOG_H */
