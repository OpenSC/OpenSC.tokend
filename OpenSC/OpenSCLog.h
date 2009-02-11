#ifndef __OPENSCLOG_H__
#define __OPENSCLOG_H__

#include <stdarg.h>
#include <stdlib.h>

void otdEnableLogging(bool enable);

void otdLog(const char *format, ...);

void otdLogHex(const char *msg, const unsigned char *buf, size_t len);

#define otdLogErr(msg, err) otdLogErrWhere(msg, err, __FILE__, __LINE__)

void otdLogErrWhere(const char *msg, int err, const char *where, int line);
#endif
