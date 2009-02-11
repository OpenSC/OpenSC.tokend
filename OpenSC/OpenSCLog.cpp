#include "OpenSCLog.h"
#include <stdio.h>
#include <string.h>

const static char file[] = "/tmp/opensc_tokend.log";

/////////////////////////////////
// Turn off logging by default //
/////////////////////////////////
bool __enabled = false;

void otdEnableLogging(bool enable)
{
	__enabled = enable;
}

void otdLog(const char *format, ...)
{
	if (!__enabled)
		return;

	va_list argp;
	FILE *f = fopen(file, "a");

	if (f) {
		va_start(argp, format);
		vfprintf(f, format, argp);
		va_end(argp);

		fclose(f);
	}
}

void otdLogHex(const char *msg, const unsigned char *buf, size_t len)
{
	if (!__enabled)
		return;

	FILE *f = fopen(file, "a");
	
	if (f) {
		fprintf(f, "%s (%d bytes):", (msg ? msg : "hex buf"), len);
		if (len > 16)
			len = 16;
		char str[40];
		str[0] = 0;
		for (size_t i = 0; i < len; i++)
			sprintf(str + (3 * i), " %02X", buf[i]);
		strcat(str, "\n");
		fprintf(f, str);

		fclose(f);
	}
}

void otdLogErrWhere(const char *msg, int err, const char *where, int line)
{
	if (!__enabled)
		return;

	FILE *f = fopen(file, "a");
	
	if (f) {
		fprintf(f, "ERR %s (%s:%d): err = %d (0x%0x)\n", (msg ? msg : ""), where, line, err, err);

		fclose(f);
	}
}

