#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include "util.h"

noreturn void die()
{
	char buf[2048];
	if(strerror_r(errno, buf, sizeof buf)) {
		snprintf(buf, sizeof buf, "unknown error");
	}
	die_fmt("%s", buf);
	exit(1);
}

noreturn void die_fmt(const char *fmt, ...)
{
	va_list ap;
	fprintf(stderr, "%s: ", program_invocation_short_name);
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fprintf(stderr, "\n");
	exit(1);
}
