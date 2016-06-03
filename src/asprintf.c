#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>

#include "util.h"

int asprintf(char **s, const char *fmt, ...)
{
	int ret, l;
	va_list ap;
	va_start(ap, fmt);
	l = vsnprintf(0, 0, fmt, ap);
	va_end(ap);
	if(l < 0 || !(*s = malloc(l+1U))) return -1;
	va_start(ap, fmt);
	ret = vsnprintf(*s, l+1U, fmt, ap);
	va_end(ap);
	return ret;
}
