#include "util.h"

const char *program_invocation_name, *program_invocation_short_name;

void init_program_invocation_name(const char *x)
{
	size_t i;
	program_invocation_name = x;
	program_invocation_short_name = x;
	for(i = 0; x[i]; i++) if(x[i] == '/') program_invocation_short_name = x+i+1;
}
