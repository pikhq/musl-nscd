#ifdef TEST
#include <pwd.h>

int main()
{
	struct passwd pwd = {};
	char *gecos;
	gecos = pwd.pw_gecos;
}
#else
typedef int x;
#endif
