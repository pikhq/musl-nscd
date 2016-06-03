#ifdef TEST
#include <pwd.h>

int main()
{
	struct passwd pwd = {};
	char *passwd;
	passwd = pwd.pw_passwd;
}
#else
typedef int x;
#endif
