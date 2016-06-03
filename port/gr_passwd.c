#ifdef TEST
#include <grp.h>

int main()
{
	struct group grp = {};
	char *passwd;
	passwd = grp.grp_passwd;
}
#else
typedef int x;
#endif
