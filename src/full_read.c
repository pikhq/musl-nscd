#include <unistd.h>
#include <errno.h>
#include "util.h"

int full_read(int fd, char *buf, size_t n)
{
	ssize_t cnt;
	while(n) {
		cnt = read(fd, buf, n);
		if(cnt < 0) {
			if(errno == EINTR) continue;
			return -1;
		}
		buf += cnt;
		n -= cnt;
	}
	return 0;
}
