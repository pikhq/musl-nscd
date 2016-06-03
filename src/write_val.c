#include <pwd.h>
#include <grp.h>
#include <limits.h>
#include <stdint.h>
#include <string.h>
#include "config.h"
#include "util.h"
#include "nscd.h"

int write_pwd(int fd, int swap, struct passwd *pwd)
{
	uint32_t head[9] = {
		NSCDVERSION
	};
	size_t namelen, passwdlen = 0, gecoslen = 0, dirlen, shelllen;

	if(!pwd) {
		if(swap) swap32(head[0]);
		return full_write(fd, (char*)head, sizeof(head));
	}

	namelen = strlen(pwd->pw_name) + 1;
#ifdef HAVE_PW_PASSWD
	passwdlen = strlen(pwd->pw_passwd) + 1;
#endif
#ifdef HAVE_PW_GECOS
	gecoslen = strlen(pwd->pw_gecos) + 1;
#endif
	dirlen = strlen(pwd->pw_dir) + 1;
	shelllen = strlen(pwd->pw_shell) + 1;

	if(   namelen > UINT32_MAX || passwdlen > UINT32_MAX
	   || gecoslen > UINT32_MAX || dirlen > UINT32_MAX
	   || shelllen > UINT32_MAX
	   || pwd->pw_uid < 0 || pwd->pw_uid > UINT32_MAX
	   || pwd->pw_gid < 0 || pwd->pw_gid > UINT32_MAX)
		return -2;

	head[PWFOUND] = 1;
	head[PWNAMELEN] = namelen;
	head[PWPASSWDLEN] = passwdlen;
	head[PWUID] = pwd->pw_uid;
	head[PWGID] = pwd->pw_gid;
	head[PWGECOSLEN] = gecoslen;
	head[PWDIRLEN] = dirlen;
	head[PWSHELLLEN] = shelllen;

	if(swap) {
		int i;
		for(i = 0; i < PW_LEN; i++)
			head[i] = swap32(head[i]);
	}

	if(full_write(fd, (char*)head, sizeof head) < 0) return -1;

	if(full_write(fd, pwd->pw_name, namelen) < 0) return -1;
#ifdef HAVE_PW_PASSWD
	if(full_write(fd, pwd->pw_passwd, passwdlen) < 0) return -1;
#endif
#ifdef HAVE_PW_GECOS
	if(full_write(fd, pwd->pw_gecos, gecoslen) < 0) return -1;
#endif
	if(full_write(fd, pwd->pw_dir, dirlen) < 0) return -1;
	if(full_write(fd, pwd->pw_shell, shelllen) < 0) return -1;
	return 0;
}

int write_grp(int fd, int swap, struct group *grp)
{
	uint32_t head[GR_LEN] = {
		NSCDVERSION
	};
	size_t namelen, passwdlen = 0, memcnt = 0, i;
	if(!grp) {
		if(swap) swap32(head[0]);
		return full_write(fd, (char*)head, sizeof(head));
	}

	namelen = strlen(grp->gr_name) + 1;
#ifdef HAVE_GR_PASSWD
	passwdlen = strlen(grp->gr_passwd) + 1;
#endif
	for(i = 0; grp->gr_mem[i]; i++) {
		memcnt++;
#if SIZE_MAX > UINT32_MAX
		if(strnlen(grp->gr_mem[i], UINT32_MAX) + 1 >= UINT32_MAX)
			return -2;
#endif
	}

	if(   namelen > UINT32_MAX || passwdlen > UINT32_MAX
	   || memcnt > UINT32_MAX
	   || grp->gr_gid < 0 || grp->gr_gid > UINT32_MAX) {
		return -2;
	}

	head[GRFOUND] = 1;
	head[GRNAMELEN] = namelen;
	head[GRPASSWDLEN] = passwdlen;
	head[GRGID] = grp->gr_gid;
	head[GRMEMCNT] = memcnt;

	if(swap) {
		for(i = 0; i < GR_LEN; i++) {
			head[i] = swap32(head[i]);
		}
	}

	if(full_write(fd, (char*)head, sizeof head) < 0) return -1;

	if(full_write(fd, grp->gr_name, namelen) < 0) return -1;
#ifdef HAVE_GR_PASSWD
	if(full_write(fd, grp->gr_passwd, passwdlen) < 0) return -1;
#endif
	for(i = 0; i < memcnt; i++) {
		uint32_t len, swaplen;
		swaplen = len = strlen(grp->gr_mem[i]) + 1;
		if(swap) swaplen = swap32(swaplen);
		if(full_write(fd, (char*)&swaplen, sizeof(uint32_t)) < 0) return -1;
		if(full_write(fd, grp->gr_mem[i], len) < 0) return -1;
	}
	return 0;
}
