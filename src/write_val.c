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
	uint32_t head[PW_LEN] = {
		NSCDVERSION
	};
	size_t namelen = 0, passwdlen = 0, gecoslen = 0, dirlen = 0, shelllen = 0;
	char *name_fld, *passwd_fld, *gecos_fld, *dir_fld, *shell_fld;

	if(!pwd) {
		if(swap) swap32(head[0]);
		return full_write(fd, (char*)head, sizeof(head));
	}

	name_fld = pwd->pw_name ? pwd->pw_name : "";
	namelen = strlen(name_fld) + 1;
#ifdef HAVE_PW_PASSWD
	passwd_fld = pwd->pw_passwd ? pwd->pw_passwd : "";
#else
	passwd_fld = "";
#endif
	passwdlen = strlen(passwd_fld) + 1;
#ifdef HAVE_PW_GECOS
	gecos_fld = pwd->pw_gecos ? pwd->pw_gecos : "";
#else
	gecos_fld = "";
#endif
	gecoslen = strlen(gecos_fld) + 1;
	dir_fld = pwd->pw_dir ? pwd->pw_dir : "";
	dirlen = strlen(dir_fld) + 1;
	shell_fld = pwd->pw_shell ? pwd->pw_shell : "";
	shelllen = strlen(shell_fld) + 1;

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

	if(namelen) if(full_write(fd, name_fld, namelen) < 0) return -1;
	if(passwdlen) if(full_write(fd, passwd_fld, passwdlen) < 0) return -1;
	if(gecoslen) if(full_write(fd, gecos_fld, gecoslen) < 0) return -1;
	if(dirlen) if(full_write(fd, dir_fld, dirlen) < 0) return -1;
	if(shelllen) if(full_write(fd, shell_fld, shelllen) < 0) return -1;
	return 0;
}

int write_grp(int fd, int swap, struct group *grp)
{
	uint32_t head[GR_LEN] = {
		NSCDVERSION
	};
	size_t namelen = 0, passwdlen = 0, memcnt = 0, i;
	char *name_fld, *passwd_fld;
	if(!grp) {
		if(swap) swap32(head[0]);
		return full_write(fd, (char*)head, sizeof(head));
	}
	
	name_fld = grp->gr_name ? grp->gr_name : "";
	namelen = strlen(name_fld) + 1;
#ifdef HAVE_GR_PASSWD
	passwd_fld = grp->gr_passwd ? grp->gr_passwd : "";
#else
	passwd_fld = "";
#endif
	passwdlen = strlen(passwd_fld) + 1;

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

	for(i = 0; grp->gr_mem[i]; i++) {
		uint32_t len, swaplen;
		swaplen = len = strlen(grp->gr_mem[i]) + 1;
		if(swap) swaplen = swap32(swaplen);
		if(full_write(fd, (char*)&swaplen, sizeof(uint32_t)) < 0) return -1;
	}
	if(namelen) if(full_write(fd, name_fld, namelen) < 0) return -1;
	if(passwdlen) if(full_write(fd, passwd_fld, passwdlen) < 0) return -1;
	for(i = 0; grp->gr_mem[i]; i++) {
		uint32_t len = strlen(grp->gr_mem[i]) + 1;
		if(full_write(fd, grp->gr_mem[i], len) < 0) return -1;
	}
	return 0;
}

int write_groups(int fd, int swap, size_t len, gid_t *groups)
{
	uint32_t head[INITGR_LEN] = {
		NSCDVERSION
	};
	size_t i;
	if(len > UINT32_MAX) {
		return -2;
	}
	head[INITGRNGRPS] = len;
	for(i = 0; i < len; i++) {
		if(groups[i] == (gid_t)-1) {
			head[INITGRNGRPS]--;
			continue;
		}
		if(groups[i] < 0 || groups[i] > UINT32_MAX)
			return -2;
	}
	head[INITGRFOUND] = !!len;

	if(swap) {
		for(i = 0; i < INITGR_LEN; i++) {
			head[i] = swap32(head[i]);
		}
	}

	if(full_write(fd, (char*)head, sizeof head) < 0) return -1;

	for(i = 0; i < len; i++) {
		if(groups[i] == (gid_t)-1) continue;
		uint32_t tmp = swap ? swap32(groups[i]) : groups[i];
		if(full_write(fd, (char*)&tmp, sizeof(uint32_t)) < 0) return -1;
	}

	return 0;
}
