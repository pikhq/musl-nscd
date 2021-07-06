#include "modules.h"

enum nss_status cache_getpwnam_r(const char *name, struct passwd *p, char *buf, size_t buf_len, int *err)
{
	return NSS_STATUS_NOTFOUND;
}

enum nss_status cache_getpwuid_r(uid_t id, struct passwd *p, char *buf, size_t buf_len, int *err)
{
	return NSS_STATUS_NOTFOUND;
}

enum nss_status cache_getgrnam_r(const char *name, struct group *g, char *buf, size_t buf_len, int *err)
{
	return NSS_STATUS_NOTFOUND;
}

enum nss_status cache_getgrgid_r(gid_t id, struct group *g, char *buf, size_t buf_len, int *err)
{
	return NSS_STATUS_NOTFOUND;
}

enum nss_status cache_initgroups_dyn(const char *name, gid_t id, long *end, long *alloc, gid_t **grps, long maxn, int *err)
{
	return NSS_STATUS_NOTFOUND;
}

#define CACHE_ON_STATUS {ACT_RETURN, ACT_CONTINUE, ACT_CONTINUE, ACT_CONTINUE}
struct mod_passwd cache_modp =
	{ .nss_getpwnam_r = cache_getpwnam_r, .nss_getpwuid_r = cache_getpwuid_r, .on_status = CACHE_ON_STATUS };
struct mod_group cache_modg =
	{ .nss_getgrnam_r = cache_getgrnam_r, .nss_getgrgid_r = cache_getgrgid_r,
	  .nss_initgroups_dyn = cache_initgroups_dyn, .on_status = CACHE_ON_STATUS };

int init_caches(void)
{
	return 0;
}
