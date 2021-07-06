#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "modules.h"

static int cache = 0;
#define IS_CACHING if(!cache) { *err = 0; return NSS_STATUS_UNAVAIL; }
#define IS_CACHING_FOR_WRITE(storage_buffer) if(!cache) { free(storage_buffer); return -1; }

/* 10 minutes, stored as seconds */
#define CACHE_INVALIDATION_TIME (10 * 60)

/* max cache entries; TODO: make configurable */
#define CACHE_MAX_ENTRIES 100000
#define CACHE_INITIAL_ENTRIES 512

static time_t monotonic_seconds(void)
{
	struct timespec res;
	if(clock_gettime(CLOCK_MONOTONIC, &res)) {
		/* this should never happen; abort? */
		perror("clock_gettime");
		return 0;
	}

	return res.tv_sec;
}

static bool compare_timestamps(time_t t, time_t now)
{
	return (now - t) < CACHE_INVALIDATION_TIME;
}

/* returns true if the timestamp is still valid */
static bool validate_timestamp(time_t t)
{
	return compare_timestamps(t, monotonic_seconds());
}

/* increment len and store the index for that new member in index */
static bool cache_increment_len(size_t *len, size_t *size, size_t sizeof_element, void **data, size_t *index)
{
	/* first simply try to increment len */
	if(*len < *size) {
		*index = (*len)++;
		return true;
	}

	/* otherwise, try to increase cache size */

	if(*size >= CACHE_MAX_ENTRIES)
		return false;

	size_t new_size;
	/* memory growth factor is 1.5x; see socket_handle.c for a similar impl */
	if(*size > CACHE_MAX_ENTRIES - *size/2)
		new_size = CACHE_MAX_ENTRIES;
	else
		new_size = *size + *size/2;

	/* XXX: doesn't check for multiplication overflow */
	void *tmp = realloc(*data, new_size * sizeof_element);
	if(!tmp)
		return false;

	*size = new_size;
	*data = tmp;
	*index = (*len)++;
	return true;
}

struct passwd_result {
	struct passwd p;
	char *b;
	/* for validation */
	time_t t;
};
struct passwd_cache {
	pthread_rwlock_t lock;
	struct passwd_result *res;
	size_t len, size;
};

static struct passwd_cache passwd_cache =
	{ .lock = PTHREAD_RWLOCK_INITIALIZER, .size = CACHE_INITIAL_ENTRIES };

enum nss_status cache_getpwnam_r(const char *name, struct passwd *p, char *buf, size_t buf_len, int *err)
{
	#define CACHE passwd_cache
	#define RESULT_TYPE passwd_result
	#define COMPARISON() (strcmp(res->p.pw_name, name) == 0)
	#define ARGUMENT p
	#include "cache_query.h"
}

enum nss_status cache_getpwuid_r(uid_t id, struct passwd *p, char *buf, size_t buf_len, int *err)
{
	#define CACHE passwd_cache
	#define RESULT_TYPE passwd_result
	#define COMPARISON() (res->p.pw_uid == id)
	#define ARGUMENT p
	#include "cache_query.h"
}

/* this function copies the passwd struct p points to and
 * takes ownership of the buffer b points to */
int cache_passwd_add(struct passwd *p, char *b)
{
	#define CACHE passwd_cache
	#define RESULT_TYPE passwd_result
	#define COMPARISON() (res->p.pw_uid == p->pw_uid)
	#define ARGUMENT p
	#include "cache_add.h"
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
	#define MALLOC_CACHE(cache) do{ if(!(cache.res = malloc(cache.size * sizeof(*cache.res)))) return -1; }while(0)
	MALLOC_CACHE(passwd_cache);

	cache = 1;
	return 0;
}
