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

struct group_result {
	struct group g;
	char *b;
	/* for validation */
	time_t t;
};
struct group_cache {
	pthread_rwlock_t lock;
	struct group_result *res;
	size_t len, size;
};

static struct group_cache group_cache =
	{ .lock = PTHREAD_RWLOCK_INITIALIZER, .size = CACHE_INITIAL_ENTRIES };

enum nss_status cache_getgrnam_r(const char *name, struct group *g, char *buf, size_t buf_len, int *err)
{
	#define CACHE group_cache
	#define RESULT_TYPE group_result
	#define COMPARISON() (strcmp(res->g.gr_name, name) == 0)
	#define ARGUMENT g
	#include "cache_query.h"
}

enum nss_status cache_getgrgid_r(gid_t id, struct group *g, char *buf, size_t buf_len, int *err)
{
	#define CACHE group_cache
	#define RESULT_TYPE group_result
	#define COMPARISON() (res->g.gr_gid == id)
	#define ARGUMENT g
	#include "cache_query.h"
}

/* this function copies the group struct p points to and
 * takes ownership of the buffer b points to */
int cache_group_add(struct group *g, char *b)
{
	#define CACHE group_cache
	#define RESULT_TYPE group_result
	#define COMPARISON() (res->g.gr_gid == g->gr_gid)
	#define ARGUMENT g
	#include "cache_add.h"
}

struct initgroups_result {
	struct initgroups_res g;
	char *name;
	/* for validation */
	time_t t;
};
struct initgroups_cache {
	pthread_rwlock_t lock;
	struct initgroups_result *res;
	size_t len, size;
};

static struct initgroups_cache initgroups_cache =
	{ .lock = PTHREAD_RWLOCK_INITIALIZER, .size = CACHE_INITIAL_ENTRIES };

enum nss_status cache_initgroups_dyn(const char *name, gid_t id, long *end, long *alloc, gid_t **grps, long maxn, int *err)
{
	IS_CACHING

	enum nss_status ret = NSS_STATUS_NOTFOUND;

	pthread_rwlock_rdlock(&initgroups_cache.lock);

	for(size_t i = 0; i < initgroups_cache.len; i++) {
		struct initgroups_result *res = &initgroups_cache.res[i];
		if (strcmp(res->name, name) == 0) {
			if(!validate_timestamp(res->t)) {
				break;
			}

			/* to simplify memory management, we use either the provided buffer or
			 * realloc a new one. It would be ideal to use the cache buffer without
			 * copying or allocating memory, but that significantly complicates
			 * the return_result code */

			if(res->g.end > *alloc) {
				void *tmp = realloc(*grps, res->g.end * sizeof(gid_t));
				/* allow a fallback to NOTFOUND, though it's unlikely that the nss
				 * backend will succeed in the allocation either */
				if(!tmp) {
					*err = ENOMEM;
					break;
				}

				*alloc = res->g.end;
				*grps = tmp;
			}
			*end = res->g.end;
			memcpy(*grps, res->g.grps, res->g.end * sizeof(gid_t));
			ret = NSS_STATUS_SUCCESS;
			break;
		}
	}

	pthread_rwlock_unlock(&initgroups_cache.lock);
	return ret;
}

/* see cache_add.h for comments on the implementation strategy */
int cache_initgroups_add(struct initgroups_res *g, const char *name)
{
	IS_CACHING_FOR_WRITE(g->grps);

	int ret = 0;
	size_t i;
	bool found_outdated = false;

	pthread_rwlock_wrlock(&initgroups_cache.lock);

	time_t oldest = initgroups_cache.len > 0 ? initgroups_cache.res[0].t : 0;
	size_t oldest_i = 0;
	bool found_invalid = false;

	time_t now = monotonic_seconds();
	for(i = 0; i < initgroups_cache.len; i++) {
		struct initgroups_result *res = &initgroups_cache.res[i];

		if(!compare_timestamps(res->t, now)) {
			found_invalid = true;
			if(res->t < oldest) {
				oldest = res->t;
				oldest_i = i;
			}
		}

		if (strcmp(res->name, name) == 0) {
			if(compare_timestamps(res->t, now)) {
				goto cleanup;
			}
			found_outdated = true;
			break;
		}
	}

	/* if we are here, we are necessarily going to add something to the cache */
	struct initgroups_result *res;
	if(found_outdated) {
		res = &initgroups_cache.res[i];
		/* we need to free the underlying storage, but we reuse res->name */
		free(res->g.grps);
	} else {
		char *namedup = strdup(name);
		if (!namedup)
			goto cleanup;

		if(found_invalid) {
			/* overwrite invalid entry */
			i = oldest_i;
			res = &initgroups_cache.res[i];
			/* we need to free all the underlying storage */
			free(res->name);
			free(res->g.grps);
		} else {
			void *tmp_pointer = initgroups_cache.res;
			if(!cache_increment_len(&initgroups_cache.len, &initgroups_cache.size, sizeof(*initgroups_cache.res), &tmp_pointer, &i)) {
				free(namedup);
				goto cleanup;
			}
			initgroups_cache.res = tmp_pointer;
		}

		res = &initgroups_cache.res[i];
		res->name = namedup;
	}
	memcpy(&res->g, g, sizeof(*g));
	res->t = now;
	g->grps = 0;

cleanup:
	pthread_rwlock_unlock(&initgroups_cache.lock);
	/* if insertion fails, we should free the buffer */
	free(g->grps);
	return ret;
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
	MALLOC_CACHE(group_cache);
	MALLOC_CACHE(initgroups_cache);

	cache = 1;
	return 0;
}
