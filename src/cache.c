#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "config.h"
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

/* returns true if the timestamp is still valid */
static bool compare_timestamps(time_t t, time_t now)
{
	return (now - t) < CACHE_INVALIDATION_TIME;
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

/* public domain hash, adapted from http://www.isthe.com/chongo/tech/comp/fnv/
 * specifically http://www.isthe.com/chongo/src/fnv/hash_32.c */
#define FNV_32_PRIME ((uint32_t)0x01000193)
#define FNV1_32_INIT ((uint32_t)0x811c9dc5)
static uint32_t hash(const char *s)
{
   uint32_t h = FNV1_32_INIT;
   for (; *s; s++) {
		h *= FNV_32_PRIME;
		h ^= (unsigned char)*s;
	}
   return h;
}

struct passwd_result {
	struct passwd p;
	char *b;
	size_t l;
	/* for validation */
	time_t t;
	uint32_t h;
};
struct passwd_cache {
	pthread_rwlock_t lock;
	struct passwd_result *res;
	size_t len, size;
};

static struct passwd_cache passwd_cache =
	{ .lock = PTHREAD_RWLOCK_INITIALIZER, .size = CACHE_INITIAL_ENTRIES };

static void copy_passwd(struct passwd *np, char *nb, const struct passwd *p, const char *b, size_t len)
{
	memcpy(nb, b, len);

	#define NEW_ADDRESS(member) np->member = p->member ? nb + (p->member - b) : 0
	NEW_ADDRESS(pw_name);
#ifdef HAVE_PW_PASSWD
	NEW_ADDRESS(pw_passwd);
#endif
	np->pw_uid = p->pw_uid;
	np->pw_gid = p->pw_gid;
#ifdef HAVE_PW_GECOS
	NEW_ADDRESS(pw_gecos);
#endif
	NEW_ADDRESS(pw_dir);
	NEW_ADDRESS(pw_shell);
	#undef NEW_ADDRESS
}

enum nss_status cache_getpwnam_r(const char *name, struct passwd *p, char **buf, int *err)
{
	#define CACHE passwd_cache
	#define RESULT_TYPE passwd_result
	#define HASH_ARG name
	#define COMPARISON() (h == res->h && strcmp(res->p.pw_name, name) == 0)
	#define ARGUMENT p
	#define COPY_FUNCTION copy_passwd
	#include "cache_query.h"
}

enum nss_status cache_getpwuid_r(uid_t id, struct passwd *p, char **buf, int *err)
{
	#define CACHE passwd_cache
	#define RESULT_TYPE passwd_result
	#define COMPARISON() (res->p.pw_uid == id)
	#define ARGUMENT p
	#define COPY_FUNCTION copy_passwd
	#include "cache_query.h"
}

/* this function copies the passwd struct p points to and
 * takes ownership of the buffer b points to */
int cache_passwd_add(struct passwd *p, char *b, size_t buf_len)
{
	#define CACHE passwd_cache
	#define RESULT_TYPE passwd_result
	#define HASH_ARG res->p.pw_name
	#define COMPARISON() (res->p.pw_uid == p->pw_uid)
	#define ARGUMENT p
	#include "cache_add.h"
}

struct group_result {
	struct group g;
	char *b;
	size_t l;
	/* for validation */
	time_t t;
	uint32_t h;
};
struct group_cache {
	pthread_rwlock_t lock;
	struct group_result *res;
	size_t len, size;
};

static struct group_cache group_cache =
	{ .lock = PTHREAD_RWLOCK_INITIALIZER, .size = CACHE_INITIAL_ENTRIES };

static void copy_group(struct group *ng, char *nb, const struct group *g, const char *b, size_t len)
{
	memcpy(nb, b, len);

	/* copy the pointer offset */
	#define NEW_ADDRESS(member) ng->member = g->member ? (void *)(nb + ((char *)(void *)g->member - (char *)(void *)b)) : 0
	NEW_ADDRESS(gr_name);
#ifdef HAVE_GR_PASSWD
	NEW_ADDRESS(gr_passwd);
#endif
	ng->gr_gid = g->gr_gid;

	NEW_ADDRESS(gr_mem);
	if(g->gr_mem) {
		for(size_t i = 0; g->gr_mem[i]; i++) {
			NEW_ADDRESS(gr_mem[i]);
		}
	}

	#undef NEW_ADDRESS
}

enum nss_status cache_getgrnam_r(const char *name, struct group *g, char **buf, int *err)
{
	#define CACHE group_cache
	#define RESULT_TYPE group_result
	#define HASH_ARG name
	#define COMPARISON() (h == res->h && strcmp(res->g.gr_name, name) == 0)
	#define ARGUMENT g
	#define COPY_FUNCTION copy_group
	#include "cache_query.h"
}

enum nss_status cache_getgrgid_r(gid_t id, struct group *g, char **buf, int *err)
{
	#define CACHE group_cache
	#define RESULT_TYPE group_result
	#define COMPARISON() (res->g.gr_gid == id)
	#define ARGUMENT g
	#define COPY_FUNCTION copy_group
	#include "cache_query.h"
}

/* this function copies the group struct p points to and
 * takes ownership of the buffer b points to */
int cache_group_add(struct group *g, char *b, size_t buf_len)
{
	#define CACHE group_cache
	#define RESULT_TYPE group_result
	#define HASH_ARG res->g.gr_name
	#define COMPARISON() (res->g.gr_gid == g->gr_gid)
	#define ARGUMENT g
	#include "cache_add.h"
}

struct initgroups_result {
	struct initgroups_res g;
	char *name;
	/* for validation */
	time_t t;
	uint32_t h;
};
struct initgroups_cache {
	pthread_rwlock_t lock;
	struct initgroups_result *res;
	size_t len, size;
};

static struct initgroups_cache initgroups_cache =
	{ .lock = PTHREAD_RWLOCK_INITIALIZER, .size = CACHE_INITIAL_ENTRIES };

enum nss_status cache_initgroups_dyn(const char *name, struct initgroups_res *resp, int *err)
{
	IS_CACHING

	enum nss_status ret = NSS_STATUS_NOTFOUND;

	uint32_t h = hash(name);

	pthread_rwlock_rdlock(&initgroups_cache.lock);

	time_t now = monotonic_seconds();
	for(size_t i = 0; i < initgroups_cache.len; i++) {
		struct initgroups_result *res = &initgroups_cache.res[i];
		if (h == res->h && strcmp(res->name, name) == 0) {
			if(!compare_timestamps(res->t, now)) {
				break;
			}

			resp->grps = malloc(res->g.end * sizeof(gid_t));
			if(!resp->grps) {
				*err = errno;
				break;
			}
			resp->alloc = resp->end = res->g.end;

			memcpy(resp->grps, res->g.grps, res->g.end * sizeof(gid_t));
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

	uint32_t h = hash(name);

	pthread_rwlock_wrlock(&initgroups_cache.lock);

	time_t oldest = initgroups_cache.len > 0 ? initgroups_cache.res[0].t : 0;
	size_t oldest_i = 0;
	bool found_invalid = false;

	time_t now = monotonic_seconds();
	for(i = 0; i < initgroups_cache.len; i++) {
		struct initgroups_result *res = &initgroups_cache.res[i];

		bool comp = compare_timestamps(res->t, now);

		if(!comp) {
			found_invalid = true;
			if(res->t < oldest) {
				oldest = res->t;
				oldest_i = i;
			}
		}

		if (h == res->h && strcmp(res->name, name) == 0) {
			if(comp) {
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
	res->h = h;
	g->grps = 0;

cleanup:
	pthread_rwlock_unlock(&initgroups_cache.lock);
	/* if insertion fails, we should free the buffer */
	free(g->grps);
	return ret;
}

int init_caches(void)
{
	#define MALLOC_CACHE(cache) do{ if(!(cache.res = malloc(cache.size * sizeof(*cache.res)))) return -1; }while(0)
	MALLOC_CACHE(passwd_cache);
	MALLOC_CACHE(group_cache);
	MALLOC_CACHE(initgroups_cache);

	cache = 1;
	return 0;
}
