/* This code is written this way in order to implement polimorphism: the struct
 * passwd and struct group caches are implemented in exactly the same way, the
 * only difference being the name of struct members and struct layout.
 *
 * The function to add values into the cache will #include this file in its
 * body, after defining the necessary macros:
 *   - CACHE: name of the cache for that struct
 *   - RESULT_TYPE: the type of a result stored in the cache
 *   - HASH_ARG: the argument that will be passed to the hashing function, if
 *     any
 *   - COMPARISON: the equality check to determine if the entry being added to
 *     cache is listed in it already
 *   - ARGUMENT: the name of the struct member holding the struct passwd or
 *     struct group being used
 */

IS_CACHING_FOR_WRITE(b);

int ret = 0;
/* variables for dealing with duplicates */
size_t i;
bool found_outdated = false;

/* studying the effects of contention on this lock might be important */
pthread_rwlock_wrlock(&CACHE.lock);

/* since we can't initialize oldest to the maximum value of time_t, because it
 * doesn't exist, initialize it with the first entry (if there is a first entry
 * at all) */
time_t oldest = CACHE.len > 0 ? CACHE.res[0].t : 0;
size_t oldest_i = 0;
bool found_invalid = false;

/* check if the new value hasn't been added by another thread */
time_t now = monotonic_seconds();
for(i = 0; i < CACHE.len; i++) {
	struct RESULT_TYPE *res = &CACHE.res[i];

	bool comp = compare_timestamps(res->t, now);

	/* look for invalid entry with lowest timestamp as a heuristic for
	 * least-recently-used */
	if(!comp) {
		found_invalid = true;
		if(res->t < oldest) {
			oldest = res->t;
			oldest_i = i;
		}
	}

	/* since the ID is canonical, we only need to look for it to check for duplicates */
	if (COMPARISON()) {
		/* valid entry */
		if(comp) {
			goto cleanup;
		}
		/* outdated entry, should be replaced */
		found_outdated = true;
		break;
	}
}

/* if we are here, we are necessarily going to add something to the cache */
struct RESULT_TYPE *res;
if(found_outdated) {
	res = &CACHE.res[i];

	/* we will simply overwrite the cache entry's ARGUMENT member */
	memcpy(&res->ARGUMENT, ARGUMENT, sizeof(*ARGUMENT));
	/* but we still need to free its underlying storage */
	free(res->b);
} else {
	if(found_invalid) {
		/* overwrite invalid entry */
		i = oldest_i;
		/* we need to free all the underlying storage */
		res = &CACHE.res[i];
		free(res->b);
	} else {
		void *tmp_pointer = CACHE.res;
		if(!cache_increment_len(&CACHE.len, &CACHE.size, sizeof(*CACHE.res), &tmp_pointer, &i))
			goto cleanup;
		CACHE.res = tmp_pointer;

		res = &CACHE.res[i];
	}

	res->ARGUMENT = *ARGUMENT;
}
res->b = b;
res->l = buf_len;
res->t = now;
#ifdef HASH_ARG
res->h = hash(HASH_ARG);
#endif
b = 0;

cleanup:
pthread_rwlock_unlock(&CACHE.lock);
/* if insertion fails, we should free the buffer */
free(b);
return ret;

#undef CACHE
#undef RESULT_TYPE
#undef HASH_ARG
#undef COMPARISON
#undef ARGUMENT
