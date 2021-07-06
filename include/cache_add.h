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

	/* look for invalid entry with lowest timestamp as a heuristic for
	 * least-recently-used */
	if(!compare_timestamps(res->t, now)) {
		found_invalid = true;
		if(res->t < oldest) {
			oldest = res->t;
			oldest_i = i;
		}
	}

	/* since the ID is canonical, we only need to look for it to check for duplicates */
	if (COMPARISON()) {
		/* valid entry */
		if(compare_timestamps(res->t, now)) {
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
b = 0;

cleanup:
pthread_rwlock_unlock(&CACHE.lock);
/* if insertion fails, we should free the buffer */
free(b);
return ret;

#undef CACHE
#undef RESULT_TYPE
#undef COMPARISON
#undef ARGUMENT
