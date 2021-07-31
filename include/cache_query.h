/* This code is written this way in order to implement polimorphism: the struct
 * passwd and struct group caches are implemented in exactly the same way, the
 * only difference being the name of struct members and struct layout.
 *
 * The function to query values from cache will #include this file in its body,
 * after defining the necessary macros:
 *   - CACHE: name of the cache for that struct
 *   - RESULT_TYPE: the type of a result stored in the cache
 *   - HASH_ARG: the argument that will be passed to the hashing function, if
 *     any
 *   - COMPARISON: the equality check to determine if the entry being queried is present in cache already
 *   - ARGUMENT: the name of the struct member holding the struct passwd or
 *     struct group being used
 */

IS_CACHING

enum nss_status ret = NSS_STATUS_NOTFOUND;

#ifdef HASH_ARG
uint32_t h = hash(HASH_ARG);
#endif

pthread_rwlock_rdlock(&CACHE.lock);

time_t now = monotonic_seconds();
for(size_t i = 0; i < CACHE.len; i++) {
	struct RESULT_TYPE *res = &CACHE.res[i];
	if (COMPARISON()) {
		if(!compare_timestamps(res->t, now)) {
			break;
		}
		*buf = malloc(res->l);
		if(!*buf) {
			*err = errno;
			break;
		}
		COPY_FUNCTION(ARGUMENT, *buf, &CACHE.res[i].ARGUMENT, CACHE.res[i].b, res->l);
		ret = NSS_STATUS_SUCCESS;
		break;
	}
}

pthread_rwlock_unlock(&CACHE.lock);
return ret;

/* avoid polluting lines after this file is included */
#undef CACHE
#undef RESULT_TYPE
#undef HASH_ARG
#undef COMPARISON
#undef ARGUMENT
#undef COPY_FUNCTION
