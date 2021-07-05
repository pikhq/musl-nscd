#include <syslog.h>
#include <poll.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <inttypes.h>
#include <semaphore.h>
#include <ctype.h>
#include <limits.h>
#include <assert.h>
#include <stdbool.h>

#include "util.h"
#include "nss.h"
#include "nscd.h"
#include "parse.h"
#include "modules.h"
#include "list.h"

/* glibc's NSS_BUFLEN_PASSWD (from pwd/pwd.h) and NSS_BUFLEN_GROUP (from grp/grp.h)
 * are set to 1024 and consider it a reasonable default */
#define BUF_LEN_DEFAULT 1024
/* NGROUPS_MAX value for musl as of 1.2.2, might change
 * to keep up with the kernel definition, so we define our own */
#define INITGR_ALLOC 32

static int return_result(int fd, int swap, uint32_t reqtype, void *key);

struct pthread_args {
	int fd;
	locale_t l;
};


static void *start_thread(void *args)
{
	struct pthread_args *p = args;
	socket_handle(p->fd, 5 * 60 * 1000, p->l, args);
	return 0;
}

static int strtouid(const char *restrict buf, uint32_t *id)
{
	char *end;
	unsigned long n;
	errno = 0;
	if(!isdigit(buf[0])) {
		errno = EINVAL;
		return 1;
	}
	n = strtoul(buf, &end, 10);
	if(n == ULONG_MAX) {
		if(errno) return 1;
	}
	if(n > UINT32_MAX || *end != '\0') {
		errno = EINVAL;
		return 1;
	}
	*id = n;
	return 0;
}

static size_t buf_len_passwd, buf_len_group;
static sem_t sem;

int init_socket_handling(void)
{
	/* temporary variable needs to be signed */
	long tmp;
	tmp = sysconf(_SC_GETPW_R_SIZE_MAX);
	buf_len_passwd = (tmp > 0) ? tmp : BUF_LEN_DEFAULT;
	tmp = sysconf(_SC_GETGR_R_SIZE_MAX);
	buf_len_group = (tmp > 0) ? tmp : BUF_LEN_DEFAULT;

	return sem_init(&sem, 0, 0);
}

void socket_handle(int fd, int timeout, locale_t l, void *pthread_args)
{
	struct pollfd pollfd;
	struct pthread_args args;
	pollfd.fd = fd;
	pollfd.events = POLLIN;

	if(timeout < 0) {
		pthread_args = &args;
		args.fd = fd;
		args.l = l;
	}

	for(;;) {
		int n;
		int errno_stash;
		uint32_t buf[REQ_LEN];
		char *str = 0;
		char idbuf[11];
		uint32_t id;
		void *key;
		int swap = 0;

		sem_post(&sem);

		n = poll(&pollfd, 1, timeout);
		if(n < 0) {
			if(errno == EINTR) continue;
			syslog(LOG_ERR, "error in poll: %s", strerror_l(errno, l));
			goto end;
		}
		if(n == 0) {
			sem_trywait(&sem);
			return;
		}
		n = accept(fd, 0, 0);
		if(n < 0) {
			if(errno == EINTR) continue;
			syslog(LOG_ERR, "error in accept: %s", strerror_l(errno, l));
			goto end;
		}
		sem_trywait(&sem);
		if(sem_trywait(&sem) == -1) {
			pthread_t thread;
			if(pthread_create(&thread, 0, start_thread, pthread_args)) {
				syslog(LOG_ERR, "error in pthread_create: %s", strerror_l(errno, l));
			} else {
				pthread_detach(thread);
			}
		} else {
			sem_post(&sem);
		}


		if(full_read(n, (char*)buf, sizeof buf) < 0) {
			syslog(LOG_ERR, "error in read: %s", strerror_l(errno, l));
			goto cleanup_fd;
		}

		if(buf[REQVERSION] != NSCDVERSION && buf[REQVERSION] == swap32(NSCDVERSION)) {
			/* means our endianness doesn't match the requester's */
			swap = 1;
			for(int i = 0; i < REQ_LEN; i++)
				buf[i] = swap32(buf[i]);
		}
		if(buf[REQVERSION] != NSCDVERSION) {
			syslog(LOG_WARNING, "Received invalid request for NSCD version %"PRIu32", expected 2", buf[REQVERSION]);
			goto cleanup_fd;
		}
		if(buf[REQKEYLEN] == 0) {
			syslog(LOG_WARNING, "Received invalid request with a key length of 0; expected greater than 0");
			goto cleanup_fd;
		}
	
		switch(buf[REQTYPE]) {
		case GETPWBYNAME: case GETGRBYNAME: case GETINITGR:
			str = malloc(buf[REQKEYLEN]);
			if(!str) {
				syslog(LOG_ERR, "error in malloc: %s", strerror_l(errno, l));
				goto cleanup_fd;
			}
			if(full_read(n, str, buf[REQKEYLEN]) < 0) {
				syslog(LOG_ERR, "error in read: %s", strerror_l(errno, l));
				goto cleanup_mem;
			}
			if(str[buf[REQKEYLEN]-1]) {
				syslog(LOG_ERR, "Received invalid request");
				goto cleanup_mem;
			}
			key = str;
			break;
		case GETPWBYUID: case GETGRBYGID:
			if(buf[REQKEYLEN] > 11) {
				syslog(LOG_ERR, "Received invalid request for %"PRIu32", expected length 11 or less got %"PRIu32, buf[REQTYPE], buf[REQKEYLEN]);
				goto cleanup_fd;
			}
			if(full_read(n, idbuf, buf[REQKEYLEN]) < 0) {
				syslog(LOG_ERR, "error in read: %s", strerror_l(errno, l));
				goto cleanup_fd;
			}
			if(idbuf[buf[REQKEYLEN]-1]) {
				syslog(LOG_ERR, "Received invalid request");
				goto cleanup_fd;
			}
			if(strtouid(idbuf, &id)) {
				syslog(LOG_ERR, "Received invalid request");
				goto cleanup_fd;
			}
			key = &id;
			break;
		default:
			syslog(LOG_INFO, "Unsupported request %"PRIu32, buf[REQTYPE]);
			goto cleanup_fd;
		}

		/* if return_result fails for any reason, we will just close the socket */
		return_result(n, swap, buf[REQTYPE], key);

cleanup_mem:
		errno_stash = errno;
		if(str) free(str);
		errno = errno_stash;
cleanup_fd:
		errno_stash = errno;
		close(n);
		errno = errno_stash;
end:
		if(timeout > 0) return;
	}

}

struct initgroups_res {
	long end;
	long alloc;
	gid_t *grps;
};

static enum nss_status nss_getkey(uint32_t reqtype, struct mod_passwd *mod_passwd, struct mod_group *mod_group, void *key, void *res, char *buf, size_t n, int *ret)
{
	int retval = NSS_STATUS_UNAVAIL;
	struct initgroups_res *initgroups_res;

	/* for debug only: guarantee the nss_getkey function is being used correctly */
	if(ISPWREQ(reqtype)) assert(mod_passwd);
	else assert(mod_group);

	switch(reqtype) {
	case GETPWBYNAME:
		retval = mod_passwd->nss_getpwnam_r((char*)key, (struct passwd*)res, buf, n, ret);
		break;
	case GETPWBYUID:
		retval = mod_passwd->nss_getpwuid_r((uid_t)*(uint32_t*)key, (struct passwd*)res, buf, n, ret);
		break;
	case GETGRBYNAME:
		retval = mod_group->nss_getgrnam_r((char*)key, (struct group*)res, buf, n, ret);
		break;
	case GETGRBYGID:
		retval = mod_group->nss_getgrgid_r((gid_t)*(uint32_t*)key, (struct group*)res, buf, n, ret);
		break;
	case GETINITGR:
		initgroups_res = res;
		initgroups_res->end = 0;
		initgroups_res->alloc = INITGR_ALLOC + 1;
		initgroups_res->grps = malloc(sizeof(gid_t) * initgroups_res->alloc);
		if(!initgroups_res->grps) {
			*ret = errno;
			return NSS_STATUS_TRYAGAIN;
		}
		retval = mod_group->nss_initgroups_dyn((char*)key, (gid_t)-1, &(initgroups_res->end), &(initgroups_res->alloc), &(initgroups_res->grps), UINT32_MAX, ret);
		break;
	}
	if(retval == NSS_STATUS_SUCCESS && ISPWREQ(reqtype)) {
		struct passwd *pwd = res;
		if(!pwd->pw_name) retval = NSS_STATUS_NOTFOUND;
#ifdef HAVE_PW_PASSWD
		if(!pwd->pw_passwd) retval = NSS_STATUS_NOTFOUND;
#endif
#ifdef HAVE_PW_GECOS
		if(!pwd->pw_gecos) retval = NSS_STATUS_NOTFOUND;
#endif
		if(!pwd->pw_dir) retval = NSS_STATUS_NOTFOUND;
		if(!pwd->pw_shell) retval = NSS_STATUS_NOTFOUND;
	}
	if(retval == NSS_STATUS_SUCCESS && ISGRPREQ(reqtype)) {
		struct group *grp = res;
		if(!grp->gr_name) retval = NSS_STATUS_NOTFOUND;
#ifdef HAVE_GR_PASSWD
		if(!grp->gr_passwd) retval = NSS_STATUS_NOTFOUND;
#endif
		if(!grp->gr_mem) retval = NSS_STATUS_NOTFOUND;
	}
	return retval;
}

int return_result(int fd, int swap, uint32_t reqtype, void *key)
{
	union {
		struct passwd p;
		struct group g;
		struct initgroups_res l;
	} res;
	link_t *l;
	struct mod_group *mod_group;
	struct mod_passwd *mod_passwd;
	char *buf = 0;
	size_t buf_len = 0;
	long tmp;
	bool using_passwd;

	if(ISPWREQ(reqtype)) {
		using_passwd = true;
		l = list_head(&passwd_mods);
		tmp = sysconf(_SC_GETPW_R_SIZE_MAX);
		if(tmp < 0) buf_len = 4096;
		else buf_len = tmp;
		buf = malloc(buf_len);
		if(!buf) return -1;
	} else {
		using_passwd = false;
		l = list_head(&group_mods);
		tmp = sysconf(_SC_GETGR_R_SIZE_MAX);
		if(tmp < 0) buf_len = 4096;
		else buf_len = tmp;
		buf = malloc(buf_len);
		if(!buf) return -1;
	}
	for(; l; l = list_next(l)) {
		int ret = 0;
		int act;
		enum nss_status status;
		action *on_status;
		if(using_passwd) {
			mod_passwd = list_ref(l, struct mod_passwd, link);
			mod_group = 0;
		} else {
			mod_group = list_ref(l, struct mod_group, link);
			mod_passwd = 0;
		}
		do {
			memset(&res, 0, sizeof(res));
			status = nss_getkey(reqtype, mod_passwd, mod_group, key, &res, buf, buf_len, &ret);
			if(status == NSS_STATUS_TRYAGAIN && ret == ERANGE) {
				size_t new_len;
				char *new_buf;
				if(buf_len == SIZE_MAX) {
					free(buf);
					errno = ENOMEM;
					return -1;
				}
				/* memory growth factor is 1.5x.
				 * to avoid overshooting SIZE_MAX and overflowing,
				 * we use the check below: buf_len > (2/3) * SIZE_MAX */
				if(buf_len > SIZE_MAX - buf_len/2) {
					new_len = SIZE_MAX;
				} else {
					/* buf_len * 1.5 */
					new_len = buf_len + buf_len/2;
				}
				/* TODO: doesn't need to be a realloc,
				 * since we don't need to copy the memory;
				 * evaluate if it's better or worse than malloc+free */
				new_buf = realloc(buf, new_len);
				if(!new_buf) {
					free(buf);
					return -1;
				}
				buf = new_buf;
				buf_len = new_len;
			}
		} while(status == NSS_STATUS_TRYAGAIN && ret == ERANGE);

		on_status = using_passwd ? mod_passwd->on_status : mod_group->on_status;
		act = on_status[
			status == NSS_STATUS_TRYAGAIN ? STS_TRYAGAIN :
			status == NSS_STATUS_UNAVAIL ? STS_UNAVAIL :
			status == NSS_STATUS_NOTFOUND ? STS_NOTFOUND :
			STS_SUCCESS];
		if(act == ACT_RETURN) {
			int err;
			if(mod_passwd)
				err = write_pwd(fd, swap, status == NSS_STATUS_SUCCESS ? &res.p : 0);
			else if(reqtype != GETINITGR)
				err = write_grp(fd, swap, status == NSS_STATUS_SUCCESS ? &res.g : 0);
			else {
				err = write_groups(fd, swap, status == NSS_STATUS_SUCCESS ? res.l.end : 0, status == NSS_STATUS_SUCCESS ? res.l.grps : 0);
				free(res.l.grps);
			}
			if(err == -1) {
				free(buf);
				return -1;
			}
			if(err == -2) {
				if(on_status[STS_UNAVAIL] == ACT_RETURN) {
					free(buf);
					if(mod_passwd)
						return write_pwd(fd, swap, 0) > 0 ? 0 : -1;
					else if(reqtype != GETINITGR)
						return write_grp(fd, swap, 0) > 0 ? 0 : -1;
					else
						return write_groups(fd, swap, 0, 0) > 0 ? 0 : -1;
				}
				continue;
			}
		}
	}
	if(!l) {
		free(buf);
		switch(reqtype) {
		case GETPWBYNAME: case GETPWBYUID:
			return write_pwd(fd, swap, 0) > 0 ? 0 : -1;
		case GETGRBYNAME: case GETGRBYGID:
			return write_grp(fd, swap, 0) > 0 ? 0 : -1;
		case GETINITGR:
			return write_groups(fd, swap, 0, 0) > 0 ? 0 : -1;
		}
	}

}
