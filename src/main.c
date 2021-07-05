#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <locale.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <syslog.h>

#include "modules.h"
#include "parse.h"
#include "util.h"

list_t passwd_mods;
list_t group_mods;

static void *get_dll(const char *service)
{
	char *path;
	void *dll;
	if(asprintf(&path, "libnss_%s.so.2", service) < 0) die();
	dll = dlopen(path, RTLD_NOW | RTLD_LOCAL);
	if(!dll) {
		sprintf(path, "libnss_%s.so", service);
		dll = dlopen(path, RTLD_NOW | RTLD_LOCAL);
	}
	if(!dll) die_fmt("%s: %s", path, dlerror());
	free(path);
	return dll;
}

static void *get_fn(void *dll, const char *name, const char *service)
{
	char *fnname;
	void *fn;
	if(asprintf(&fnname, "_nss_%s_%s", service, name) < 0) die();
	fn = dlsym(dll, fnname);
	free(fnname);
	return fn;
}

static enum nss_status null_getpwnam_r(const char *a, struct passwd *b, char *c, size_t d, int *e)
{
	return NSS_STATUS_NOTFOUND;
}

static enum nss_status null_getpwuid_r(uid_t a, struct passwd *b, char *c, size_t d, int *e)
{
	return NSS_STATUS_NOTFOUND;
}

static enum nss_status null_getgrnam_r(const char *a, struct group *b, char *c, size_t d, int *e)
{
	return NSS_STATUS_NOTFOUND;
}

static enum nss_status null_getgrgid_r(gid_t a, struct group *b, char *c, size_t d, int *e)
{
	return NSS_STATUS_NOTFOUND;
}

static enum nss_status null_initgroups_dyn(const char *a, gid_t b, long *c, long *d, gid_t **e, long f, int *g)
{
	return NSS_STATUS_NOTFOUND;
}

int main(int argc, char **argv)
{
	int fd;
	char *socket_path = "/var/run/nscd/socket";
	char *config_path = "/etc/nsswitch.conf";
	char *pid_path = 0;
	bool daemonize = false;
	int c;

	signal(SIGPIPE, SIG_IGN);

	init_program_invocation_name(argv[0]);

	while((c = getopt(argc, argv, "c:s:p:d")) != -1) switch(c) {
	case 'c':
		config_path = optarg;
		break;
	case 's':
		socket_path = optarg;
		break;
	case 'p':
		pid_path = optarg;
		break;
	case 'd':
		daemonize = true;
		break;
	default:
		return 1;
	}

	yyin = fopen(config_path, "r");
	if(!yyin) die_fmt("%s was not found", config_path);

	errno = 0;
	if(yyparse()) {
		if(errno) die();
		return 1;
	}
	fclose(yyin);

	link_t *entry_l, *service_l;

	entry_l = list_head(&parsed_output);
	while(entry_l) {
		struct entry *entry = list_ref(entry_l, struct entry, link);
		struct service *service;

		service_l = list_head(&entry->services);
		while(service_l) {
			service = list_ref(service_l, struct service, link);

			for(size_t i = 0; i < 4; i++) {
				/* TODO: implement ACT_MERGE */
				if(service->on_status[i] == ACT_MERGE) {
					die_fmt("service '%s' is configured with a merge action in '%s', this is unsupported", service->service, config_path);
				}
			}

			if(entry->database == DB_PASSWD) {
				void *dll;
				struct mod_passwd *mod;
				mod = malloc(sizeof(*mod));
				if(!mod) die();

				dll = get_dll(service->service);
				mod->nss_getpwnam_r = (nss_getpwnam_r)get_fn(dll, "getpwnam_r", service->service);
				if(!mod->nss_getpwnam_r) mod->nss_getpwnam_r = null_getpwnam_r;
				mod->nss_getpwuid_r = (nss_getpwuid_r)get_fn(dll, "getpwuid_r", service->service);
				if(!mod->nss_getpwuid_r) mod->nss_getpwuid_r = null_getpwuid_r;

				memcpy(mod->on_status, service->on_status, sizeof(mod->on_status));

				list_push_back(&passwd_mods, &mod->link);
			} else if(entry->database == DB_GROUP) {
				void *dll;
				struct mod_group *mod;
				mod = malloc(sizeof(*mod));
				if(!mod) die();

				dll = get_dll(service->service);
				mod->nss_getgrnam_r = (nss_getgrnam_r)get_fn(dll, "getgrnam_r", service->service);
				if(!mod->nss_getgrnam_r) mod->nss_getgrnam_r = null_getgrnam_r;
				mod->nss_getgrgid_r = (nss_getgrgid_r)get_fn(dll, "getgrgid_r", service->service);
				if(!mod->nss_getgrgid_r) mod->nss_getgrgid_r = null_getgrgid_r;
				mod->nss_initgroups_dyn = (nss_initgroups_dyn)get_fn(dll, "initgroups_dyn", service->service);
				if(!mod->nss_initgroups_dyn) mod->nss_initgroups_dyn = null_initgroups_dyn;

				memcpy(mod->on_status, service->on_status, sizeof(mod->on_status));

				list_push_back(&group_mods, &mod->link);
			}
			service_l = list_next(service_l);
			free(service->service);
			free(service);
		}
		entry_l = list_next(entry_l);
		free(entry);
	}

	fd = socket(PF_UNIX, SOCK_STREAM, 0);
	if(fd < 0) die();
	struct sockaddr_un addr = {
		.sun_family = AF_UNIX
	};
	strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path));
	if(bind(fd, (struct sockaddr*)&addr, sizeof addr) < 0) {
		int tmp_fd;
		if(errno != EADDRINUSE)
			die();
		tmp_fd = socket(PF_UNIX, SOCK_STREAM, 0);
		if(tmp_fd < 0) die();
		if(connect(tmp_fd, (struct sockaddr*)&addr, sizeof addr) >= 0) {
			errno = EADDRINUSE;
			die();
		} else if(errno != ECONNREFUSED) die();
		close(tmp_fd);
		unlink(addr.sun_path);
		if(bind(fd, (struct sockaddr*)&addr, sizeof addr) < 0) die();
	}

	chmod(socket_path, 0666);

	if(listen(fd, 100) < 0) die();
	locale_t l = newlocale(LC_ALL_MASK, "C", (locale_t)0);
	if(!l) die();

	openlog("musl-nscd", 0
#ifdef LOG_PERROR
			| LOG_PERROR
#endif
			, LOG_DAEMON);

	if(daemonize) {
		int null_fd = 0;
		if((null_fd = open("/dev/null", O_RDWR)) < 0) {
			syslog(LOG_ERR, "%s", strerror(errno));
			return 1;
		}
		if(dup2(null_fd, 0) < 0 || dup2(null_fd, 1) < 0 || dup2(null_fd, 2) < 0) {
			syslog(LOG_ERR, "%s", strerror(errno));
			return 1;
		}
		if(null_fd > 2) close(null_fd);

		switch(fork()) {
		case 0: break;
		case -1: syslog(LOG_ERR, "%s", strerror(errno)); return 1;
		default: return 0;
		}

		if(setsid() < 0) die();

		switch(fork()) {
		case 0: break;
		case -1: syslog(LOG_ERR, "%s", strerror(errno)); return 1;
		default: return 0;
		}
	}

	if(pid_path) {
		FILE *f = fopen(pid_path, "w");
		if(!f) { syslog(LOG_ERR, "%s", strerror(errno)); return 1; }
		fprintf(f, "%ju\n", (uintmax_t)getpid());
		fclose(f);
	}

	chdir("/");

	if (init_socket_handling() < 0) die();
	socket_handle(fd, -1, l, 0);
}
