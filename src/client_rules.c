#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "client_rules.h"

struct client_rule {
	char *client;
	char *service;
};

static struct client_rule *rules;
static size_t rules_n;

bool client_rules_enabled;

int client_rule_add(const char *client, const char *service)
{
	struct client_rule *tmp;
	char *c, *s;

	if(!*client || !*service || strlen(client) >= CLIENT_NAME_MAX) {
		errno = EINVAL;
		return -1;
	}

	c = strdup(client);
	s = strdup(service);
	tmp = realloc(rules, (rules_n + 1) * sizeof(*rules));
	if(!c || !s || !tmp) {
		free(c);
		free(s);
		/* realloc failure leaves the old array intact */
		if(tmp) rules = tmp;
		errno = ENOMEM;
		return -1;
	}
	rules = tmp;
	rules[rules_n].client = c;
	rules[rules_n].service = s;
	rules_n++;
	return 0;
}

int client_rule_parse(const char *spec)
{
	const char *sep = strchr(spec, ':');
	char client[CLIENT_NAME_MAX];
	size_t len;

	if(!sep || strchr(sep + 1, ':')) {
		errno = EINVAL;
		return -1;
	}
	len = sep - spec;
	if(len == 0 || len >= sizeof client) {
		errno = EINVAL;
		return -1;
	}
	memcpy(client, spec, len);
	client[len] = 0;
	return client_rule_add(client, sep + 1);
}

bool client_rules_use_service(const char *service)
{
	for(size_t i = 0; i < rules_n; i++)
		if(!strcmp(rules[i].service, service)) return true;
	return false;
}

bool client_is_restricted(const char *client)
{
	for(size_t i = 0; i < rules_n; i++)
		if(!strcmp(rules[i].client, client)) return true;
	return false;
}

bool client_rule_match(const char *client, const char *service)
{
	for(size_t i = 0; i < rules_n; i++)
		if(!strcmp(rules[i].client, client) && !strcmp(rules[i].service, service))
			return true;
	return false;
}

void client_rules_log(void)
{
	for(size_t i = 0; i < rules_n; i++)
		syslog(LOG_INFO, "requests from '%s' will not be passed to service '%s'",
			rules[i].client, rules[i].service);
}

int client_get_name(int fd, char *buf, size_t len)
{
	struct ucred cred;
	socklen_t cred_len = sizeof cred;
	char path[64];
	char exe[4096];
	ssize_t n;
	const char *base;
	static const char deleted[] = " (deleted)";
	size_t base_len;

	if(getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cred, &cred_len) < 0)
		return -1;
	/* pid 0 means the peer is not visible in our pid namespace */
	if(cred.pid <= 0)
		return -1;

	snprintf(path, sizeof path, "/proc/%ld/exe", (long)cred.pid);
	n = readlink(path, exe, sizeof exe - 1);
	if(n <= 0)
		return -1;
	exe[n] = 0;

	/* an executable replaced by a package upgrade shows up as
	 * "/usr/sbin/winbindd (deleted)"; it is still the same program */
	if((size_t)n > sizeof deleted - 1 &&
	   !strcmp(exe + n - (sizeof deleted - 1), deleted))
		exe[n - (sizeof deleted - 1)] = 0;

	base = strrchr(exe, '/');
	base = base ? base + 1 : exe;
	base_len = strlen(base);
	if(base_len == 0 || base_len >= len)
		return -1;
	memcpy(buf, base, base_len + 1);
	return 0;
}
