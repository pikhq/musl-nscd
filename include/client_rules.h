#ifndef CLIENT_RULES_H
#define CLIENT_RULES_H

#include <stdbool.h>
#include <stddef.h>

/*
 * Client rules let musl-nscd skip specific NSS services for requests
 * coming from specific programs.
 *
 * The motivating case is Samba's winbindd: it must never resolve users or
 * groups through nss_winbind, because that sends the query back into
 * winbindd itself and deadlocks it until its request timeout expires.
 * On glibc, nss_winbind runs inside the winbindd process and detects this
 * via the _NO_WINBINDD environment variable; with musl-nscd the lookup
 * crosses a socket, so musl-nscd has to make that decision instead.
 *
 * The client is identified by the basename of the executable of the peer
 * process (via SO_PEERCRED and /proc/<pid>/exe).
 */

/* longest client program name that can be matched */
#define CLIENT_NAME_MAX 256

/* add a rule from a "program:service" specification; returns 0 on success */
int client_rule_parse(const char *spec);

/* add a rule directly; returns 0 on success */
int client_rule_add(const char *client, const char *service);

/* true if any rule refers to the given service */
bool client_rules_use_service(const char *service);

/* true if any rule applies to the given client program */
bool client_is_restricted(const char *client);

/* true if requests from client must not be passed to service */
bool client_rule_match(const char *client, const char *service);

/* log the active rules (call after openlog) */
void client_rules_log(void);

/* get the program name of the process connected on fd;
 * returns 0 on success, -1 if it could not be determined */
int client_get_name(int fd, char *buf, size_t len);

/* set by main when at least one rule refers to a configured service */
extern bool client_rules_enabled;

#endif
