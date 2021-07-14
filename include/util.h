#ifndef UTIL_H
#define UTIL_H

#include <stddef.h>
#include <stdint.h>
#include <pwd.h>
#include <grp.h>
#include <locale.h>

#if __STDC_VERSION__ >= 201112L
#include <stdnoreturn.h>
#elif defined(__GNUC__)
#define noreturn __attribute__((__noreturn__))
#else
#define noreturn
#endif

void init_program_invocation_name(const char*);
extern const char *program_invocation_name;
extern const char *program_invocation_short_name;
noreturn void die(void);
noreturn void die_fmt(const char*, ...);
int asprintf(char**, const char*, ...);
int full_write(int, const char*, size_t);
int full_read(int, char*, size_t);
uint32_t swap32(uint32_t);
int write_pwd(int, int, struct passwd*);
int write_grp(int, int, struct group*);
int write_groups(int, int, size_t, gid_t*);
int init_socket_handling(unsigned);
void socket_handle(int);

#endif
