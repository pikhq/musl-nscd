#ifndef NSCD_H
#define NSCD_H

#include <stdint.h>

#define NSCDVERSION 2
#define GETPWBYNAME 0
#define GETPWBYUID 1
#define GETGRBYNAME 2
#define GETGRBYGID 3

#define REQVERSION 0
#define REQTYPE 1
#define REQKEYLEN 2
#define REQ_LEN 3

#define PWVERSION 0
#define PWFOUND 1
#define PWNAMELEN 2
#define PWPASSWDLEN 3
#define PWUID 4
#define PWGID 5
#define PWGECOSLEN 6
#define PWDIRLEN 7
#define PWSHELLLEN 8
#define PW_LEN 9

#define GRVERSION 0
#define GRFOUND 1
#define GRNAMELEN 2
#define GRPASSWDLEN 3
#define GRGID 4
#define GRMEMCNT 5
#define GR_LEN 6

#endif
