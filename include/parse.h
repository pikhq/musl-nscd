#ifndef PARSE_H
#define PARSE_H

#include "list.h"

#include <stdio.h>

typedef unsigned char database;
typedef unsigned char status;
typedef unsigned char action;

enum {
	DB_ALIASES,
	DB_ETHERS,
	DB_GROUP,
	DB_HOSTS,
	DB_INITGROUPS,
	DB_NETGROUP,
	DB_NETWORKS,
	DB_PASSWD,
	DB_PROTOCOLS,
	DB_PUBLICKEY,
	DB_RPC,
	DB_SERVICES,
	DB_SHADOW
};

enum {
	STS_SUCCESS,
	STS_NOTFOUND,
	STS_UNAVAIL,
	STS_TRYAGAIN
};

enum {
	ACT_RETURN,
	ACT_CONTINUE,
	ACT_MERGE
};

struct service {
	char *service;
	action on_status[4];
	link_t link;
};

struct entry {
	database database;
	list_t services;
	link_t link;
};

extern FILE *yyin;
extern list_t parsed_output;
int yyparse(void);

#endif
