#ifndef PARSE_COMMON_H
#define PARSE_COMMON_H

#include <stdbool.h>
#include "parse.h"
#include "list.h"

union yystype {
	char *str;
	database database;
	status status;
	action action;
	action modifiers[4];
	list_t list;
	struct entry entry;
	struct service service;

	struct {
		status status;
		action action;
		bool negate;
	} modifier;
};

#define TOK_STRING 258
#define TOK_DB 259
#define TOK_STS 260
#define TOK_ACT 261

#define YYSTYPE union yystype
extern YYSTYPE yylval;

int yylex();

#endif
