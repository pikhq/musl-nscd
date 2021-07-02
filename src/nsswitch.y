%{

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "parse_common.h"

list_t parsed_output;

void yyerror(const char*);

static const action default_actions[] = {
	ACT_RETURN,
	ACT_CONTINUE,
	ACT_CONTINUE,
	ACT_CONTINUE
};

%}

%token <str> STRING 258
%token <database> DB 259
%token <status> STS 260
%token <action> ACT 261
%type <modifier> modifier
%type <service> item
%type <modifiers> modifiers
%type <list> list
%type <entry> line
%type <list> file

%%

top:
	file {
		parsed_output = $1;
	}
	;

file:
	%empty {
		list_init(&$$);
	}
	| file line {
		if($2.database == (unsigned char)-1) {
			$$ = $1;
		} else {
			struct entry *entry = malloc(sizeof(*entry));
			if(!entry) YYABORT;
			memcpy(entry, &$2, sizeof(*entry));
			$$ = $1;
			list_push_back(&$$, &(entry->link));
		}
	}
	;

line:
	'\n' {
		$$.database = (unsigned char)-1;
	}
	| DB list '\n' {
		$$.database = $1;
		$$.services = $2;
	}
	;

modifier:
	'[' STS ']' {
		$$.status = $2;
		$$.action = $2 == STS_SUCCESS ? ACT_RETURN : ACT_CONTINUE;
		$$.negate = false;
	}
	| '[' '!' STS ']' {
		$$.status = $3;
		$$.action = $3 == STS_SUCCESS ? ACT_RETURN : ACT_CONTINUE;
		$$.negate = true;
	}
	| '[' STS '=' ACT ']' {
		$$.status = $2;
		$$.action = $4;
		$$.negate = false;
	}
	| '[' '!' STS '=' ACT ']' {
		$$.status = $3;
		$$.action = $5;
		$$.negate = true;
	}
	;

modifiers:
	%empty {
		memcpy($$, default_actions, sizeof($$));
	}
	| modifiers modifier {
		int i;
		memcpy($$, $1, sizeof($$));
		for(i = 0; i < sizeof($$)/sizeof($$[0]); i++) {
			if(i == $2.status && !$2.negate) {
				$$[i] = $2.action;
			}
			if(i != $2.status && $2.negate) {
				$$[i] = $2.action;
			}
		}
	}

item:
	STRING modifiers {
		memcpy($$.on_status, $2, sizeof($2));
		$$.service = $1;
	}
	;

list:
	%empty {
		list_init(&$$);
	}
	| list item {
		$$ = $1;
		struct service *service = malloc(sizeof(*service));
		if(!service) YYABORT;
		memcpy(service, &$2, sizeof(*service));
		list_push_back(&$$, &(service->link));
	}
	;

%%

void yyerror(const char *s)
{
	fprintf(stderr, "%s\n", s);
}

#if TEST_PARSER

static const char *dbmap[] = {
	"aliases",
	"ethers",
	"group",
	"hosts",
	"initgroups",
	"netgroup",
	"networks",
	"passwd",
	"protocols",
	"publickey",
	"rpc",
	"services",
	"shadow"
};

static const char *stsmap[] = {
	"SUCCESS",
	"NOTFOUND",
	"UNAVAIL",
	"TRYAGAIN"
};

static const char *actmap[] = {
	"return",
	"continue",
	"merge"
};

int main()
{
#if YYDEBUG
	yydebug = 1;
#endif
	if(yyparse()) return 1;
	link_t *line, *service;
	line = list_head(&parsed_output);
	while(line) {
		struct entry *entry = list_ref(line, struct entry, link);
		printf("%s: ", dbmap[entry->database]);
		service = list_head(&entry->services);
		while(service) {
			struct service *svc = list_ref(service, struct service, link);
			printf("%s ", svc->service);
			for(int i = 0; i < 4; i++) {
				if(svc->on_status[i] != default_actions[i])
					printf("[%s=%s] ", stsmap[i], actmap[svc->on_status[i]]);
			}
			service = list_next(service);
			free(svc->service);
			free(svc);
		}
		printf("\n");
		line = list_next(line);
		free(entry);
	}
}

#endif
