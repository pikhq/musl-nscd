%{
#include "parse_common.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
%}

%x COMMENT
%x LIST
%x ACTION

%%

"\n" |
<LIST,ACTION,COMMENT>"\n" { BEGIN INITIAL; return '\n'; }

aliases:?	{ yylval.database = DB_ALIASES; BEGIN LIST; return TOK_DB; }
automount:?	{ yylval.database = DB_AUTOMOUNT; BEGIN LIST; return TOK_DB; }
ethers:?	{ yylval.database = DB_ETHERS; BEGIN LIST; return TOK_DB; }
group:?		{ yylval.database = DB_GROUP; BEGIN LIST; return TOK_DB; }
hosts:?		{ yylval.database = DB_HOSTS; BEGIN LIST; return TOK_DB; }
initgroups:?	{ yylval.database = DB_INITGROUPS; BEGIN LIST; return TOK_DB; }
netgroup:?	{ yylval.database = DB_NETGROUP; BEGIN LIST; return TOK_DB; }
networks:?	{ yylval.database = DB_NETWORKS; BEGIN LIST; return TOK_DB; }
passwd:?	{ yylval.database = DB_PASSWD; BEGIN LIST; return TOK_DB; }
protocols:?	{ yylval.database = DB_PROTOCOLS; BEGIN LIST; return TOK_DB; }
publickey:?	{ yylval.database = DB_PUBLICKEY; BEGIN LIST; return TOK_DB; }
rpc:?		{ yylval.database = DB_RPC; BEGIN LIST; return TOK_DB; }
services:?	{ yylval.database = DB_SERVICES; BEGIN LIST; return TOK_DB; }
shadow:?	{ yylval.database = DB_SHADOW; BEGIN LIST; return TOK_DB; }

<LIST>"["	{ BEGIN ACTION; return '['; }
<LIST>([[:alnum:]]|_)+ {
	yylval.str = strndup(yytext, yyleng);
	return TOK_STRING;
}
<LIST>[ \t] { ; }

<ACTION>"!"|"="		{ return *yytext; }
<ACTION>"]"		{ BEGIN LIST; return *yytext; }
<ACTION>"SUCCESS"	{ yylval.status = STS_SUCCESS; return TOK_STS; }
<ACTION>"NOTFOUND"	{ yylval.status = STS_NOTFOUND; return TOK_STS; }
<ACTION>"UNAVAIL"	{ yylval.status = STS_UNAVAIL; return TOK_STS; }
<ACTION>"TRYAGAIN"	{ yylval.status = STS_TRYAGAIN; return TOK_STS; }
<ACTION>"return"	{ yylval.action = ACT_RETURN; return TOK_ACT; }
<ACTION>"continue"	{ yylval.action = ACT_CONTINUE; return TOK_ACT; }
<ACTION>"merge"		{ yylval.action = ACT_MERGE; return TOK_ACT; }

"#"			BEGIN COMMENT;

<COMMENT>[^\n]*		;

<LIST,ACTION,INITIAL>.	return *yytext;
%%

int yywrap(void)
{
	return 1;
}
