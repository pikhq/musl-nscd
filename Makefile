srcdir = .
exec_prefix = /usr/local
bindir = $(exec_prefix)/bin
sbindir = $(exec_prefix)/sbin
prefix = /usr/local
includedir = $(prefix)/include
libdir = $(prefix)/lib

SRC_DIRS = $(addprefix $(srcdir)/,src port)
GEN_SRCS = $(sort $(patsubst $(srcdir)/%.y,obj/%.tab.c,$(wildcard $(addsuffix /*.y,$(SRC_DIRS)))) \
              $(patsubst $(srcdir)/%.l,obj/%.yy.c,$(wildcard $(addsuffix /*.l,$(SRC_DIRS)))))
SRCS = $(sort $(wildcard $(addsuffix /*.c,$(SRC_DIRS))))
OBJS = $(sort $(patsubst %,%.o,$(basename $(GEN_SRCS))) \
         $(addprefix obj/,$(patsubst $(srcdir)/%,%.o,$(basename $(SRCS)))))
PORTS = $(sort $(wildcard $(srcdir)/port/*.c))
TESTS = $(addprefix obj/test/,$(sort $(patsubst $(srcdir)/%,%,$(basename $(PORTS)))))
HEADERS = $(sort $(wildcard $(srcdir)/include/*))
TOOLS = obj/nscd

GENH = obj/include/config.h

LDFLAGS =
CPPFLAGS =
CFLAGS = -Os -pipe
CFLAGS_C99 = -std=c99

CFLAGS_ALL = $(CFLAGS_C99)
CFLAGS_ALL += -D_XOPEN_SOURCE=700 -I$(srcdir)/include -Iobj/include
CFLAGS_ALL += $(CPPFLAGS) $(CFLAGS_AUTO) $(CFLAGS)

LDFLAGS_ALL = $(LDFLAGS_AUTO) $(LDFLAGS)
LDLIBS += $(LDLIBS_AUTO)

INSTALL = $(srcdir)/tools/install.sh

-include config.mak

all: $(TOOLS)

OBJ_DIRS = $(sort $(patsubst %/,%,$(dir $(BINS) $(OBJS) $(TESTS) $(GENH))) obj/src obj/include)

$(TESTS) $(BINS) $(OBJS) $(GENH): | $(OBJ_DIRS)

$(OBJ_DIRS):
	mkdir -p $@

obj/include/config.h: $(srcdir)/tools/gen_config.sh $(TESTS)
	$(srcdir)/tools/gen_config.sh $(srcdir) >$@

$(OBJS): $(HEADERS)

obj/%.o: obj/%.c $(GENH)
	$(CC) $(CFLAGS_ALL) -c -o $@ $<

obj/%.o: $(srcdir)/%.c $(GENH)
	$(CC) $(CFLAGS_ALL) -c -o $@ $<

ifdef MODIFY_SRC
$(srcdir)/dist/%.yy.c: $(srcdir)/%.l
	$(LEX) -t $< >$@

$(srcdir)/dist/%.tab.c: $(srcdir)/%.y
	$(YACC) -b $* $<

$(srcdir)/dist/src:
	mkdir -p $@

genfiles: $(srcdir)/dist/src
genfiles: $(patsubst $(srcdir)/%.l,$(srcdir)/dist/%.yy.c,$(wildcard $(add_suffix /*.l,$(SRC_DIRS))))
genfiles: $(patsubst $(srcdir)/%.y,$(srcdir)/dist/%.tab.c,$(wildcard $(add_suffix /*.y,$(SRC_DIRS))))
endif

ifdef LEX
obj/%.yy.c: $(srcdir)/%.l
	$(LEX) -t $< >$@
else
obj/%.yy.c: $(srcdir)/dist/%.yy.c
	cp $< $@
endif

ifdef YACC
obj/%.tab.c: $(srcdir)/%.y
	$(YACC) -b obj/$* $<
else
obj/%.tab.c: $(srcdir)/dist/%.tab.c
	cp $< $@
endif

obj/nscd: $(OBJS)
	$(CC) $(CFLAGS_ALL) $(LDFLAGS_ALL) $^ $(LDLIBS) -o $@

obj/test/%: $(srcdir)/%.c
	$(CC) $(CFLAGS_ALL) -DTEST $(LDFLAGS_ALL) $< $(LDLIBS) -o $@ >/dev/null 2>&1 || cat </dev/null >$@

$(DESTDIR)$(bindir)/%: obj/%
	$(INSTALL) -D $< $@

$(DESTDIR)$(sbindir)/%: obj/%
	$(INSTALL) -D $< $@

$(DESTDIR)$(includedir)/%: $(srcdir)/include/%
	$(INSTALL) -D -m 644 $< $@

install-headers: $(DESTDIR)$(includedir)/nss.h

install-tools: $(TOOLS:obj/%=$(DESTDIR)$(sbindir)/%)

install: install-tools install-headers

clean:
	rm -rf obj

distclean: clean
	rm -f config.mak

.PHONY: all install-tools install clean dist-clean genfiles
