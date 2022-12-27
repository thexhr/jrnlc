CC = cc

#CFLAGS  = -g3 -ggdb
CFLAGS  = -O2

CFLAGS += -pipe -fdiagnostics-color -Wno-unknown-warning-option -Wpedantic
CFLAGS += -Wall -Werror-implicit-function-declaration -Wno-format-truncation
CFLAGS += -Wstrict-prototypes -Wmissing-prototypes -Wmissing-declarations
CFLAGS += -Wshadow -Wpointer-arith -Wcast-qual -Wswitch-enum
CFLAGS += -Wformat-security -Wformat-overflow=2
CFLAGS += -Wno-padded -Wextra
CFLAGS += `pkg-config --cflags libsodium json-c`
LDADD   = `pkg-config --libs libsodium json-c`

BIN   = jrnlc
OBJS  = jrnlc.o json.o util.o recallocarray.o config.o crypto.o key.o
OBJS += readpassphrase.o

INSTALL ?= install -p

PREFIX ?= /usr/local
BIND ?= $(PREFIX)/bin
MAN ?= $(PREFIX)/man
SHARE ?= $(PREFIX)/share

all: $(BIN)

install: all
	$(INSTALL) -d -m 755 -o root $(MAN)/man1
	$(INSTALL) -m 644 -o root $(BIN).1 $(MAN)/man1
	$(INSTALL) -m 755 -o root $(BIN) $(BIND)

uninstall:
	rm -f $(MAN)/man1/$(BIN).1
	rm -f $(BIND)/$(BIN)

all: $(BIN)

$(BIN): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS) $(LDADD)

.c.o:
	$(CC) $(CFLAGS) -o $@ -c $<

clean:
	rm -f $(BIN) $(OBJS)
