#
#   TSP Server
#
#   A TSP Server implementation that follows RFC5572 as much as possible.
#   It is designed to be compatible with FreeNET6 service.
#
#   Copyright (C) 2011  Guo-Fu Tseng <cooldavid@cooldavid.org>
#
#   This program is free software: you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation, either version 3 of the License, or
#   (at your option) any later version.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

MYSQL_CFLAGS=$(shell mysql_config --include)
MYSQL_LDFLAGS=$(shell mysql_config --libs_r)
LDAP_LDFLAGS=-lldap
CFLAGS+=-Wall
LDFLAGS+=-lpthread -lrt -lexpat $(MYSQL_LDFLAGS) $(LDAP_LDFLAGS) -lssl

ifdef DBG
CFLAGS+=-DDEBUG_$(DBG) -g
else
CFLAGS+=-O3
endif

OBJS=$(patsubst %.c,%.o,$(wildcard *.c))

all: tsps

$(OBJS): tsps.h

mysql.o: mysql.c
	$(CC) $(CFLAGS) $(MYSQL_CFLAGS) -c mysql.c

tsps: $(OBJS) tsps.h
	$(CC) -o $@ $(OBJS) $(LDFLAGS)

clean:
	@rm -rf tsps *.o

.PHONY: all clean

