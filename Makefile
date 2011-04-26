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

CFLAGS+=-Wall -I expat-2.0.1/lib
XMLLIB=expat-2.0.1/.libs/libexpat.so
LDFLAGS+=-lpthread -lrt -lexpat -L expat-2.0.1/.libs -Xlinker -rpath=`pwd`/expat-2.0.1/.libs

ifdef DBG
CFLAGS+=-DDEBUG_$(DBG) -g
else
CFLAGS+=-O3
endif

OBJS=$(patsubst %.c,%.o,$(wildcard *.c))

all: tsps

$(OBJS): tsps.h

expat-2.0.1: expat-2.0.1.tar.gz
	tar -zxf expat-2.0.1.tar.gz
	if [ -d $@ ]; then touch $@; fi

expat-2.0.1/Makefile: expat-2.0.1
	cd expat-2.0.1 && ./configure
	if [ -f $@ ]; then touch $@; fi

$(XMLLIB): expat-2.0.1/Makefile
	$(MAKE) -C expat-2.0.1
	if [ -f $@ ]; then touch $@; fi

tsps: $(OBJS) tsps.h $(XMLLIB)
	$(CC) -o $@ $(LDFLAGS) $(OBJS)

clean:
	@rm -rf tsps *.o

distclean: clean
	@rm -rf expat-2.0.1

.PHONY: all clean distclean

