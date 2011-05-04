/*
 *  TSP Server
 *
 *  A TSP Server implementation that follows RFC5572 as much as possible.
 *  It is designed to be compatible with FreeNET6 service.
 *
 *  Copyright (C) 2011  Guo-Fu Tseng <cooldavid@cooldavid.org>
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "tsps.h"

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>

#ifdef DEBUG_ALL
#define DEBUG_THREAD
#define DEBUG_TSP
#define DEBUG_XML
#define DEBUG_KEEPALIVE
#define DEBUG_MYSQL
#define DEBUG_LOGIN
#endif

#define DEBUG_FUNCTION(dbgname) \
	void dbg_ ## dbgname (const char *dbgmsg, ...) \
	{ \
		va_list ap; \
		int len = strlen(dbgmsg); \
		char *fmt = calloc(1, len + 256); \
		va_start(ap, dbgmsg); \
		if (!fmt) \
			return; \
		sprintf(fmt, "dbg_" #dbgname ": %s\n", dbgmsg); \
		if (server.debug) { \
			vprintf(fmt, ap); \
		} else { \
			vsyslog(LOG_DEBUG, fmt, ap); \
		} \
		free(fmt); \
	}

#define NULL_FUNCTION(dbgname) \
	void dbg_ ## dbgname (const char *dbgmsg, ...) {}

#ifdef DEBUG_THREAD
DEBUG_FUNCTION(thread)
#else
NULL_FUNCTION(thread)
#endif

#ifdef DEBUG_TSP
DEBUG_FUNCTION(tsp)
#else
NULL_FUNCTION(tsp)
#endif

#ifdef DEBUG_XML
DEBUG_FUNCTION(xml)
#else
NULL_FUNCTION(xml)
#endif

#ifdef DEBUG_KEEPALIVE
DEBUG_FUNCTION(keepalive)
#else
NULL_FUNCTION(keepalive)
#endif

#ifdef DEBUG_MYSQL
DEBUG_FUNCTION(mysql)
#else
NULL_FUNCTION(mysql)
#endif

#ifdef DEBUG_LOGIN
DEBUG_FUNCTION(login)
#else
NULL_FUNCTION(login)
#endif

