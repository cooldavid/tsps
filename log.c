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
#include <stdlib.h>
#include <string.h>

void tspslog(const char *msg, ...)
{
	va_list ap;
	int len = strlen(msg);
	char *fmt = calloc(1, len + 16);
	if (!fmt)
		return;

	va_start(ap, msg);
	sprintf(fmt, "tsps: %s\n", msg);
	vfprintf(stderr, fmt, ap);
	free(fmt);
}
