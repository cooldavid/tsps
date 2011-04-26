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

#include <string.h>

int login_plain(struct client_session *session, const char *user, const char *pass)
{
	/*
	 * FIXME: Check username/password from database
	 */
	return -1;
}

void login_anonymous(struct client_session *session)
{
	struct in6_addr v6addr;

	memcpy(&v6addr, &server.v6sockaddr.sin6_addr, sizeof(v6addr));
	v6addr.s6_addr16[5] = (session->v4addr.s_addr >> 16) & 0xFFFF;
	v6addr.s6_addr16[6] = (session->v4addr.s_addr) & 0xFFFF;
	v6addr.s6_addr16[7] = session->v4port;
	session_set_v6addr(session, &v6addr);
}

