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
	struct in6_addr v6addr;
	int id = mysql_get_userid(user, pass);
	if (id == -1)
		return -1;

	memcpy(&v6addr, &server.v6prefix, sizeof(v6addr));
	v6addr.s6_addr32[3] = htonl(id);
	session_set_v6addr(session, &v6addr);
	return 0;
}

void login_anonymous(struct client_session *session)
{
	struct in6_addr v6addr;
	int i;

	memcpy(&v6addr, &server.v6prefix, sizeof(v6addr));
	for (i = 0; i < 3; ++i)
		v6addr.s6_addr32[i] |= server.v6postfixmask.s6_addr32[i];
	v6addr.s6_addr16[5] = (session->v4addr.s_addr) & 0xFFFFu;
	v6addr.s6_addr16[6] = (session->v4addr.s_addr >> 16) & 0xFFFFu;
	v6addr.s6_addr16[7] = htons(session->v4port);
	session_set_v6addr(session, &v6addr);
}

