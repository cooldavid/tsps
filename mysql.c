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

#include <my_global.h>
#include <mysql.h>

static MYSQL mysql;

int mysql_initialize(void)
{
	MYSQL *conn;
	MYSQL_RES *result;

	conn = mysql_init(&mysql);
	if (!conn) {
		fprintf(stderr, "Error mysql %u: %s\n",
				mysql_errno(conn), mysql_error(conn));
		return -1;
	}

	if (mysql_real_connect(conn, server.dbhost, server.dbuser,
				server.dbpass, server.dbname, 0, NULL, 0) == NULL) {
		fprintf(stderr, "Error mysql %u: %s\n",
				mysql_errno(conn), mysql_error(conn));
		return -1;
	}

	if (mysql_query(conn, "SELECT `id` FROM `users` LIMIT 1;")) {
		fprintf(stderr, "Error mysql %u: %s\n",
				mysql_errno(conn), mysql_error(conn));
		return -1;
	}

	result = mysql_store_result(conn);
	mysql_free_result(result);
	return 0;
}

int mysql_get_userid(const char *user, const char *pass)
{
	MYSQL_RES *result;
	MYSQL_ROW row;
	int id;
	char query[256];

	sprintf(query, "SELECT `id` FROM `users` WHERE `user`='%s' AND `pass`='%s' AND `state`=1;",
			user, pass);
	dbg_mysql("MySQL Executing: %s", query);
	if (mysql_query(&mysql, query)) {
		tspslog(LOG_ERR, "Error mysql %u: %s\n",
				mysql_errno(&mysql), mysql_error(&mysql));
		dbg_mysql("Error mysql %u: %s\n",
				mysql_errno(&mysql), mysql_error(&mysql));
		return -1;
	}

	result = mysql_store_result(&mysql);
	if (!result) {
		tspslog(LOG_ERR, "Error mysql %u: %s\n",
				mysql_errno(&mysql), mysql_error(&mysql));
		dbg_mysql("Error mysql %u: %s\n",
				mysql_errno(&mysql), mysql_error(&mysql));
		return -1;
	}

	row = mysql_fetch_row(result);
	if (!row) {
		id = -1;
	} else {
		id = strtol(row[0], NULL, 10);
	}
	mysql_free_result(result);

	sprintf(query, "UPDATE `users` SET `lastlogin`=CURRENT_TIMESTAMP()"
			" WHERE `user`='%s';", user);
	if (mysql_query(&mysql, query)) {
		tspslog(LOG_ERR, "Error mysql %u: %s\n",
				mysql_errno(&mysql), mysql_error(&mysql));
		return -1;
	}

	return id;
}

