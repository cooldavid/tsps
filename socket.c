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
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>

int bind_socket(void)
{
	server.sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (server.sockfd == -1) {
		tspslog(LOG_ERR, "Failed to create UDPv4 socket");
		return -1;
	}
	if (bind(server.sockfd,
			(struct sockaddr *)&server.v4sockaddr,
			sizeof(struct sockaddr_in)) != 0) {
		tspslog(LOG_ERR, "Failed to bind to UDPv4 %s:%d: %s",
				inet_ntoa(server.v4sockaddr.sin_addr),
				ntohs(server.v4sockaddr.sin_port),
				strerror(errno));
		return -1;
	}

	return 0;
}

void socket_sendto(void *data, int len, struct in_addr *addr, in_port_t port)
{
	struct sockaddr_in saddr;
	socklen_t scklen = sizeof(saddr);
	int rc;

	saddr.sin_family = AF_INET;
	saddr.sin_addr.s_addr = addr->s_addr;
	saddr.sin_port = htons(port);
	do {
		rc = sendto(server.sockfd, data, len, 0, (struct sockaddr *)&saddr, scklen);
		if (rc == -1 &&
		    errno != EAGAIN && errno != EINTR) {
			tspslog(LOG_ERR, "Fail to send to server UDP socket");
			break;
		}
	} while (rc <= 0);
}

