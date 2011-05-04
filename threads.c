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

#include <pthread.h>
#include <stdio.h>
#include <errno.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>

static pthread_t ttun;
static pthread_t tsock;

void *thread_tun(void *arg)
{
	while (1) {
		dbg_thread("Waiting for tun input");
		sleep_on_tun_empty(SLEEP_GAP);
		while (!queue_tun_isempty()) {
			dbg_thread("Processing tun input");
			dequeue_tun();
		}
		do_keepalive();
	}
	return NULL;
}

void *thread_sock(void *arg)
{
	while (1) {
		dbg_thread("Waiting for sock input");
		sleep_on_sock_empty(SLEEP_GAP);
		while (!queue_sock_isempty()) {
			dbg_thread("Processing sock input");
			dequeue_sock();
		}
	}
	return NULL;
}

int create_threads(void)
{
	if (pthread_create(&ttun, NULL, thread_tun, NULL)) {
		tspslog(LOG_ERR, "Failed to create TUN process thread: %s",
			strerror(errno));
		return -1;
	}
	if (pthread_create(&tsock, NULL, thread_sock, NULL)) {
		tspslog(LOG_ERR, "Failed to create socket process thread: %s",
			strerror(errno));
		return -1;
	}
	return 0;
}

void main_loop(void)
{
	int nfds;
	fd_set ofdset, fdset;

	FD_ZERO(&ofdset);
	FD_SET(server.tunfd, &ofdset);
	FD_SET(server.sockfd, &ofdset);
	if (server.tunfd > server.sockfd)
		nfds = server.tunfd + 1;
	else
		nfds = server.sockfd + 1;
	while (1) {
		memcpy(&fdset, &ofdset, sizeof(fd_set));
		if (select(nfds, &fdset, NULL, NULL, NULL) < 0) {
			perror("Select error");
			break;
		}

		if (FD_ISSET(server.tunfd, &fdset))
			enqueue_tun();

		if (FD_ISSET(server.sockfd, &fdset))
			enqueue_sock();
	}
}

