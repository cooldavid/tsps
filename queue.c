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

#include <unistd.h>
#include <stdlib.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>
#include <time.h>

enum {
	QUEUE_SIZE = 32,
};
static char queue_tun[QUEUE_SIZE][MTU];
static char queue_sock[QUEUE_SIZE][MTU];
static ssize_t length_tun[QUEUE_SIZE];
static ssize_t length_sock[QUEUE_SIZE];
static struct sockaddr_in client_addr[QUEUE_SIZE];
static int freeptr_tun, curptr_tun = -1;
static int freeptr_sock, curptr_sock = -1;

static pthread_mutex_t lock_tunqueue = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t lock_sockqueue = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t cond_tunqueue = PTHREAD_COND_INITIALIZER;
static pthread_cond_t cond_sockqueue = PTHREAD_COND_INITIALIZER;

int queue_tun_isfull(void)
{
	int rt;
	pthread_mutex_lock(&lock_tunqueue);
	rt = (freeptr_tun == curptr_tun);
	pthread_mutex_unlock(&lock_tunqueue);
	return rt;
}

int queue_sock_isfull(void)
{
	int rt;
	pthread_mutex_lock(&lock_sockqueue);
	rt = (freeptr_sock == curptr_sock);
	pthread_mutex_unlock(&lock_sockqueue);
	return rt;
}

static inline int _queue_tun_isempty(void)
{
	return ((curptr_tun + 1) % QUEUE_SIZE) == freeptr_tun;
}

static inline int _queue_sock_isempty(void)
{
	return ((curptr_sock + 1) % QUEUE_SIZE) == freeptr_sock;
}

int queue_tun_isempty(void)
{
	int rt;
	pthread_mutex_lock(&lock_tunqueue);
	rt = _queue_tun_isempty();
	pthread_mutex_unlock(&lock_tunqueue);
	return rt;
}

int queue_sock_isempty(void)
{
	int rt;
	pthread_mutex_lock(&lock_sockqueue);
	rt = _queue_sock_isempty();
	pthread_mutex_unlock(&lock_sockqueue);
	return rt;
}

void enqueue_tun(void)
{
	int ptr;

	pthread_mutex_lock(&lock_tunqueue);
	if (freeptr_tun == curptr_tun) {
		pthread_mutex_unlock(&lock_tunqueue);
		return;
	}
	ptr = (freeptr_tun++) % QUEUE_SIZE;
	freeptr_tun %= QUEUE_SIZE;
	pthread_mutex_unlock(&lock_tunqueue);

	tun_read(queue_tun[ptr], &length_tun[ptr]);
	pthread_cond_signal(&cond_tunqueue);
}

void enqueue_sock(void)
{
	int ptr;
	socklen_t socklen = sizeof(struct sockaddr_in);

	pthread_mutex_lock(&lock_sockqueue);
	if (freeptr_sock == curptr_sock) {
		pthread_mutex_unlock(&lock_sockqueue);
		return;
	}
	ptr = (freeptr_sock++) % QUEUE_SIZE;
	freeptr_sock %= QUEUE_SIZE;
	pthread_mutex_unlock(&lock_sockqueue);

	socket_recvfrom(queue_sock[ptr], &length_sock[ptr],
			&client_addr[ptr], &socklen);
	pthread_cond_signal(&cond_sockqueue);
}

void drop_tun(void)
{
	static char dummy[MTU];
	ssize_t length;

	tspslog(LOG_WARNING, "Dropped packet from TUN interface");
	tun_read(dummy, &length);
}

void drop_sock(void)
{
	static char dummy[MTU];
	ssize_t length;

	tspslog(LOG_WARNING, "Dropped packet from UDP socket");
	socket_recvfrom(dummy, &length, NULL, NULL);
}

void dequeue_tun(void)
{
	int ptr;

	pthread_mutex_lock(&lock_tunqueue);
	if (_queue_tun_isempty()) {
		pthread_mutex_unlock(&lock_tunqueue);
		return;
	}
	ptr = (++curptr_tun) % QUEUE_SIZE;
	curptr_tun %= QUEUE_SIZE;
	pthread_mutex_unlock(&lock_tunqueue);

	process_tun_packet(queue_tun[ptr], length_tun[ptr]);
}

void dequeue_sock(void)
{
	int ptr;

	pthread_mutex_lock(&lock_sockqueue);
	if (_queue_sock_isempty()) {
		pthread_mutex_unlock(&lock_sockqueue);
		return;
	}
	ptr = (++curptr_sock) % QUEUE_SIZE;
	curptr_sock %= QUEUE_SIZE;
	pthread_mutex_unlock(&lock_sockqueue);

	process_sock_packet(&client_addr[ptr], queue_sock[ptr], length_sock[ptr]);
}

void sleep_on_tun_empty(int seconds)
{
	struct timespec ts;
	int rc = 0;

	pthread_mutex_lock(&lock_tunqueue);
	clock_gettime(CLOCK_REALTIME, &ts);
	ts.tv_sec += seconds;
	while (rc != ETIMEDOUT) {
		rc = pthread_cond_timedwait(&cond_tunqueue, &lock_tunqueue, &ts);
		if (rc != 0 && rc != ETIMEDOUT) {
			tspslog(LOG_ERR, "Conditional wait error");
			exit(EXIT_FAILURE);
		}
		if (!_queue_tun_isempty())
			break;
	}
	pthread_mutex_unlock(&lock_tunqueue);
}

void sleep_on_sock_empty(int seconds)
{
	struct timespec ts;
	int rc = 0;

	pthread_mutex_lock(&lock_sockqueue);
	clock_gettime(CLOCK_REALTIME, &ts);
	ts.tv_sec += seconds;
	while (rc != ETIMEDOUT) {
		rc = pthread_cond_timedwait(&cond_sockqueue, &lock_sockqueue, &ts);
		if (rc != 0 && rc != ETIMEDOUT) {
			tspslog(LOG_ERR, "Conditional wait error");
			exit(EXIT_FAILURE);
		}
		if (!_queue_sock_isempty())
			break;
	}
	pthread_mutex_unlock(&lock_sockqueue);
}

