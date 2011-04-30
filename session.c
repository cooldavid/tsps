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

#include <stdlib.h>
#include <string.h>
#include <pthread.h>

enum {
	HASH_SIZE = 1024,
};
static struct client_session *v4hash[HASH_SIZE];
static struct client_session *v6hash[HASH_SIZE];
static pthread_mutex_t lock_session = PTHREAD_MUTEX_INITIALIZER;

static int
hash_v4(const struct sockaddr_in *addr)
{
	uint32_t key;

	key = addr->sin_addr.s_addr;
	key *= ntohs(addr->sin_port);
	key %= HASH_SIZE;
	return key;
}

static int
_hash_v4(const struct in_addr *addr, uint16_t port)
{
	uint32_t key;

	key = addr->s_addr;
	key *= port;
	key %= HASH_SIZE;
	return key;
}

static int
hash_v6(const struct in6_addr *addr6)
{
	uint32_t key;

	key = addr6->s6_addr32[0];
	key += addr6->s6_addr32[1];
	key += addr6->s6_addr32[2];
	key += addr6->s6_addr32[3];
	key %= HASH_SIZE;
	return key;
}

static struct client_session *
search_session_byv4(const struct sockaddr_in *addr)
{
	int key;
	struct client_session *session;

	key = hash_v4(addr);
	session = v4hash[key];
	while (session) {
		if (session->v4addr.s_addr == addr->sin_addr.s_addr &&
		    session->v4port == ntohs(addr->sin_port))
			return session;
		session = session->v4next;
	}

	return NULL;
}

static struct client_session *
search_session_byv6(const struct in6_addr *addr6)
{
	int key;
	struct client_session *session;

	key = hash_v6(addr6);
	session = v6hash[key];
	while (session) {
		if (!memcmp(&session->v6addr, addr6, sizeof(*addr6)))
			return session;
		session = session->v6next;
	}

	return NULL;
}

static void
hashv4_add(struct client_session *newsess)
{
	int key;
	struct client_session *sess;

	key = _hash_v4(&newsess->v4addr, newsess->v4port);
	sess = v4hash[key];
	if (!sess) {
		v4hash[key] = newsess;
	} else {
		while (sess->v4next)
			sess = sess->v4next;
		sess->v4next = newsess;
		newsess->v4priv = sess;
	}
}

static void
hashv6_add(struct client_session *newsess)
{
	int key;
	struct client_session *sess;

	key = hash_v6(&newsess->v6addr);
	sess = v6hash[key];
	if (!sess) {
		v6hash[key] = newsess;
	} else {
		while (sess->v6next)
			sess = sess->v6next;
		sess->v6next = newsess;
		newsess->v6priv = sess;
	}
}

static struct client_session *
create_session(const struct sockaddr_in *addr)
{
	struct client_session *session;

	session = calloc(1, sizeof(*session));
	if (!session) {
		tspslog(LOG_ERR, "Create session: Out of memory");
		exit(EXIT_FAILURE);
	}
	session->v4addr.s_addr = addr->sin_addr.s_addr;
	session->v4port = ntohs(addr->sin_port);
	session->status = STAT_HELLO;

	hashv4_add(session);
	return session;
}

struct client_session *
get_session_byv4(const struct sockaddr_in *addr)
{
	struct client_session *session;

	pthread_mutex_lock(&lock_session);
	session = search_session_byv4(addr);
	if (!session)
		session = create_session(addr);
	++(session->refcnt);
	pthread_mutex_unlock(&lock_session);
	return session;
}

struct client_session *
get_session_byv6(const struct in6_addr *addr6)
{
	struct client_session *session;

	pthread_mutex_lock(&lock_session);
	session = search_session_byv6(addr6);
	++(session->refcnt);
	pthread_mutex_unlock(&lock_session);
	return session;
}

void
session_set_v6addr(struct client_session *session, struct in6_addr *addr6)
{
	pthread_mutex_lock(&lock_session);
	memcpy(&session->v6addr, addr6, sizeof(*addr6));
	hashv6_add(session);
	pthread_mutex_unlock(&lock_session);
}

static void
remove_v4session(struct client_session *session)
{
	int key;

	key = _hash_v4(&session->v4addr, session->v4port);
	if (session->v4priv) {
		session->v4priv->v4next = session->v4next;
		if (session->v4next)
			session->v4next->v4priv = session->v4priv;
	} else {
		v4hash[key] = session->v4next;
	}
}

static void
remove_v6session(struct client_session *session)
{
	int key;

	key = hash_v6(&session->v6addr);
	if (session->v6priv) {
		session->v6priv->v6next = session->v6next;
		if (session->v6next)
			session->v6next->v6priv = session->v6priv;
	} else {
		v6hash[key] = session->v6next;
	}
}

static void
remove_session(struct client_session *session)
{
	static char zeros[32];

	remove_v4session(session);
	if (memcmp(&session->v6addr, zeros, sizeof(struct in6_addr)))
		remove_v6session(session);
}

void
put_session(struct client_session *session)
{
	pthread_mutex_lock(&lock_session);
	if (!(--(session->refcnt)) && session->status == STAT_DESTROY) {
		remove_session(session);
		free(session);
	}
	pthread_mutex_unlock(&lock_session);
}

void
kill_session(struct client_session *session)
{
	pthread_mutex_lock(&lock_session);
	if (!(--(session->refcnt))) {
		remove_session(session);
		free(session);
	} else {
		session->status = STAT_DESTROY;
	}
	pthread_mutex_unlock(&lock_session);
}

