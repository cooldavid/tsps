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
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

enum {
	HASH_SIZE = 1024,
};
static struct keepalive_info *kahash[HASH_SIZE];
static pthread_mutex_t lock_keepalive = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t lock_hook = PTHREAD_MUTEX_INITIALIZER;

static int hashkey(time_t seed)
{
	return seed % HASH_SIZE;
}

static void insert_hash(struct keepalive_info *newkai)
{
	int key = hashkey(newkai->expire);
	struct keepalive_info *kai;

	pthread_mutex_lock(&lock_keepalive);
	kai = kahash[key];
	if (!kai) {
		kahash[key] = newkai;
	} else {
		while (kai->next)
			kai = kai->next;
		kai->next = newkai;
		newkai->priv = kai;
	}
	pthread_mutex_unlock(&lock_keepalive);
}

void insert_keepalive(struct client_session *session)
{
	struct keepalive_info *kai;

	kai = calloc(1, sizeof(struct keepalive_info));
	if (!kai) {
		tspslog(LOG_ERR, "Create keepalive info: Out of memory");
		exit(EXIT_FAILURE);
	}
	time(&session->lastrcv);
	kai->expire = time(NULL) + session->keepalive;
	kai->session = session;
	session->kai = kai;
	build_icmp6(kai->kapkt, &session->v6addr);
	insert_hash(kai);

	dbg_keepalive("Hooked keepalive info for session: %s:%u (%p)",
			inet_ntoa(session->v4addr),
			session->v4port,
			session->kai);
}

void remove_keepalive(struct client_session *session)
{
	pthread_mutex_lock(&lock_hook);
	if (session->kai)
		session->kai->session = NULL;
	dbg_keepalive("Unhook keepalive info for killed session: %s:%u (%p)",
			inet_ntoa(session->v4addr),
			session->v4port,
			session->kai);
	pthread_mutex_unlock(&lock_hook);
}

static void unhash_keepalive(struct keepalive_info *kai, int key)
{
	if (kai->priv) {
		kai->priv->next = kai->next;
		if (kai->next)
			kai->next->priv = kai->priv;
	} else {
		kahash[key] = kai->next;
	}
	kai->priv = NULL;
	kai->next = NULL;
}

static struct keepalive_info *pop_keepalive(time_t exp)
{
	int key = hashkey(exp);
	struct keepalive_info *kai;

	pthread_mutex_lock(&lock_keepalive);
	kai = kahash[key];
	while (kai) {
		if (kai->expire <= exp) {
			unhash_keepalive(kai, key);
			pthread_mutex_unlock(&lock_keepalive);
			return kai;
		}
		kai = kai->next;
	}
	pthread_mutex_unlock(&lock_keepalive);
	return kai;
}

static void _do_keepalive(time_t expire)
{
	struct keepalive_info *kai;
	struct client_session *session;
	time_t last;
	struct in_addr ip;
	in_port_t port;
	uint32_t keepalive;

	while ((kai = pop_keepalive(expire)) != NULL) {
		pthread_mutex_lock(&lock_hook);

		/*
		 * Check if session is still exist
		 */
		session = get_session(kai->session);
		if (!session) {
			dbg_keepalive("Free keepalive info for killed session: %p",
					kai);
			free(kai);
			pthread_mutex_unlock(&lock_hook);
			continue;
		}

		/*
		 * Skip keepalive if recent activity is within
		 * keepalive window
		 */
		last = (session->lastrcv < session->lastsnd) ? 
				session->lastrcv :
				session->lastsnd;
		if ((last + session->keepalive) > expire) {
			kai->expire = last + session->keepalive;
			insert_hash(kai);
			dbg_keepalive("Skip keepalive for active channel: "
					"scheduled %u seconds later (%p)",
					kai->expire - time(NULL), kai);
			put_session(session);
			pthread_mutex_unlock(&lock_hook);
			continue;
		}

		/*
		 * Remove session if no action after 5 * keepalive
		 */
		last = (session->lastrcv > session->lastsnd) ? 
				session->lastrcv :
				session->lastsnd;
		if ((last + (session->keepalive * 5)) < time(NULL)) {
			dbg_keepalive("Timeout inactive channel: %s:%u (%p)",
					inet_ntoa(session->v4addr),
					session->v4port, kai);
			timeout_session(session);
			free(kai);
			pthread_mutex_unlock(&lock_hook);
			continue;
		}

		/*
		 * Copy IP/PORT from session before exiting hook lock
		 */
		ip = session->v4addr;
		port = session->v4port;
		keepalive = session->keepalive;

		put_session(session);
		pthread_mutex_unlock(&lock_hook);

		/*
		 * Send ICMPv6 ping over UDPv4 socket
		 */
		dbg_keepalive("Sending keepalive at %u (%p)",
				time(NULL), kai);
		socket_ping(&ip, port, kai->kapkt);
		kai->expire = time(NULL) + keepalive;
		insert_hash(kai);
		dbg_keepalive("Keepalive scheduled %u seconds later (%p)",
				kai->expire - time(NULL), kai);
	}

}

void do_keepalive(void)
{
	time_t expire;

	for (expire = time(NULL) - (SLEEP_GAP * 2);
			expire <= time(NULL);
			++expire) {
		_do_keepalive(expire);
	}
}

