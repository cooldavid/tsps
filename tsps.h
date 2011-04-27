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

#ifndef __TSPS_H_INCLUDDED__
#define __TSPS_H_INCLUDDED__

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <stdint.h>
#include <syslog.h>

struct client_session {
	struct in_addr		nataddr;
	struct in_addr		v4addr;
	uint16_t		v4port;
	struct in6_addr		v6addr;
	int			status;
	int			mode;
	int			keepalive;
	struct client_session	*v4next;
	struct client_session	*v4priv;
	struct client_session	*v6next;
	struct client_session	*v6priv;
};

enum {
	STAT_HELLO,
	STAT_AUTH,
	STAT_AUTH_PLAIN,
	STAT_CREATE,
	STAT_CONFIRM,
	STAT_ESTAB
};

struct tspserver {
	char			tundev[32];
	struct sockaddr_in	v4sockaddr;
	struct sockaddr_in6	v6sockaddr;
	uint8_t			v6prefixlen;
	uint8_t			mode;
	int			tunfd;
	int			sockfd;
};

enum {
	UNDEFINED_MODE,
	ANONYMOUS_MODE,
	AUTHENTICATED_MODE,
	HYBRID_MODE,
};

enum {
	MTU = 1500,
};

struct tunnel_request {
	char	action[32];
	char	type[32];
	char	proxy[32];
	char	v4addr[32];
	int	keepalive;
	int	isv4addr;
};

struct tunnel_ack {
	char	action[32];
};

/* tsps.c */
extern struct tspserver server;

/* tun.c */
int bind_tunif(void);
int tun_setaddr(void);
void tun_write(void *data, int len);

/* socket.c */
int bind_socket(void);
void socket_sendto(void *data, int len,
			struct in_addr *addr, in_port_t port);

/* session.c */
int initialize_session(void);
struct client_session *search_session_byv4(const struct sockaddr_in *addr);
struct client_session *search_session_byv6(const struct in6_addr *addr6);
struct client_session *create_session(const struct sockaddr_in *addr);
void session_set_v6addr(struct client_session *session, struct in6_addr *addr6);
void kill_session(struct client_session *session);

/* queue.c */
int queue_tun_isfull(void);
int queue_sock_isfull(void);
int queue_tun_isempty(void);
int queue_sock_isempty(void);
void enqueue_tun(void);
void enqueue_sock(void);
void drop_tun(void);
void drop_sock(void);
void dequeue_tun(void);
void dequeue_sock(void);
void block_on_tun_empty(void);
void block_on_sock_empty(void);

/* threads.c */
int create_threads(void);
void main_loop(void);

/* tsp.c */
void process_tun_packet(const char *data, ssize_t len);
void process_sock_packet(const struct sockaddr_in *client, char *data, ssize_t len);

/* login.c */
int login_plain(struct client_session *session, const char *user, const char *pass);
void login_anonymous(struct client_session *session);

/* xml.c */
void parse_tunnel_request(char *xml, int contlen, struct tunnel_request *req);
char *build_tunnel_offer(struct client_session *session);
void parse_tunnel_ack(char *xml, int contlen, struct tunnel_ack *ack);

/* log.c */
void tspslog(int prio, const char *msg, ...);

/* debug.c */
void dbg_thread(const char *dbgmsg, ...);
void dbg_tsp(const char *dbgmsg, ...);
void dbg_xml(const char *dbgmsg, ...);

#endif
