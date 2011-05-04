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
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <stdint.h>
#include <syslog.h>

struct keepalive_info;
#define PAYLOADLEN 8
#define ICMP6LEN (sizeof(struct icmp6_hdr) + PAYLOADLEN)
#define IP6LEN (sizeof(struct ip6_hdr) + ICMP6LEN)
#define BUFLEN 256
#define REALM "cdpatsps"

struct client_session {
	struct in_addr		nataddr;
	struct in_addr		v4addr;
	uint16_t		v4port;
	struct in6_addr		v6addr;
	int			status;
	int			mode;
	int			keepalive;
	int			refcnt;
	char			nonce[9];
	time_t			lastrcv;
	time_t			lastsnd;
	struct keepalive_info	*kai;
	struct client_session	*v4next;
	struct client_session	*v4priv;
	struct client_session	*v6next;
	struct client_session	*v6priv;
};

enum {
	STAT_HELLO,
	STAT_AUTH,
	STAT_AUTH_PLAIN,
	STAT_AUTH_MD5,
	STAT_AUTH_MD5_OK,
	STAT_CREATE,
	STAT_CONFIRM,
	STAT_ESTAB,
	STAT_DESTROY
};

struct keepalive_info {
	time_t			expire;
	uint8_t			kapkt[IP6LEN];
	struct client_session	*session;
	struct keepalive_info	*next;
	struct keepalive_info	*priv;
};

struct tspserver {
	char			tundev[32];
	struct sockaddr_in	v4sockaddr;
	struct sockaddr_in6	v6sockaddr;
	struct in6_addr		v6prefix;
	struct in6_addr		v6postfixmask;
	uint8_t			v6prefixlen;
	uint8_t			mode;
	int			tunfd;
	int			sockfd;
	int			debug;
	char			*dbhost;
	char			*dbuser;
	char			*dbpass;
	char			*dbname;
};

enum {
	UNDEFINED_MODE,
	ANONYMOUS_MODE,
	AUTHENTICATED_MODE,
	HYBRID_MODE,
};

enum {
	MTU = 1500,
	PHDRSZ = 16,
	SLEEP_GAP = 1,
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
void tun_read(void *data, int *len);
void tun_write(void *data, int len);

/* socket.c */
int bind_socket(void);
void socket_recvfrom(void *data, int *len,
			const struct sockaddr_in *addr, socklen_t *scklen);
void socket_sendto(void *data, int len,
			const struct in_addr *addr, in_port_t port);
void socket_ping(const struct in_addr *addr, in_port_t port,
		uint8_t icmp6buf[IP6LEN]);
void build_icmp6(uint8_t icmp6buf[IP6LEN], const struct in6_addr *addr6);

/* session.c
 *
 * One of the put_session or kill_session must be called after
 * got session from get_session_byv[64].
 *
 * get_session_byv4 automatically creates session if not exist.
 *
 * session_set_v6_addr must be called between get_session_* and
 * {put|kill}_session.
 */
struct client_session *get_session(struct client_session *session);
struct client_session *get_session_byv4(const struct sockaddr_in *addr);
struct client_session *get_session_byv6(const struct in6_addr *addr6);
void put_session(struct client_session *session);
void kill_session(struct client_session *session);
void session_set_v6addr(struct client_session *session, struct in6_addr *addr6);
void timeout_session(struct client_session *session);

/* queue.c */
int queue_tun_isempty(void);
int queue_sock_isempty(void);
void enqueue_tun(void);
void enqueue_sock(void);
void dequeue_tun(void);
void dequeue_sock(void);
void sleep_on_tun_empty(int seconds);
void sleep_on_sock_empty(int seconds);

/* threads.c */
int create_threads(void);
void main_loop(void);

/* tsp.c */
void process_tun_packet(const char *data, ssize_t len);
void process_sock_packet(const struct sockaddr_in *client, char *data, ssize_t len);

/* keepalive.c */
void insert_keepalive(struct client_session *session);
void remove_keepalive(struct client_session *session);
void do_keepalive(void);

/* login.c */
void build_md5_challenge(struct client_session *session, char challenge[BUFLEN]);
int login_md5(struct client_session *session, char *data, ssize_t dlen, char md5sresp[BUFLEN]);
int login_plain(struct client_session *session, const char *user, const char *pass);
void login_anonymous(struct client_session *session);

/* xml.c */
void parse_tunnel_request(char *xml, int contlen, struct tunnel_request *req);
char *build_tunnel_offer(struct client_session *session);
void parse_tunnel_ack(char *xml, int contlen, struct tunnel_ack *ack);

/* mysql.c */
int mysql_initialize(void);
int mysql_get_userid(const char *user);
int mysql_get_passhash(const char *user, char *pass);

/* log.c */
void tspslog(int prio, const char *msg, ...);

/* debug.c */
void dbg_thread(const char *dbgmsg, ...);
void dbg_tsp(const char *dbgmsg, ...);
void dbg_xml(const char *dbgmsg, ...);
void dbg_keepalive(const char *dbgmsg, ...);
void dbg_mysql(const char *dbgmsg, ...);
void dbg_login(const char *dbgmsg, ...);

#endif
