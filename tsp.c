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
#include <strings.h>
#include <ctype.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <arpa/inet.h>

#ifdef linux
#include <linux/if_tun.h>
#endif

struct tsphdr {
	uint32_t seq;
	uint32_t timestamp;
	char data[0];
} __attribute__ ((packed));

void process_tun_packet(const char *data, ssize_t len)
{
	struct tun_pi *pi = (struct tun_pi *)data;
	struct ip6_hdr *v6hdr = (struct ip6_hdr *)(data + sizeof(struct tun_pi));
	struct client_session *session;

	if (len < (sizeof (struct tun_pi) + sizeof (struct ip6_hdr)))
		return;
	if (pi->proto != htons (ETH_P_IPV6))
		return;

	/*
	 * NOTE: Handle broadcast/multicast destination?
	 */
	session = search_session_byv6(&v6hdr->ip6_dst);
	if (!session)
		return;

	socket_sendto(v6hdr, len - sizeof(struct tun_pi),
			&session->v4addr, session->v4port);
}

static void tsp_reply(struct client_session *session,
			struct tsphdr *tsp, const char *msg)
{
	int len = strlen(msg);

	if ((len + sizeof(struct tsphdr)) > MTU)
		len = MTU - sizeof(struct tsphdr);
	strncpy(tsp->data, msg, len);
	socket_sendto(tsp, len + sizeof(struct tsphdr),
			&session->v4addr, session->v4port);
}

static void tsp_version_cap(struct client_session *session,
				struct tsphdr *tsp, ssize_t dlen)
{
	static const char *verpfx = "VERSION=2.0.";
	char cap[256];

	if (strncasecmp(tsp->data, verpfx, strlen(verpfx))) {
		tsp_reply(session, tsp, "302 Unsupported client version\r\n");
		kill_session(session);
		return;
	}

	strcpy(cap, "CAPABILITY");
	strcat(cap, " TUNNEL=V6UDPV4");
	if (server.mode == ANONYMOUS_MODE || server.mode == HYBRID_MODE)
		strcat(cap, " AUTH=ANONYMOUS");
	if (server.mode == AUTHENTICATED_MODE || server.mode == HYBRID_MODE) {
		strcat(cap, " AUTH=PLAIN");
		/* FIXME: strcat(cap, " AUTH=PLAIN AUTH=DIGEST-MD5"); */
	}
	strcat(cap, "\r\n");
	tsp_reply(session, tsp, cap);
	session->status = STAT_AUTH;
}

static void tsp_auth_plain(struct client_session *session,
				struct tsphdr *tsp, ssize_t dlen)
{
	static const char *authfail = "300 Authentication failed\r\n";
	static const char *authok = "200 Success\r\n";
	char *endptr, *user, *pass;

	if (dlen < 4)
		goto auth_fail;

	user = strtok_r(tsp->data + 1, "\r\n", &endptr);
	if (!user || (dlen < (strlen(user) + 4)))
		goto auth_fail;

	pass = strtok(endptr + 1, "\r\n");
	if (!pass || (dlen < (strlen(user) + strlen(pass) + 4)))
		goto auth_fail;

	if (!login_plain(session, user, pass)) {
		tsp_reply(session, tsp, authok);
		session->status = STAT_CREATE;
		return;
	}

auth_fail:
	tsp_reply(session, tsp, authfail);
	kill_session(session);
}

static void tsp_auth(struct client_session *session,
				struct tsphdr *tsp, ssize_t dlen)
{
	static const char *authpfx = "AUTHENTICATE";
	static const char *authfail = "300 Authentication failed\r\n";
	static const char *authok = "200 Success\r\n";
	char *authtype;

	if (dlen <= strlen(authpfx) + 2 ||
	    strncasecmp(tsp->data, authpfx, strlen(authpfx))) {
		tsp_reply(session, tsp, authfail);
		kill_session(session);
		return;
	}

	authtype = tsp->data + strlen(authpfx) + 1;
	if (server.mode == ANONYMOUS_MODE || server.mode == HYBRID_MODE) {
		if (!strncasecmp(authtype, "ANONYMOUS", 9)) {
			tsp_reply(session, tsp, authok);
			login_anonymous(session);
			session->mode = ANONYMOUS_MODE;
			session->status = STAT_CREATE;
			return;
		}
	}

	if (server.mode == AUTHENTICATED_MODE || server.mode == HYBRID_MODE) {
		if (!strncasecmp(authtype, "PLAIN", 5)) {
			tsp_reply(session, tsp, "");
			session->mode = AUTHENTICATED_MODE;
			session->status = STAT_AUTH_PLAIN;
			return;
		}
	}

	/*
	 * FIXME: Implement digest-md5 auth here
	 */

	tsp_reply(session, tsp, authfail);
	kill_session(session);
}

static int extract_xml(char *data, ssize_t dlen, int *contlen, char **xml)
{
	static const char *prefix = "Content-length:";
	char *ptr, *eptr;

	if (dlen < strlen(prefix) + 2)
		return -1;

	if (strncasecmp(data, prefix, strlen(prefix)))
		return -1;

	ptr = data + strlen(prefix);
	while (isspace(*ptr))
		++ptr;
	if (!isdigit(*ptr))
		return -1;
	*contlen = strtol(ptr, &eptr, 10);
	if (ptr == eptr || !isspace(*eptr))
		return -1;

	ptr = eptr;
	while (isspace(*ptr))
		++ptr;
	*xml = ptr;

	if (dlen < ((ptr - data) + strlen(ptr)) ||
	    *contlen != strlen(ptr))
		return -1;

	return 0;
}

static void tsp_create_tunnel(struct client_session *session,
				struct tsphdr *tsp, ssize_t dlen)
{
	static const char *createfail = "310 Unsupported client tunnel\r\n";
	struct in_addr v4addr;
	struct tunnel_request req;
	char *xml;
	int contlen;

	if (extract_xml(tsp->data, dlen, &contlen, &xml))
		goto create_error;

	parse_tunnel_request(xml, contlen, &req);
	if (strcasecmp(req.action, "create"))
		goto create_error;
	if (strcasecmp(req.type, "v6udpv4"))
		goto create_error;
	if (strcasecmp(req.proxy, "no"))
		goto create_error;
	if (!inet_aton(req.v4addr, &v4addr))
		goto create_error;
	if (v4addr.s_addr != session->v4addr.s_addr) {
		session->nataddr.s_addr = v4addr.s_addr;
	}
	session->keepalive = req.keepalive;

	dbg_tsp("Create tunnel check passed");
	tsp_reply(session, tsp, build_tunnel_offer(session));
	session->status = STAT_CONFIRM;
	return;

create_error:
	tsp_reply(session, tsp, createfail);
	kill_session(session);

}

static void tsp_confirm_tunnel(struct client_session *session,
				struct tsphdr *tsp, ssize_t dlen)
{
	static const char *conffail = "310 Failed to confirm client tunnel\r\n";
	struct tunnel_ack ack;
	char *xml;
	int contlen;

	if (extract_xml(tsp->data, dlen, &contlen, &xml))
		goto ack_error;

	parse_tunnel_ack(xml, contlen, &ack);
	if (strcasecmp(ack.action, "accept"))
		goto ack_error;

	tsp_reply(session, tsp, "");
	session->status = STAT_ESTAB;
	return;

ack_error:
	tsp_reply(session, tsp, conffail);
	kill_session(session);
}

static void tsp_disconnect(struct client_session *session,
				struct tsphdr *tsp, ssize_t dlen)
{
	tsp_reply(session, tsp, "310 TSP status error\r\n");
	tspslog(LOG_INFO, "Client %s:%u %s",
			inet_ntoa(session->v4addr),
			session->v4port,
			(session->status == STAT_HELLO)?
				"unauthorized": "disconnected");
	kill_session(session);
}

static void tsp_data(struct client_session *session,
				struct tsphdr *tsp, ssize_t dlen)
{
	struct ip6_hdr *v6hdr = (struct ip6_hdr *)tsp;
	static char addr1[64], addr2[64];

	if (memcmp(&v6hdr->ip6_src, &session->v6addr, sizeof(struct in6_addr))) {
		tspslog(LOG_ERR, "Droped packet due to client v6 address mismatch:\n\t%s\n\t%s",
				inet_ntop(AF_INET6, &v6hdr->ip6_src, addr1, sizeof(addr1)),
				inet_ntop(AF_INET6, &session->v6addr, addr2, sizeof(addr2)));
		return;
	}

	tun_write(tsp, dlen);
}

void process_sock_packet(const struct sockaddr_in *client,
				char *data, ssize_t len)
{
	struct client_session *session;
	struct tsphdr *tsphdr = (struct tsphdr *)data;

	if (len <= sizeof(struct tsphdr))
		return;

	session = search_session_byv4(client);
	if (!session)
		session = create_session(client);
	if ((tsphdr->seq & 0xF0000000u) == 0xF0000000u) {
		data[len] ='\0';
		len -= sizeof(struct tsphdr);
		dbg_tsp("=============== Received ==============");
		dbg_tsp("%s", tsphdr->data);
		dbg_tsp("=======================================");
		switch (session->status) {
		case STAT_HELLO:
			dbg_tsp("STAT_HELLO");
			tspslog(LOG_INFO, "Client %s:%u connecting.",
					inet_ntoa(client->sin_addr),
					ntohs(client->sin_port));
			tsp_version_cap(session, tsphdr, len);
			break;
		case STAT_AUTH:
			dbg_tsp("STAT_AUTH");
			tsp_auth(session, tsphdr, len);
			break;
		case STAT_AUTH_PLAIN:
			dbg_tsp("STAT_AUTH_PLAIN");
			tsp_auth_plain(session, tsphdr, len);
			break;
		case STAT_CREATE:
			dbg_tsp("STAT_CREATE");
			tsp_create_tunnel(session, tsphdr, len);
			break;
		case STAT_CONFIRM:
			dbg_tsp("STAT_CONFIRM");
			tsp_confirm_tunnel(session, tsphdr, len);
			if (session->status == STAT_ESTAB)
				tspslog(LOG_INFO, "Client %s:%u connected.",
						inet_ntoa(client->sin_addr),
						ntohs(client->sin_port));
			break;
		case STAT_ESTAB:
			dbg_tsp("STAT_ESTAB");
			tsp_disconnect(session, tsphdr, len);
			break;
		}
	} else {
		if (session->status == STAT_ESTAB)
			tsp_data(session, tsphdr, len);
		else
			tsp_disconnect(session, tsphdr, len);
	}
}

