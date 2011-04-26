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
#include "expat.h"

#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <arpa/inet.h>

static void create_tunnel_start(void *data, const char *el, const char **attr)
{
	struct tunnel_request *req = (struct tunnel_request *)data;
	int i;
	const char *key, *val;

	if (!strcasecmp(el, "tunnel")) {
		for (i = 0; attr[i]; i += 2) {
			key = attr[i];
			val = attr[i + 1];
			if (!strcasecmp(key, "action")) {
				strncpy(req->action, val, sizeof(req->action) - 1);
			} else if (!strcasecmp(key, "type")) {
				strncpy(req->type, val, sizeof(req->type) - 1);
			} else if (!strcasecmp(key, "proxy")) {
				strncpy(req->proxy, val, sizeof(req->proxy) - 1);
			}
		}
	} else if (!strcasecmp(el, "address")) {
		for (i = 0; attr[i]; i += 2) {
			key = attr[i];
			val = attr[i + 1];
			if (!strcasecmp(key, "type") && !strcasecmp(val, "ipv4")) {
				req->isv4addr = 1;
				break;
			}
		}
	} else if (!strcasecmp(el, "keepalive")) {
		for (i = 0; attr[i]; i += 2) {
			key = attr[i];
			val = attr[i + 1];
			if (!strcasecmp(key, "interval")) {
				req->keepalive = strtol(val, NULL, 10);
				break;
			}
		}
	}

}

static void create_tunnel_end(void *data, const char *el)
{
	struct tunnel_request *req = (struct tunnel_request *)data;

	if (!strcasecmp(el, "address"))
		req->isv4addr = 0;
}

static void create_tunnel_text(void *data, const char *s, int len)
{
	struct tunnel_request *req = (struct tunnel_request *)data;

	if (req->isv4addr) {
		if (len > (sizeof(req->v4addr) - 1))
			len = sizeof(req->v4addr) - 1;
		strncpy(req->v4addr, s, len);
	}
}

void parse_tunnel_request(char *xml, int contlen, struct tunnel_request *req)
{
	XML_Parser parser = XML_ParserCreate(NULL);
	bzero(req, sizeof(struct tunnel_request));
	XML_SetElementHandler(parser, create_tunnel_start, create_tunnel_end);
	XML_SetCharacterDataHandler(parser, create_tunnel_text);
	strcpy(req->proxy, "no");
	req->keepalive = 30;
	XML_SetUserData(parser, req);
	XML_Parse(parser, xml, contlen, 1);
	XML_ParserFree(parser);
}

char *build_tunnel_offer(struct client_session *session)
{
	static char sendbuf[1024];
	static char xmlbuf[1024];
	static char serverv4[32], serverv6[64], clientv4[32], clientv6[64];

	inet_ntop(AF_INET, &server.v4sockaddr.sin_addr, serverv4, sizeof(serverv4));
	inet_ntop(AF_INET6, &server.v6sockaddr.sin6_addr, serverv6, sizeof(serverv6));
	inet_ntop(AF_INET, &session->v4addr, clientv4, sizeof(clientv4));
	inet_ntop(AF_INET6, &session->v6addr, clientv6, sizeof(clientv6));

	sprintf(xmlbuf, "200 Success\r\n"
		"<tunnel action=\"info\" type=\"v6udpv4\" lifetime=\"604800\">\r\n"
		"	<server>\r\n"
		"		<address type=\"ipv4\">%s</address>\r\n"
		"		<address type=\"ipv6\">%s</address>\r\n"
		"	</server>\r\n"
		"	<client>\r\n"
		"		<address type=\"ipv4\">%s</address>\r\n"
		"		<address type=\"ipv6\">%s</address>\r\n"
		"		<keepalive interval=\"%d\">\r\n"
		"			<address type=\"ipv6\">%s</address>\r\n"
		"		</keepalive>\r\n"
		"	</client>\r\n"
		"</tunnel>\r\n",
		serverv4, serverv6, clientv4, clientv6, session->keepalive, serverv6);
	sprintf(sendbuf, "Content-length: %d\r\n%s", strlen(xmlbuf), xmlbuf);
	dbg_xml("%s", sendbuf);
	return sendbuf;
}

static void ack_tunnel_start(void *data, const char *el, const char **attr)
{
	struct tunnel_ack *ack = (struct tunnel_ack *)data;
	int i;
	const char *key, *val;

	if (!strcasecmp(el, "tunnel")) {
		for (i = 0; attr[i]; i += 2) {
			key = attr[i];
			val = attr[i + 1];
			if (!strcasecmp(key, "action")) {
				strncpy(ack->action, val, sizeof(ack->action) - 1);
				break;
			}
		}
	}
}

static void ack_tunnel_end(void *data, const char *el)
{
}

void parse_tunnel_ack(char *xml, int contlen, struct tunnel_ack *ack)
{
	XML_Parser parser = XML_ParserCreate(NULL);
	bzero(ack, sizeof(struct tunnel_ack));
	XML_SetElementHandler(parser, ack_tunnel_start, ack_tunnel_end);
	XML_SetUserData(parser, ack);
	XML_Parse(parser, xml, contlen, 1);
	XML_ParserFree(parser);
}

