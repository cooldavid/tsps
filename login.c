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
#include <time.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <openssl/md5.h>

static char base64_char[65] = {
	'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
	'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
	'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
	'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
	'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
	'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
	'w', 'x', 'y', 'z', '0', '1', '2', '3',
	'4', '5', '6', '7', '8', '9', '+', '/', '='};

static uint8_t base64_val[255];

static void base64_encode(char dst[BUFLEN], const char src[BUFLEN])
{
	int i, len, a, b, c, d;
	char *enc = dst;

	len = strlen(src);
	for (i = 0; i < len; i += 3) {
		if ((len - i) >= 3) {
			a = (src[i] >> 2) & 0x3F;
			b = ((src[i] << 4) & 0x30) | ((src[i + 1] >> 4) & 0xF);
			c = ((src[i + 1] << 2) & 0x3C) | ((src[i + 2] >> 6) & 0x3);
			d = src[i + 2] & 0x3F;
		} else if ((len - i) == 2) {
			a = (src[i] >> 2) & 0x3F;
			b = ((src[i] << 4) & 0x30) | ((src[i + 1] >> 4) & 0xF);
			c = ((src[i + 1] << 2) & 0x3C);
			d = 64;
		} else {
			a = (src[i] >> 2) & 0x3F;
			b = ((src[i] << 4) & 0x30);
			c = 64;
			d = 64;
		}
		sprintf(enc, "%c%c%c%c",
			base64_char[a], base64_char[b],
			base64_char[c], base64_char[d]);
		enc += 4;
	}
}

static void base64_decode(char buf[BUFLEN])
{
	int i, len, a, b, c;
	char *src, *dst;

	if (!base64_val['/']) {
		for (i = 0; i < 64; ++i)
			base64_val[(uint8_t)base64_char[i]] = i;
	}

	len = strlen(buf);
	src = dst = buf;
	for (i = 0; i < len; i += 4) {
		a = ((base64_val[(uint8_t)src[i]] << 2) & 0xFC) |
			((base64_val[(uint8_t)src[i + 1]] >> 4) & 0x03);
		b = ((base64_val[(uint8_t)src[i + 1]] << 4) & 0xF0) |
			((base64_val[(uint8_t)src[i + 2]] >> 2) & 0x0F);
		c = ((base64_val[(uint8_t)src[i + 2]] << 6) & 0xC0) |
			(base64_val[(uint8_t)src[i + 3]] & 0x3F);
		dst[0] = a;
		dst[1] = b;
		dst[2] = c;
		dst += 3;
	}
	*dst = '\0';
}

void build_md5_challenge(struct client_session *session, char challenge[BUFLEN])
{
	struct timespec ts;
	char textbuf[BUFLEN];

	clock_gettime(CLOCK_REALTIME, &ts);
	srandom(ts.tv_nsec);
	sprintf(session->nonce, "%08X", (unsigned int)random());

	sprintf(textbuf, "realm=\"" REALM "\",nonce=\"%s\",qop=auth,"
			"algorithm=md5-sess,charset=utf8", session->nonce);

	base64_encode(challenge, textbuf);
	strcat(challenge, "\r\n");

	dbg_login("Challenge: %s", textbuf);
	dbg_login("Challenge-base64: %s", challenge);
}

static char *get_value(char *data, const char *key, int *len)
{
	char *ptr, *rt;
	int keylen = strlen(key);
	int quote = 0;

	ptr = strstr(data, key);
	while (ptr && (ptr > data) && *(ptr - 1) != ',')
		ptr = strstr(ptr + 1, key);
	if (!ptr)
		return NULL;

	ptr += keylen;
	if (*ptr == '\"') {
		quote = 1;
		++ptr;
	}

	rt = ptr;
	*len = 0;
	while (isalnum(*ptr) || *ptr == '/' || *ptr == '.' || *ptr == '-') {
		++(*len);
		++ptr;
	}

	if (ptr == rt)
		return NULL;

	if (quote) {
		if (*ptr != '\0' && *ptr != '\"')
			return NULL;
	} else {
		if (*ptr != '\0' && *ptr != ',')
			return NULL;
	}

	return rt;
}

struct md5_resp {
	char *username;
	char *realm;
	char *nonce;
	char *nc;
	char *cnonce;
	char *uri;
	char *response;
};

static int parse_md5_response(char *data, struct md5_resp *md5r)
{
	int username_len, realm_len, nonce_len;
	int nc_len, cnonce_len, uri_len, response_len;

	md5r->username = get_value(data, "username=", &username_len);
	if (!md5r->username)
		return -1;

	md5r->realm = get_value(data, "realm=", &realm_len);
	if (!md5r->realm)
		return -1;

	md5r->nonce = get_value(data, "nonce=", &nonce_len);
	if (!md5r->nonce)
		return -1;

	md5r->nc = get_value(data, "nc=", &nc_len);
	if (!md5r->nc)
		return -1;

	md5r->cnonce = get_value(data, "cnonce=", &cnonce_len);
	if (!md5r->cnonce)
		return -1;

	md5r->uri = get_value(data, "digest-uri=", &uri_len);
	if (!md5r->uri)
		return -1;

	md5r->response = get_value(data, "response=", &response_len);
	if (!md5r->response)
		return -1;

	md5r->username[username_len] = '\0';
	md5r->realm[realm_len] = '\0';
	md5r->nonce[nonce_len] = '\0';
	md5r->nc[nc_len] = '\0';
	md5r->cnonce[cnonce_len] = '\0';
	md5r->uri[uri_len] = '\0';
	md5r->response[response_len] = '\0';
	return 0;
}

static uint8_t _hexval(char c)
{
	if (c >= 'a' && c <= 'f')
		return 10 + (c - 'a');
	if (c >= '0' && c <= '9')
		return c - '0';
	return 0;
}

static uint8_t hexval(const char *str)
{
	return ((_hexval(str[0]) << 4) & 0xF0) | (_hexval(str[1]) & 0x0F);
}

int login_md5(struct client_session *session, char *data, ssize_t dlen, char md5sresp[BUFLEN])
{
	struct md5_resp md5r;
	char passhash[65], buf[BUFLEN];
	unsigned char HA1[16], HEXHA1[33];
	unsigned char HA2[16], HEXHA2[33];
	unsigned char HRESP[16], HEXHRESP[33];
	struct in6_addr v6addr;
	int i, id;

	if (strlen(data) > dlen) {
		printf("%zd > %zd\n", strlen(data), dlen);
		return -1;
	}

	base64_decode(data);
	if (parse_md5_response(data, &md5r))
		return -1;

	if (strcmp(md5r.realm, REALM))
		return -1;

	if (strcmp(md5r.nonce, session->nonce))
		return -1;

	if (strcmp(md5r.nc, "00000001"))
		return -1;

	dbg_login("Username: %s, Realm: %s, Nonce: %s, NC: %s, CNonce: %s, "
		  "Digest-URI: %s, Responce: %s",
		  md5r.username, md5r.realm, md5r.nonce, md5r.nc,
		  md5r.cnonce, md5r.uri, md5r.response);

	if (mysql_get_passhash(md5r.username, passhash))
		return -1;

	dbg_login("MD5-login: Stored hash %s", passhash);

	if (strlen(passhash) != 32)
		return -1;

	/*
	 * Generate and exaim response hash
	 */
	for (i = 0; i < 16; ++i)
		buf[i] = hexval(passhash + (i * 2));
	sprintf(buf + 16, ":%s:%s", md5r.nonce, md5r.cnonce);
	MD5((unsigned char *)buf, strlen(buf + 16) + 16, HA1);
	for (i = 0; i < 16; ++i)
		sprintf((char *)(HEXHA1 + (i * 2)), "%02x", HA1[i]);

	sprintf(buf, "AUTHENTICATE:%s", md5r.uri);
	MD5((unsigned char *)buf, strlen(buf), HA2);
	for (i = 0; i < 16; ++i)
		sprintf((char *)(HEXHA2 + (i * 2)), "%02x", HA2[i]);

	sprintf(buf, "%s:%s:%s:%s:%s:%s",
			HEXHA1, md5r.nonce, md5r.nc,
			md5r.cnonce, "auth", HEXHA2);
	MD5((unsigned char *)buf, strlen(buf), HRESP);
	for (i = 0; i < 16; ++i)
		sprintf((char *)(HEXHRESP + (i * 2)), "%02x", HRESP[i]);

	if (strcmp(md5r.response, (char *)HEXHRESP))
		return -1;

	/*
	 * Generate server response
	 */
	sprintf(buf, ":%s", md5r.uri);
	MD5((unsigned char *)buf, strlen(buf), HA2);
	for (i = 0; i < 16; ++i)
		sprintf((char *)(HEXHA2 + (i * 2)), "%02x", HA2[i]);

	sprintf(buf, "%s:%s:%s:%s:%s:%s",
			HEXHA1, md5r.nonce, md5r.nc,
			md5r.cnonce, "auth", HEXHA2);
	MD5((unsigned char *)buf, strlen(buf), HRESP);
	for (i = 0; i < 16; ++i)
		sprintf((char *)(HEXHRESP + (i * 2)), "%02x", HRESP[i]);

	sprintf(buf, "rspauth=%s", HEXHRESP);
	base64_encode(md5sresp, buf);
	strcat(md5sresp, "\r\n");

	dbg_login("sresp: %s", buf);
	dbg_login("sresp base64: %s", md5sresp);

	/*
	 * Assign IPv6 address
	 */
	id = mysql_get_userid(md5r.username);
	if (id == -1)
		return -1;

	memcpy(&v6addr, &server.v6prefix, sizeof(v6addr));
	v6addr.s6_addr32[3] = htonl(id);
	session_set_v6addr(session, &v6addr);

	return 0;
}

int login_plain(struct client_session *session, const char *user, const char *pass)
{
	struct in6_addr v6addr;
	char passhash[65], buf[BUFLEN];
	unsigned char HA1[16], HEXHA1[33];
	int i, id;

	dbg_login("Plain-login: %s %s", user, pass);
	if (server.dbhost) {
		if (mysql_get_passhash(user, passhash))
			return -1;
	
		dbg_login("Plain-login: Stored hash %s", passhash);
		if (strlen(passhash) != 32)
			return -1;
	
		sprintf(buf, "%s:" REALM ":%s", user, pass);
		MD5((unsigned char *)buf, strlen(buf), HA1);
		for (i = 0; i < 16; ++i)
			sprintf((char *)(HEXHA1 + (i * 2)), "%02x", HA1[i]);
	
		dbg_login("Plain-login: Gened hash %s", (char *)HEXHA1);
		if (strcmp(passhash, (char *)HEXHA1))
			return -1;
	
		id = mysql_get_userid(user);
	} else /* if (server.ldap_uri) */ {
		if (tsps_ldap_login(user, pass))
			return -1;
		id = tsps_ldap_get_userid(user);
	}

	if (id == -1)
		return -1;

	dbg_login("Plain-login: %s id is %d", user, id);
	memcpy(&v6addr, &server.v6prefix, sizeof(v6addr));
	v6addr.s6_addr32[3] = htonl(id);
	session_set_v6addr(session, &v6addr);
	return 0;
}

void login_anonymous(struct client_session *session)
{
	struct in6_addr v6addr;
	int i;

	memcpy(&v6addr, &server.v6prefix, sizeof(v6addr));
	for (i = 0; i < 3; ++i)
		v6addr.s6_addr32[i] |= server.v6postfixmask.s6_addr32[i];
	v6addr.s6_addr16[5] = (session->v4addr.s_addr) & 0xFFFFu;
	v6addr.s6_addr16[6] = (session->v4addr.s_addr >> 16) & 0xFFFFu;
	v6addr.s6_addr16[7] = htons(session->v4port);
	session_set_v6addr(session, &v6addr);
}

