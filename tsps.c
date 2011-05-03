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
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

struct tspserver server;

static int parse_args(int argc, char *argv[])
{
	int opt;
	uint16_t port;
	int len;
	char *prelen, *eptr;
	char v6addr[64];

	server.mode = UNDEFINED_MODE;
	server.v4sockaddr.sin_port = htons(3653);

	while ((opt = getopt(argc, argv, "t:b:p:n:NAHh:u:P:d:D")) != -1) {
		switch (opt) {
		case 't':
			strncpy(server.tundev, optarg, 31);
			server.tundev[31] = '\0';
			break;
		case 'b':
			if (inet_pton(AF_INET, optarg, &server.v4sockaddr.sin_addr) <= 0) {
				fprintf(stderr, "Address error: %s\n", optarg);
				return -1;
			}
			break;
		case 'p':
			port = strtol(optarg, &eptr, 10);
			if (*eptr != '\0' || eptr == optarg) {
				fprintf(stderr, "Port number error: %s\n", optarg);
				return -1;
			}
			if (port <= 0 || port > 65535) {
				fprintf(stderr, "Port error: %d(%s)\n", port, optarg);
				return -1;
			}
			server.v4sockaddr.sin_port = htons(port);
			break;
		case 'n':
			prelen = strchr(optarg, '/');
			if (!prelen || prelen != strrchr(optarg, '/')) {
				fprintf(stderr, "Address prefix error: %s\n", optarg);
				return -1;
			}
			server.v6prefixlen = strtol(prelen + 1, &eptr, 10);
			if (*eptr != '\0' || eptr == (prelen + 1)) {
				fprintf(stderr, "Address prefix error: %s\n", prelen + 1);
				return -1;
			}
			if (server.v6prefixlen > 80 || server.v6prefixlen < 32) {
				fprintf(stderr, "Prefix length must between 32 and 80\n");
				return -1;
			}
			strncpy(v6addr, optarg, 64);
			v6addr[63] = '\0';
			prelen = strchr(v6addr, '/');
			if (prelen)
				*prelen = '\0';
			if (inet_pton(AF_INET6, v6addr, &server.v6sockaddr.sin6_addr) <= 0) {
				fprintf(stderr, "Address error: %s\n", v6addr);
				return -1;
			}
			break;
		case 'N':
			if (server.mode != UNDEFINED_MODE) {
				fprintf(stderr, "Can not set mode twice.\n");
				return -1;
			}
			server.mode = ANONYMOUS_MODE;
			break;
		case 'A':
			if (server.mode != UNDEFINED_MODE) {
				fprintf(stderr, "Can not set mode twice.\n");
				return -1; 
			}
			server.mode = AUTHENTICATED_MODE;
			break;
		case 'H':
			if (server.mode != UNDEFINED_MODE) {
				fprintf(stderr, "Can not set mode twice.\n");
				return -1; 
			}
			server.mode = HYBRID_MODE;
			break;
		case 'h':
			len = strlen(optarg);
			server.dbhost = malloc(len + 1);
			strcpy(server.dbhost, optarg);
			break;
		case 'u':
			len = strlen(optarg);
			server.dbuser = malloc(len + 1);
			strcpy(server.dbuser, optarg);
			break;
		case 'P':
			len = strlen(optarg);
			server.dbpass = malloc(len + 1);
			strcpy(server.dbpass, optarg);
			memset(optarg, '*', len);
			break;
		case 'd':
			len = strlen(optarg);
			server.dbname = malloc(len + 1);
			strcpy(server.dbname, optarg);
			break;
		case 'D':
			server.debug = 1;
			break;
		default:

			return -1;
		}
	}

	if (server.mode == UNDEFINED_MODE)
		server.mode = ANONYMOUS_MODE;

	return 0;
}

static void usage(const char *progname)
{
	fprintf(stderr, "\n"
		"Usage: %s %s -b IPv4_bind_address [-p IPv4_bind_port] -n IPv6_prefix [-A|-N|-H]\n"
		"          -h MySQL_Host -u MySQL_User -P MySQL_Pass -d MySQL_DBName -D\n"
		"       IPv4_bind_address: Used for client to connect\n"
		"                          ex: 123.123.123.123\n"
		"       IPv4_bind_port:    Used for client to connect\n"
		"                          default: 3653\n"
		"       IPv6_prefix:       The IPv6 prefix that is allowed for client address\n"
		"                          The value of the prefix length must between 32 and 80\n"
		"                          ex: 2001:DB8:ABC:DEF:123::/80\n"
		"       -N:                Anonymous mode only(Default)\n"
		"       -A:                Authenticated mode only\n"
		"       -H:                Hybrid(Anonymous/Authenticated) mode\n"
		"       -D:                Debug mode: Keep standard I/O, don't fork\n",
		progname,
#ifdef linux
		"[-t tunX]"
#else
		"-t /dev/tunX"
#endif
		);
}

static int check_server_configure(void)
{
	static char zeros[32];
	int i, rplen = 128 - server.v6prefixlen;
	uint8_t m, *mask6;

	if (!memcmp(&server.v4sockaddr.sin_addr, zeros, sizeof(struct in_addr))) {
		fprintf(stderr, "Must specify IPv4_bind_address\n");
		return -1; 
	}

	if (!memcmp(&server.v6sockaddr.sin6_addr, zeros, sizeof(struct in6_addr))) {
		fprintf(stderr, "Must specify IPv6_prefix\n");
		return -1; 
	}

	if (server.mode != ANONYMOUS_MODE &&
	    (!server.dbhost || !server.dbuser || !server.dbpass || !server.dbname)) {
		fprintf(stderr, "Must specify MySQL parameters in authenticated mode\n");
		return -1;
	}

	bzero(&server.v6postfixmask, sizeof(struct in6_addr));
	mask6 = server.v6postfixmask.s6_addr;
	for (i = 0; (i * 8) <= (rplen - 8); ++i)
		mask6[15 - i] = 0xFFu;
	if ((i * 8) < rplen) {
		rplen -= i * 8;
		m = (1 << rplen);
		m -= 1;
		mask6[15 -i] = m;
	}

	for (i = 0; i < 4; ++i) {
		server.v6prefix.s6_addr32[i] =
			server.v6sockaddr.sin6_addr.s6_addr32[i] &
				~(server.v6postfixmask.s6_addr32[i]);
	}

	return 0;
}

int main(int argc, char *argv[], char *envv[])
{
	openlog("tsps", LOG_CONS | LOG_PID, LOG_USER);

	if (parse_args(argc, argv)) {
		usage(argv[0]);
		return EXIT_FAILURE;
	}

	if (check_server_configure()) {
		usage(argv[0]);
		return EXIT_FAILURE;
	}

	if (bind_tunif()) {
		fprintf(stderr, "Binding TUN device error\n");
		return EXIT_FAILURE;
	}

	if (tun_setaddr()) {
		fprintf(stderr, "Setting address for TUN device error\n");
		return EXIT_FAILURE;
	}

	if (bind_socket()) {
		fprintf(stderr, "Binding socket error\n");
		return EXIT_FAILURE;
	}

	if (server.mode != ANONYMOUS_MODE && mysql_initialize()) {
		fprintf(stderr, "Initialize MySQL error\n");
		return EXIT_FAILURE;
	}

	if (!server.debug) {
		close(0);
		close(1);
		close(2);
		if (fork())
			return 0;
	}

	if (create_threads()) {
		tspslog(LOG_ERR, "Failed to create threads\n");
		return EXIT_FAILURE;
	}

	main_loop();

	return 0;
}

