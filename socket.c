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
#include <sys/types.h>
#include <arpa/inet.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

int bind_socket(void)
{
	server.sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (server.sockfd == -1) {
		tspslog(LOG_ERR, "Failed to create UDPv4 socket");
		return -1;
	}
	if (bind(server.sockfd,
			(struct sockaddr *)&server.v4sockaddr,
			sizeof(struct sockaddr_in)) != 0) {
		tspslog(LOG_ERR, "Failed to bind to UDPv4 %s:%d: %s",
				inet_ntoa(server.v4sockaddr.sin_addr),
				ntohs(server.v4sockaddr.sin_port),
				strerror(errno));
		return -1;
	}

	return 0;
}

void socket_recvfrom(void *data, ssize_t *len,
			const struct sockaddr_in *addr, socklen_t *scklen)
{
	do {
		*len = recvfrom(server.sockfd, data, MTU, 0,
				(struct sockaddr *)addr, scklen);
		if (*len == -1 &&
		    errno != EAGAIN && errno != EINTR) {
			tspslog(LOG_ERR, "Fail to read from server UDP socket");
			exit(EXIT_FAILURE);
		}
	} while (*len <= 0);
}

void socket_sendto(void *data, size_t len, const struct in_addr *addr, in_port_t port)
{
	struct sockaddr_in saddr;
	socklen_t scklen = sizeof(saddr);
	int rc;

	saddr.sin_family = AF_INET;
	saddr.sin_addr.s_addr = addr->s_addr;
	saddr.sin_port = htons(port);
	do {
		rc = sendto(server.sockfd, data, len, 0, (struct sockaddr *)&saddr, scklen);
		if (rc == -1 &&
		    errno != EAGAIN && errno != EINTR) {
			tspslog(LOG_ERR, "Fail to send to server UDP socket");
			break;
		}
	} while (rc <= 0);
}

static int icmp6_cksum(const struct ip6_hdr *ip6, const struct icmp6_hdr *icp,
        u_int len)
{
        size_t i;
        register const u_int16_t *sp;
        u_int32_t sum;
        union {
                struct {
                        struct in6_addr ph_src;
                        struct in6_addr ph_dst;
                        u_int32_t       ph_len;
                        u_int8_t        ph_zero[3];
                        u_int8_t        ph_nxt;
                } ph;
                u_int16_t pa[20];
        } phu;

        /* pseudo-header */
        memset(&phu, 0, sizeof(phu));
        phu.ph.ph_src = ip6->ip6_src;
        phu.ph.ph_dst = ip6->ip6_dst;
        phu.ph.ph_len = htonl(len);
        phu.ph.ph_nxt = IPPROTO_ICMPV6;

        sum = 0;
        for (i = 0; i < sizeof(phu.pa) / sizeof(phu.pa[0]); i++)
                sum += phu.pa[i];

        sp = (const u_int16_t *)icp;

        for (i = 0; i < (len & ~1); i += 2)
                sum += *sp++;

        if (len & 1)
                sum += htons((*(const u_int8_t *)sp) << 8);

        while (sum > 0xffff)
                sum = (sum & 0xffff) + (sum >> 16);

        return sum;
}

void build_icmp6(uint8_t icmp6buf[IP6LEN], uint16_t *chksum, const struct in6_addr *addr6)
{
	struct ip6_hdr *ip6hdr = (struct ip6_hdr *)icmp6buf;
	struct icmp6_hdr *icmp6hdr = (struct icmp6_hdr *)(ip6hdr + 1);
	uint8_t *icmp6payload = (uint8_t *)(icmp6hdr + 1);
	int i;

	bzero(icmp6buf, IP6LEN);
	ip6hdr->ip6_vfc = 0x60;
	ip6hdr->ip6_plen = htons(ICMP6LEN);
	ip6hdr->ip6_hlim = 0x5u;
	ip6hdr->ip6_nxt = IPPROTO_ICMPV6;
	ip6hdr->ip6_src = server.v6sockaddr.sin6_addr;
	ip6hdr->ip6_dst = *addr6;

	icmp6hdr->icmp6_type = ICMP6_ECHO_REQUEST;
	icmp6hdr->icmp6_id = htons(time(NULL) & 0xFFFF);
	icmp6hdr->icmp6_seq = 0;

	for (i = 0; i < PAYLOADLEN; ++i)
		icmp6payload[i] = 0xCDu;

	*chksum = icmp6_cksum(ip6hdr, icmp6hdr, ICMP6LEN);
}

void socket_ping(const struct in_addr *addr, in_port_t port, uint8_t icmp6buf[IP6LEN], uint16_t chksum)
{
	struct ip6_hdr *ip6hdr = (struct ip6_hdr *)icmp6buf;
	struct icmp6_hdr *icmp6hdr = (struct icmp6_hdr *)(ip6hdr + 1);
	uint16_t seq;
	uint32_t sum;

	seq = ntohs(icmp6hdr->icmp6_seq);
	icmp6hdr->icmp6_seq = htons(++seq);

	sum = chksum + icmp6hdr->icmp6_seq;
        while (sum > 0xffff)
                sum = (sum & 0xffff) + (sum >> 16);
	icmp6hdr->icmp6_cksum = ~(sum) & 0xffff;
	socket_sendto(icmp6buf, IP6LEN, addr, port);
}

void socket_reply_icmp6(const struct in_addr *addr, in_port_t port, void *icmp6buf, ssize_t dlen)
{
	struct ip6_hdr *ip6hdr = (struct ip6_hdr *)icmp6buf;
	struct icmp6_hdr *icmp6hdr = (struct icmp6_hdr *)(ip6hdr + 1);

	ip6hdr->ip6_dst = ip6hdr->ip6_src;
	ip6hdr->ip6_src = server.v6sockaddr.sin6_addr;
	icmp6hdr->icmp6_type = ICMP6_ECHO_REPLY;
	icmp6hdr->icmp6_cksum -= htons((ICMP6_ECHO_REPLY - ICMP6_ECHO_REQUEST) << 8);
	socket_sendto(icmp6buf, dlen, addr, port);
}

