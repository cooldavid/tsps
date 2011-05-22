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
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>

static int tun_open(void)
{
	if (!*server.tundev)
		return -1;

	if ((server.tunfd = open(server.tundev, O_RDWR)) < 0)
		return -1;

	return 0;
}

#ifdef linux
#include <linux/if_tun.h>
/*
 * struct in6_ifreq defined in <linux/ipv6.h>
 * Putted it here because the redefinition conflict.
 */
struct in6_ifreq {
	struct in6_addr	ifr6_addr;
	__u32		ifr6_prefixlen;
	int		ifr6_ifindex; 
};

static int tun_alloc(void)
{
	struct ifreq ifr;
	int fd, err;

	if ((fd = open("/dev/net/tun", O_RDWR)) < 0)
		return tun_open();

	memset(&ifr, 0, sizeof(ifr));
	/* Flags: IFF_TUN   - TUN device (no Ethernet headers) 
	 *        IFF_TAP   - TAP device  
	 *
	 *        IFF_NO_PI - Do not provide packet information  
	 */ 
	ifr.ifr_flags = IFF_TUN;
	if (*server.tundev)
		strncpy(ifr.ifr_name, server.tundev, IFNAMSIZ);

	if ((err = ioctl(fd, TUNSETIFF, (void *) &ifr)) < 0) {
		perror("Allocate tundev");
		close(fd);
		return err;
	}
	strcpy(server.tundev, ifr.ifr_name);
	server.tunfd = fd;
	return 0;
}

static int tun_linux_setaddr(void)
{
	char errbuf[64];
	struct in6_ifreq ifr6;
	struct ifreq ifr;
	int fd;

	memcpy((char *) &ifr6.ifr6_addr, (char *) &server.v6sockaddr.sin6_addr,
			sizeof(struct in6_addr));

	/*
	 * Setup interface address
	 */
	fd = socket(AF_INET6, SOCK_DGRAM, 0);
	if (fd < 0) {
		tspslog(LOG_ERR, "No support for INET6 on this system");
		return -1;
	}
	strcpy(ifr.ifr_name, server.tundev);
	if (ioctl(fd, SIOGIFINDEX, &ifr) < 0) {
		strerror_r(errno, errbuf, sizeof(errbuf));
		tspslog(LOG_ERR, "Getting interface index error: %s", errbuf);
		return -1;
	}
	ifr6.ifr6_ifindex = ifr.ifr_ifindex;
	ifr6.ifr6_prefixlen = server.v6prefixlen;
	if (ioctl(fd, SIOCSIFADDR, &ifr6) < 0) {
		strerror_r(errno, errbuf, sizeof(errbuf));
		tspslog(LOG_ERR, "Setting interface address error: %s", errbuf);
		return -1;
	}

	/*
	 * Bring up interface
	 */
	strcpy(ifr.ifr_name, server.tundev);
	if (ioctl(fd, SIOCGIFFLAGS, &ifr) < 0) {
		strerror_r(errno, errbuf, sizeof(errbuf));
		tspslog(LOG_ERR, "Getting interface flags error: %s", errbuf);
		return -1;
	}
	strcpy(ifr.ifr_name, server.tundev);
	ifr.ifr_flags |= (IFF_UP | IFF_RUNNING);
	if (ioctl(fd, SIOCSIFFLAGS, &ifr) < 0) {
		strerror_r(errno, errbuf, sizeof(errbuf));
		tspslog(LOG_ERR, "Setting interface flags error: %s", errbuf);
		return -1;
	}
	return 0;
}
#endif

int tun_setaddr(void)
{
#ifdef linux
	return tun_linux_setaddr();
#else
	tspslog(LOG_ERR, "Address setting not implement");
	return -1;
#endif
}

int bind_tunif(void)
{
#ifdef linux
	return tun_alloc();
#else
	return tun_open();
#endif
}

static pthread_mutex_t tun_lock = PTHREAD_MUTEX_INITIALIZER;

void tun_read(void *data, ssize_t *len)
{
	struct tun_pi *pi = (struct tun_pi *)data;
	struct ip6_hdr *ip6 = (struct ip6_hdr *)(pi + 1);
	static const int hdrlen = sizeof(struct tun_pi) + sizeof(struct ip6_hdr);
	int offset = 0, datalen = 0;

	pthread_mutex_lock(&tun_lock);
	memset(data, 0xFF, PHDRSZ + MTU);
	do {
		*len = read(server.tunfd, data + offset, PHDRSZ + MTU - offset);
		if (*len == -1 &&
		    errno != EAGAIN && errno != EINTR) {
			tspslog(LOG_ERR, "Fail to read from server tun interface");
			exit(EXIT_FAILURE);
		}
		if (*len > 0)
			offset += *len;
		if (datalen == 0 && offset >= hdrlen) {
			if (ntohs(pi->proto) != ETH_P_IPV6)
				break;
			datalen = ntohs(ip6->ip6_plen) + hdrlen;
		}
	} while (*len <= 0 || datalen == 0 || offset < datalen);
	pthread_mutex_unlock(&tun_lock);
}

void tun_write(void *data, size_t len)
{
	struct tun_pi *pi;
	int rc, offset = 0;

	if (sizeof(struct tun_pi) > PHDRSZ) {
		tspslog(LOG_ERR, "Preserved header space not enough");
		exit(EXIT_FAILURE);
	}

	pi = (struct tun_pi *)((uint8_t *)data - sizeof(struct tun_pi));
	len += sizeof(struct tun_pi);
	pi->flags = 0;
	pi->proto = htons(ETH_P_IPV6);
	pthread_mutex_lock(&tun_lock);
	do {
		rc = write(server.tunfd, ((void *)pi) + offset, len - offset);
		if (rc == -1 &&
		    errno != EAGAIN && errno != EINTR) {
			tspslog(LOG_ERR, "Fail to write to server tun interface");
			break;
		}
		if (rc > 0)
			offset += rc;
	} while (rc <= 0 || offset < len);
	pthread_mutex_unlock(&tun_lock);
}

