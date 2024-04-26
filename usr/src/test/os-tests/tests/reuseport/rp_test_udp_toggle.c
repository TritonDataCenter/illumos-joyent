/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/* Copyright 2020 Araragi Hokuto */

/* rp_test_udp_toggle.c -- test SO_REUSEPORT toggle behaviour on UDP */

/*
 * This test create and bind a UDP socket, with
 * SO_REUSEPORT enabled; then it disables the option,
 * and try to bind another socket. Both bind() call
 * should success.
 */

#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#define	DONTCARE(x)	((void)(x))

int
bind_socket(const struct sockaddr_in *addr)
{
	int fd;
	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
		perror("socket");
		return (-1);
	}

	int optval = 1;
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT,
	    &optval, sizeof (optval)) < 0) {
		perror("setsockopt");
		DONTCARE(close(fd));
		return (-1);
	}

	if (bind(fd, (const void *)addr, sizeof (struct sockaddr_in)) < 0) {
		perror("bind");
		DONTCARE(close(fd));
		return (-1);
	}

	return (fd);
}

int fda = 0,
    fdb = 0;

/* close fds before exiting test */
void
close_fds(void)
{
	DONTCARE(close(fda));
	DONTCARE(close(fdb));
}

int
main(void)
{
	struct sockaddr_in addr;
	memset(&addr, 0, sizeof (addr));

	addr.sin_family	= AF_INET;
	addr.sin_port	= htons(22331);

	if (inet_pton(AF_INET, "127.0.0.1", &addr) < 0) {
		/* inet_pton failure is an exception */
		perror("inet_pton");
		return (-1);
	}

	fda = bind_socket(&addr);

	int optval = 0;
	if (setsockopt(fda, SOL_SOCKET, SO_REUSEPORT,
	    &optval, sizeof (optval)) < 0) {
		perror("setsockopt");
		return (-1);
	}

	fdb = bind_socket(&addr);

	int pass;
	pass = fda > 0;
	pass = pass && (fdb > 0);

	close_fds();
	return (pass ? 0 : 1);
}
