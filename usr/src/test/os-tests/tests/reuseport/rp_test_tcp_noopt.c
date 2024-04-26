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

/* rp_test_tcp_noopt.c -- test bind(3SOCKET) without SO_REUSEPORT on TCP */

/*
 * This test creates two AF_INET socket, and try binding them
 * to the exact same address, without SO_REUSEPORT set on either
 * one. The second bind() is expected to fail in this case.
 */
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#define	DONTCARE(x)	((void)(x))

/* create and bind a socket to the given address */
int
bind_socket(int *fd, const struct sockaddr_in *addr)
{
	*fd = socket(AF_INET, SOCK_STREAM, 0);
	if (*fd < 0) {
		/*
		 * Failed to create socket.
		 * This is neither PASS or FAIL -- It's an exception.
		 * return 1 to indicate this scene.
		 */
		perror("socket");
		return (1);
	}

	return (bind(*fd, (const void *)addr, sizeof (struct sockaddr_in)));
}

int
main(void)
{
	struct sockaddr_in addr;
	memset(&addr, 0, sizeof (addr));

	addr.sin_family = AF_INET;
	addr.sin_port = htons(22334);
	if (inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr) != 1) {
		/* inet_pton failure is an exception */
		perror("inet_pton");
		return (-1);
	}

	int fda, fdb;
	int bind_ret;

	bind_ret = bind_socket(&fda, &addr);
	if (bind_ret == 1) {
		/* socket(3SOCKET) failure is an exception */
		return (-1);
	}

	if (bind_ret) {
		/* failed to bind first socket is an exception */
		perror("bind");
		return (-1);
	}

	bind_ret = bind_socket(&fdb, &addr);
	if (bind_ret == 1) {
		DONTCARE(close(fda));
		return (-1);
	}

	int pass;
	pass = (bind_ret < 0) && (errno == EADDRINUSE);

	DONTCARE(close(fda));
	DONTCARE(close(fdb));

	return (pass ? 0 : 1);
}
