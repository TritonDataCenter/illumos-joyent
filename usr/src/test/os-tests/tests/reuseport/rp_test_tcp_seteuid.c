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

/*
 * rp_test_tcp_noopt.c -- test SO_REUSEPORT behaviour
 * between different effective UID on TCP
 */

/*
 * This test spawn a subprocess, and let it bind a TCP socket;
 * then it switch to euid 101 and try to bind to the same address.
 * The second bind should fail.
 */
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <sys/eventfd.h>

#include <assert.h>
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
		/* socket() fail is an exception. Return 1 to indicate this. */
		perror("socket");
		return (1);
	}

	int optval = 1;
	if (setsockopt(*fd, SOL_SOCKET, SO_REUSEPORT,
	    &optval, sizeof (optval))) {
		/* setsockopt() fail is an exception */
		perror("setsockopt");
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

	int fd;
	int bind_ret;

	int signal_evfd = eventfd(0, 0);
	if (signal_evfd < 0) {
		perror("eventfd");
		return (-1);
	}

	int exit_evfd = eventfd(0, 0);
	if (exit_evfd < 0) {
		perror("eventfd");
		return (-1);
	}

	pid_t pid = fork();

	if (pid < 0) {
		/* fork() fail is an exception */
		perror("fork");
		return (-1);
	}


	if (pid == 0) {
		bind_ret = bind_socket(&fd, &addr);
		if (bind_ret < 0) {
			/* bind fail in child process is an exception */
			perror("bind");

			/* write 2 to evfd to indicate exception */
			uint64_t buf = 2;
			DONTCARE(write(signal_evfd, &buf, sizeof (buf)));

			DONTCARE(close(fd));
			return (-1);
		}

		/* signal parent that we've bound the socket */
		uint64_t buf = 1;
		DONTCARE(write(signal_evfd, &buf, sizeof (buf)));

		/* wait for parent signal */
		buf = 0;
		DONTCARE(read(exit_evfd, &buf, sizeof (buf)));
		assert(buf == 1);

		DONTCARE(close(fd));
		return (-1);
	}

	/* parent process */

	/* wait for child process to signal  */
	uint64_t buf = 0;
	DONTCARE(read(signal_evfd, &buf, sizeof (buf)));

	if (buf == 2) {
		/* exception in child process */
		return (-1);
	}
	assert(buf == 1);

	if (seteuid(101) < 0) {
		perror("seteuid");
		/* signal child to exit */
		buf = 1;
		DONTCARE(write(exit_evfd, &buf, sizeof (buf)));
		return (-1);
	}

	bind_ret = bind_socket(&fd, &addr);

	int pass;
	pass = (bind_ret < 0) && (errno == EADDRNOTAVAIL);

	/* signal child to exit */
	buf = 1;
	DONTCARE(write(exit_evfd, &buf, sizeof (buf)));

	DONTCARE(close(fd));

	return (pass ? 0 : 1);
}
