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

/*
 * Copyright 2022 Oxide Computer Company
 */

#include <err.h>
#include <string.h>
#include <stdlib.h>

void
test_fail(const char *fmt, ...)
{
	va_list args;
	char *fmt_hdr = NULL;

	va_start(args, fmt);
	(void) asprintf(&fmt_hdr, "TEST FAILED - %s", fmt);
	verrx(EXIT_FAILURE, fmt_hdr, args);
	/* NOTREATCHED */
	va_end(args);
}

void
test_pass(void)
{
	errx(EXIT_SUCCESS, "TEST PASSED");
	/* NOTREATCHED */
}
