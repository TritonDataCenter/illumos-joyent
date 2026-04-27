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
 * Copyright 2026 Oxide Computer Company
 */

/*
 * Test a few aspects of inet6_opt(3C), particularly around error cases.
 */

#include <stdlib.h>
#include <err.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <sys/sysmacros.h>

typedef struct {
	const char *i6a_desc;
	int i6a_ret;
	int i6a_off;
	uint8_t i6a_type;
	socklen_t i6a_len;
	uint_t i6a_align;
} inet6_append_t;

static const inet6_append_t inet6_append_tests[] = {
	{ "no offset, 1-byte align", 6, 0, IP6OPT_JUMBO, 4, 1 },
	{ "no offset, 2-byte align", 6, 0, IP6OPT_JUMBO, 4, 2 },
	{ "no offset, 2-byte align (2)", 8, 0, IP6OPT_JUMBO, 5, 2 },
	{ "no offset, 4-byte align (1)", 8, 0, IP6OPT_JUMBO, 4, 4 },
	{ "no offset, 4-byte align (2)", 8, 0, IP6OPT_JUMBO, 6, 4 },
	{ "no offset, 8-byte align (1)", 16, 0, IP6OPT_JUMBO, 8, 8 },
	{ "no offset, 8-byte align (2)", 24, 0, IP6OPT_JUMBO, 22, 8 },
	{ "offset, 1-byte align (1)", 23, 20, IP6OPT_JUMBO, 1, 1 },
	{ "offset, 2-byte align (1)", 14, 8, IP6OPT_JUMBO, 3, 2 },
	{ "offset, 2-byte align (2)", 14, 8, IP6OPT_JUMBO, 4, 2 },
	{ "offset, 4-byte align (1)", 20, 10, IP6OPT_JUMBO, 7, 4 },
	{ "offset, 4-byte align (2)", 20, 10, IP6OPT_JUMBO, 8, 4 },
	{ "offset, 4-byte align (3)", 24, 10, IP6OPT_JUMBO, 9, 4 },
	{ "invalid align (1)", -1, 0, IP6OPT_JUMBO, 4, 3 },
	{ "invalid align (2)", -1, 0, IP6OPT_JUMBO, 22, 5 },
	{ "invalid align (3)", -1, 0, IP6OPT_JUMBO, 22, 7 },
	{ "invalid align (4)", -1, 0, IP6OPT_JUMBO, 22, 10 },
	{ "align > len (1)", -1, 0, IP6OPT_JUMBO, 2, 4 },
	{ "align > len (2)", -1, 0, IP6OPT_JUMBO, 7, 8 },
	{ "invalid type (1)", -1, 0, IP6OPT_PAD1, 4, 1 },
	{ "invalid type (2)", -1, 0, IP6OPT_PADN, 4, 1 },
	{ "invalid length (1)", -1, 0, IP6OPT_PADN, 256, 1 },
	{ "invalid length (2)", -1, 0, IP6OPT_PADN, 7777, 1 }
};

int
main(void)
{
	uint8_t buf[128];
	int ret = EXIT_SUCCESS;

	/*
	 * First verify several invalid sizes for the buffer allocation. We use
	 * a token buffer for this.
	 */
	const socklen_t inv_lens[] = { 0, 1, 7, 23, 169, UINT32_MAX };
	for (size_t i = 0; i < ARRAY_SIZE(inv_lens); i++) {
		if (inet6_opt_init(buf, inv_lens[i]) != -1) {
			warnx("TEST FAILED: inet6_opt_init passed with invalid "
			    "length 0x%x", inv_lens[i]);
			ret = EXIT_FAILURE;
		} else {
			(void) printf("TEST PASSED: inet6_opt_init rejected "
			    "invalid length 0x%x\n", inv_lens[i]);
		}
	}

	/*
	 * Next, valid and invalid append operations without data.
	 */
	for (size_t i = 0; i < ARRAY_SIZE(inet6_append_tests); i++) {
		const inet6_append_t *t = &inet6_append_tests[i];
		int rval = inet6_opt_append(NULL, 0, t->i6a_off, t->i6a_type,
		    t->i6a_len, t->i6a_align, NULL);
		if (rval != t->i6a_ret) {
			warnx("TEST FAILED: %s: inet6_opt_append returned %d, "
			    "but expected %d\n", t->i6a_desc, rval, t->i6a_ret);
			ret = EXIT_FAILURE;
		} else {
			(void) printf("TEST PASSED: %s: inet6_opt_append "
			    "returned %d\n", t->i6a_desc, t->i6a_ret);
		}
	}

	/*
	 * Now go through and test a few cases that would cause us to exceed the
	 * buffer capacity and make sure that we always catch those.
	 */
	if (inet6_opt_append(buf, sizeof (buf), 120, IP6OPT_NSAP_ADDR, 10, 1,
	    NULL) != -1) {
		warnx("TEST FAILED: didn't fail inet6_opt_append overflow");
		ret = EXIT_FAILURE;
	} else {
		(void) printf("TEST PASSED: caught inet6_opt_append "
		    "overflow\n");
	}

	buf[0] = 2;
	if (inet6_opt_finish(buf, 2, 24) != -1) {
		warnx("TEST FAILED: didn't fail inet6_opt_finish overflow");
		ret = EXIT_FAILURE;
	} else {
		(void) printf("TEST PASSED: caught inet6_opt_finish "
		    "overflow\n");
	}

	if (ret == EXIT_SUCCESS) {
		(void) printf("All tests passed successfully\n");
	}
	return (ret);
}
