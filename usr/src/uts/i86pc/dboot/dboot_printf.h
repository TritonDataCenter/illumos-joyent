/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */

/*
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright 2020 Joyent, Inc.
 */

#ifndef	_DBOOT_PRINTF_H
#define	_DBOOT_PRINTF_H

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Very primitive printf. This only understands the following simple formats:
 *        %%, %b, %c, %d, %o, %p, %s, %x and size specifiers l, ll, j, z
 */
extern void dboot_printf(char *fmt, ...)
    __KPRINTFLIKE(1);

/*
 * Primitive version of panic, prints a message, waits for a keystroke,
 * then resets the system
 */
extern void dboot_panic(char *fmt, ...)
    __KPRINTFLIKE(1) __NORETURN;


#ifdef	__cplusplus
}
#endif

#endif	/* _DBOOT_PRINTF_H */
