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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2018 Joyent, Inc.
 * Copyright 2024 OmniOS Community Edition (OmniOSce) Association.
 * Copyright 2026 Edgecast Cloud LLC.
 */

#include <sys/systm.h>
#include <sys/fcntl.h>
#include <sys/file.h>
#include <sys/filio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/inttypes.h>
#include <sys/mutex.h>
#include <sys/proc.h>
#include <sys/session.h>
#include <sys/sunddi.h>

#include <sys/lx_types.h>
#include <sys/lx_fcntl.h>
#include <sys/lx_misc.h>
#include <sys/brand.h>

extern int openat(int, char *, int, int);
extern int open(char *, int, int);
extern int close(int);
extern int cioctl(file_t *, int, intptr_t, int *);
extern int lookupnameat(char *, enum uio_seg, int, vnode_t **, vnode_t **,
    vnode_t *);


static int
ltos_open_flags(int input)
{
	int flags;

	/*
	 * An O_PATH open on Linux never opens the underlying device, so it can
	 * never acquire a controlling terminal. We emulate O_PATH with a real
	 * (read-only) open, so make sure that it does not either; e.g. systemd
	 * (pid 1) opens the console with O_PATH to chown it.
	 */
	if (input & LX_O_PATH) {
		input &= (LX_O_DIRECTORY | LX_O_NOFOLLOW | LX_O_CLOEXEC);
		input |= LX_O_NOCTTY;
	}

	/*
	 * The illumos O_ACCMODE also includes O_SEARCH|O_EXEC
	 * so this has the effect of stripping those here.
	 */
	flags = (input & LX_O_ACCMODE);

	if (input & LX_O_CREAT)
		flags |= O_CREAT;
	if (input & LX_O_EXCL)
		flags |= O_EXCL;
	if (input & LX_O_NOCTTY)
		flags |= O_NOCTTY;
	if (input & LX_O_TRUNC)
		flags |= O_TRUNC;
	if (input & LX_O_APPEND)
		flags |= O_APPEND;
	if (input & LX_O_NONBLOCK)
		flags |= O_NONBLOCK;
	if (input & LX_O_SYNC)
		flags |= O_SYNC;
	if (input & LX_O_LARGEFILE)
		flags |= O_LARGEFILE;
	if (input & LX_O_NOFOLLOW)
		flags |= O_NOFOLLOW;
	if (input & LX_O_CLOEXEC)
		flags |= O_CLOEXEC;
	if (input & LX_O_DIRECTORY)
		flags |= O_DIRECTORY;

	/*
	 * Linux uses the LX_O_DIRECT flag to do raw, synchronous I/O to the
	 * device backing the fd in question.  illumos has O_DIRECT but
	 * we additionally need O_RSYNC|O_SYNC to simulate the Linux
	 * semantics as far as possible.
	 *
	 * The LX_O_DIRECT flag also requires that the transfer size and
	 * alignment of I/O buffers be a multiple of the logical block size for
	 * the underlying file system, but frankly there isn't an easy way to
	 * support that functionality without doing something like adding an
	 * fcntl(2) flag to denote LX_O_DIRECT mode.
	 *
	 * Since LX_O_DIRECT is merely a performance advisory, we'll just
	 * emulate what we can and trust that the only applications expecting
	 * an error when performing I/O from a misaligned buffer or when
	 * passing a transfer size is not a multiple of the underlying file
	 * system block size will be test suites.
	 */
	if (input & LX_O_DIRECT)
		flags |= (O_RSYNC|O_SYNC|O_DIRECT);

	return (flags);
}

#define	LX_POSTPROCESS_OPTS	(LX_O_ASYNC | LX_O_PATH)

static int
lx_open_postprocess(int fd, int fmode)
{
	file_t *fp;
	int error = 0;

	if ((fmode & LX_POSTPROCESS_OPTS) == 0) {
		/* Skip out early, if possible */
		return (0);
	}

	if ((fp = getf(fd)) == NULL) {
		/*
		 * It is possible that this fd was closed by the time we
		 * arrived here if some one is hammering away with close().
		 */
		return (EIO);
	}

	if (fmode & LX_O_ASYNC && error == 0) {
		if ((error = VOP_SETFL(fp->f_vnode, fp->f_flag, FASYNC,
		    fp->f_cred, NULL)) == 0) {
			mutex_enter(&fp->f_tlock);
			fp->f_flag |= FASYNC;
			mutex_exit(&fp->f_tlock);
		}
	}

	if (fmode & LX_O_PATH && error == 0) {
		/*
		 * While the O_PATH flag has no direct analog in SunOS, it is
		 * emulated by removing both FREAD and FWRITE from f_flag.
		 * This causes read(2) and write(2) result in EBADF and can be
		 * checked for in other syscalls to trigger the correct behavior
		 * there.
		 */
		mutex_enter(&fp->f_tlock);
		fp->f_flag &= ~(FREAD|FWRITE);
		mutex_exit(&fp->f_tlock);
	}

	releasef(fd);
	if (error != 0) {
		(void) closeandsetf(fd, NULL);
	}
	return (error);
}

/*
 * On Linux, opening /dev/console never makes it the controlling terminal
 * (see tty_open()), whereas on illumos a session leader without a controlling
 * terminal acquires any tty it opens without O_NOCTTY. systemd (pid 1) opens
 * /dev/console from time to time; if it became pid 1's controlling terminal,
 * nothing else (e.g. agetty via TIOCSCTTY) could acquire it until reboot.
 *
 * Return B_TRUE if this open would make the zone console our controlling
 * terminal. To keep the common path cheap, only session leaders without a
 * controlling terminal look up the path.
 */
static major_t lx_zcons_major = DDI_MAJOR_T_NONE;

static boolean_t
lx_open_acquires_console(int atfd, char *path)
{
	proc_t *p = curproc;
	sess_t *sp;
	boolean_t can_acquire;
	boolean_t rv = B_FALSE;
	vnode_t *vp;

	mutex_enter(&p->p_splock);
	sp = p->p_sessp;
	can_acquire = (sp->s_sidp == p->p_pidp && sp->s_vp == NULL);
	mutex_exit(&p->p_splock);

	if (!can_acquire)
		return (B_FALSE);

	if (lx_zcons_major == DDI_MAJOR_T_NONE)
		lx_zcons_major = ddi_name_to_major("zcons");
	if (lx_zcons_major == DDI_MAJOR_T_NONE)
		return (B_FALSE);

	if (lx_vp_at(atfd, path, &vp, 0) != 0)
		return (B_FALSE);

	if (vp->v_type == VCHR && getmajor(vp->v_rdev) == lx_zcons_major)
		rv = B_TRUE;

	VN_RELE(vp);
	return (rv);
}

long
lx_openat(int atfd, char *path, int fmode, int cmode)
{
	int flags, fd, error;
	mode_t mode = 0;

	if (atfd == LX_AT_FDCWD)
		atfd = AT_FDCWD;

	flags = ltos_open_flags(fmode);

	if ((fmode & (LX_O_NOCTTY | LX_O_PATH)) == 0 &&
	    lx_open_acquires_console(atfd, path)) {
		flags |= O_NOCTTY;
	}

	if ((fmode & (LX_O_NOFOLLOW|LX_O_PATH|__FLXPATH)) ==
	    (LX_O_NOFOLLOW|LX_O_PATH|__FLXPATH)) {
		flags |= __FLXPATH;
	}

	if (flags & O_CREAT)
		mode = (mode_t)cmode;

	ttolwp(curthread)->lwp_errno = 0;
	fd = openat(atfd, path, flags, mode);
	if (ttolwp(curthread)->lwp_errno != 0) {
		if ((fmode & (LX_O_NOFOLLOW|LX_O_PATH|__FLXPATH)) ==
		    (LX_O_NOFOLLOW|LX_O_PATH) &&
		    ttolwp(curthread)->lwp_errno == ELOOP) {
			/*
			 * On Linux, if O_NOFOLLOW and O_PATH are set together
			 * and the target is a symbolic link, then openat
			 * should return a file descriptor referring to the
			 * symbolic link.
			 *
			 * This file descriptor can be used with fchownat(2),
			 * fstatat(2), linkat(2), and readlinkat(2) alongside
			 * an empty pathname.
			 *
			 * illumos has a private interface flag that causes
			 * openat() to return a file descriptor attached to
			 * the symlink's vnode. This, in conjunction with the
			 * other adjustments made in lx_open_postprocess()
			 * for O_PATH, is enough to satisfy systemd and
			 * other parts of Linux.
			 */
			return (lx_openat(atfd, path, fmode|__FLXPATH, cmode));
		}

		if (ttolwp(curthread)->lwp_errno == EINTR)
			ttolxlwp(curthread)->br_syscall_restart = B_TRUE;

		return (ttolwp(curthread)->lwp_errno);
	}

	if ((error = lx_open_postprocess(fd, fmode)) != 0) {
		return (set_errno(error));
	}
	return (fd);
}

long
lx_open(char *path, int fmode, int cmode)
{
	return (lx_openat(LX_AT_FDCWD, path, fmode, cmode));
}
