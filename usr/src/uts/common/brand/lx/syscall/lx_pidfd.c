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
 * Copyright 2026 Edgecast Cloud LLC.
 */

/*
 * Linux process file descriptors (pidfds).
 *
 * A pidfd refers to a specific process, identified by its pid and its start
 * time, so that it keeps referring to the same process even if the pid is
 * reused. A pidfd is created by pidfd_open(2), or by clone(2)/clone3(2) with
 * CLONE_PIDFD (via the B_PIDFD_OPEN brand call from the user-level clone
 * emulation). It supports:
 *
 *  - poll/epoll: POLLIN once the process has exited.
 *  - waitid(P_PIDFD): waits for the process, which must be a child. With a
 *    non-blocking pidfd this fails with EAGAIN if the child has not exited.
 *  - pidfd_send_signal(2).
 *  - The "Pid:" line in /proc/<pid>/fdinfo/<fd> (see lx_pidfd_getpid()),
 *    which shows -1 once the process has been reaped.
 *
 * The pidfd is an anonymous vnode, like an event port. All open pidfds are
 * on lx_pidfd_list. lx_pidfd_proc_exit() is called from lx_proc_exit() when a
 * process exits; it marks the process as exited (LX_PROC_EXITED) and wakes up
 * any pollers of its pidfds. Both run with lx_pidfd_lock held, so that a
 * pidfd created concurrently with the exit can't miss the exit. Lock order:
 * lx_pidfd_lock, pidlock, p_lock, lpf_lock.
 *
 * Only 64-bit processes have the pidfd system calls.
 */

#include <sys/types.h>
#include <sys/systm.h>
#include <sys/errno.h>
#include <sys/file.h>
#include <sys/fcntl.h>
#include <sys/vnode.h>
#include <sys/vfs.h>
#include <sys/vfs_opreg.h>
#include <sys/poll.h>
#include <sys/proc.h>
#include <sys/list.h>
#include <sys/kmem.h>
#include <sys/cmn_err.h>
#include <sys/zone.h>
#include <sys/mkdev.h>
#include <sys/sysmacros.h>
#include <sys/brand.h>
#include <sys/lx_brand.h>
#include <sys/lx_misc.h>
#include <sys/lx_fcntl.h>
#include <sys/lx_syscalls.h>

typedef struct lx_pidfd {
	list_node_t	lpf_link;	/* on lx_pidfd_list */
	vnode_t		*lpf_vnode;
	zoneid_t	lpf_zoneid;
	pid_t		lpf_pid;	/* native pid */
	pid_t		lpf_lxpid;	/* Linux pid */
	hrtime_t	lpf_start;	/* p_mstart; 0 if unknown */
	kmutex_t	lpf_lock;	/* protects lpf_exited */
	boolean_t	lpf_exited;	/* process has exited */
	pollhead_t	lpf_pollhead;
} lx_pidfd_t;

#define	VTOPIDFD(vp)	((lx_pidfd_t *)(vp)->v_data)

#define	LX_PIDFD_NONBLOCK	LX_O_NONBLOCK

static kmutex_t lx_pidfd_lock;
static list_t lx_pidfd_list;
static vnodeops_t *lx_pidfd_vnodeops;
static vfsops_t *lx_pidfd_vfsops;
static vfs_t lx_pidfd_vfs;

/*
 * Find the process a pidfd refers to. Returns NULL if it has been reaped (or
 * the pid reused). The caller holds pidlock.
 */
static proc_t *
lx_pidfd_proc(lx_pidfd_t *lpf)
{
	proc_t *p;

	ASSERT(MUTEX_HELD(&pidlock));

	if (lpf->lpf_start == 0)
		return (NULL);
	if ((p = prfind_zone(lpf->lpf_pid, lpf->lpf_zoneid)) == NULL ||
	    p->p_mstart != lpf->lpf_start || p->p_stat == SIDL)
		return (NULL);
	return (p);
}

/* ARGSUSED */
static int
lx_pidfd_open_op(vnode_t **vpp, int flag, cred_t *cr, caller_context_t *ct)
{
	return (0);
}

/* ARGSUSED */
static int
lx_pidfd_close(vnode_t *vp, int flag, int count, offset_t offset,
    cred_t *cr, caller_context_t *ct)
{
	return (0);
}

/* ARGSUSED */
static int
lx_pidfd_rdwr(vnode_t *vp, uio_t *uiop, int ioflag, cred_t *cr,
    caller_context_t *ct)
{
	return (EINVAL);
}

/* ARGSUSED */
static int
lx_pidfd_getattr(vnode_t *vp, vattr_t *vap, int flags, cred_t *cr,
    caller_context_t *ct)
{
	/* Like a Linux anonymous inode */
	bzero(vap, sizeof (*vap));
	vap->va_mask = AT_ALL;
	vap->va_type = VNON;
	vap->va_mode = 0600;
	vap->va_uid = crgetuid(cr);
	vap->va_gid = crgetgid(cr);
	vap->va_fsid = lx_pidfd_vfs.vfs_dev;
	vap->va_nodeid = (ino64_t)(uintptr_t)VTOPIDFD(vp) >> 4;
	vap->va_nlink = 1;
	vap->va_blksize = PAGESIZE;
	return (0);
}

/* ARGSUSED */
static int
lx_pidfd_access(vnode_t *vp, int mode, int flags, cred_t *cr,
    caller_context_t *ct)
{
	return (0);
}

/* ARGSUSED */
static int
lx_pidfd_seek(vnode_t *vp, offset_t ooff, offset_t *noffp,
    caller_context_t *ct)
{
	return (ESPIPE);
}

/* ARGSUSED */
static int
lx_pidfd_poll(vnode_t *vp, short events, int anyyet, short *reventsp,
    pollhead_t **phpp, caller_context_t *ct)
{
	lx_pidfd_t *lpf = VTOPIDFD(vp);
	short revents = 0;

	mutex_enter(&lpf->lpf_lock);
	if (lpf->lpf_exited)
		revents = (POLLIN | POLLRDNORM) & events;
	*reventsp = revents;
	if ((revents == 0 && !anyyet) || (events & POLLET))
		*phpp = &lpf->lpf_pollhead;
	mutex_exit(&lpf->lpf_lock);

	return (0);
}

/* ARGSUSED */
static void
lx_pidfd_inactive(vnode_t *vp, cred_t *cr, caller_context_t *ct)
{
	lx_pidfd_t *lpf = VTOPIDFD(vp);

	mutex_enter(&lx_pidfd_lock);
	list_remove(&lx_pidfd_list, lpf);
	mutex_exit(&lx_pidfd_lock);

	pollhead_clean(&lpf->lpf_pollhead);
	vn_free(vp);
	mutex_destroy(&lpf->lpf_lock);
	kmem_free(lpf, sizeof (*lpf));
}

static const fs_operation_def_t lx_pidfd_vnodeops_template[] = {
	VOPNAME_OPEN,		{ .vop_open = lx_pidfd_open_op },
	VOPNAME_CLOSE,		{ .vop_close = lx_pidfd_close },
	VOPNAME_READ,		{ .vop_read = lx_pidfd_rdwr },
	VOPNAME_WRITE,		{ .vop_write = lx_pidfd_rdwr },
	VOPNAME_GETATTR,	{ .vop_getattr = lx_pidfd_getattr },
	VOPNAME_ACCESS,		{ .vop_access = lx_pidfd_access },
	VOPNAME_SEEK,		{ .vop_seek = lx_pidfd_seek },
	VOPNAME_POLL,		{ .vop_poll = lx_pidfd_poll },
	VOPNAME_INACTIVE,	{ .vop_inactive = lx_pidfd_inactive },
	VOPNAME_FRLOCK,		{ .error = fs_error },
	VOPNAME_PATHCONF,	{ .error = fs_error },
	VOPNAME_DISPOSE,	{ .error = fs_error },
	VOPNAME_GETSECATTR,	{ .error = fs_error },
	VOPNAME_SHRLOCK,	{ .error = fs_error },
	NULL,			NULL
};

/*
 * Return B_TRUE if 'vp' is a pidfd.
 */
boolean_t
lx_pidfd_vnode(vnode_t *vp)
{
	return (vp != NULL && vn_matchops(vp, lx_pidfd_vnodeops));
}

/*
 * For the "Pid:" line in /proc/<pid>/fdinfo/<fd>: return B_TRUE if 'vp' is a
 * pidfd, with the Linux pid of its process, or -1 if it has been reaped. The
 * caller must hold 'vp', and must not hold pidlock or any p_lock.
 */
boolean_t
lx_pidfd_getpid(vnode_t *vp, pid_t *pidp)
{
	lx_pidfd_t *lpf;

	if (!lx_pidfd_vnode(vp))
		return (B_FALSE);

	lpf = VTOPIDFD(vp);
	mutex_enter(&pidlock);
	*pidp = (lx_pidfd_proc(lpf) != NULL) ? lpf->lpf_lxpid : -1;
	mutex_exit(&pidlock);
	return (B_TRUE);
}

/*
 * Create a pidfd for the process with native pid 'spid' in the current zone.
 * If 'reaped_ok' is set, a pidfd is created even if the process no longer
 * exists; this is for CLONE_PIDFD, where the child may have exited and been
 * reaped (e.g. with SIGCHLD ignored) before we get here.
 */
int
lx_pidfd_create(pid_t spid, boolean_t nonblock, boolean_t reaped_ok,
    int *fdp)
{
	zone_t *zone = curproc->p_zone;
	lx_pidfd_t *lpf;
	vnode_t *vp;
	file_t *fp;
	proc_t *p;
	int fd;

	lpf = kmem_zalloc(sizeof (*lpf), KM_SLEEP);
	mutex_init(&lpf->lpf_lock, NULL, MUTEX_DEFAULT, NULL);
	lpf->lpf_zoneid = zone->zone_id;
	lpf->lpf_pid = spid;
	lpf->lpf_lxpid = (spid == zone->zone_proc_initpid) ? 1 : spid;

	vp = vn_alloc(KM_SLEEP);
	vn_setops(vp, lx_pidfd_vnodeops);
	vp->v_type = VNON;
	vp->v_vfsp = &lx_pidfd_vfs;
	vp->v_data = (caddr_t)lpf;
	lpf->lpf_vnode = vp;

	/*
	 * Look up the process and, with lx_pidfd_lock held, check whether it
	 * has already exited; see the comment at the top of this file.
	 */
	mutex_enter(&lx_pidfd_lock);
	mutex_enter(&pidlock);
	p = prfind_zone(spid, zone->zone_id);
	if (p == NULL || p->p_stat == SIDL) {
		mutex_exit(&pidlock);
		if (!reaped_ok) {
			mutex_exit(&lx_pidfd_lock);
			vn_free(vp);
			mutex_destroy(&lpf->lpf_lock);
			kmem_free(lpf, sizeof (*lpf));
			return (ESRCH);
		}
		lpf->lpf_exited = B_TRUE;
	} else {
		lx_proc_data_t *lxpd;

		lpf->lpf_start = p->p_mstart;
		mutex_enter(&p->p_lock);
		lxpd = ptolxproc(p);
		if (p->p_stat == SZOMB || lxpd == NULL ||
		    (lxpd->l_flags & LX_PROC_EXITED) != 0)
			lpf->lpf_exited = B_TRUE;
		mutex_exit(&p->p_lock);
		mutex_exit(&pidlock);
	}
	list_insert_tail(&lx_pidfd_list, lpf);
	mutex_exit(&lx_pidfd_lock);

	/* Like Linux, a pidfd is always close-on-exec. */
	if (falloc(vp, FREAD | FWRITE | (nonblock ? FNONBLOCK : 0), &fp,
	    &fd) != 0) {
		/* lx_pidfd_inactive() frees everything */
		VN_RELE(vp);
		return (EMFILE);
	}
	mutex_exit(&fp->f_tlock);
	setf(fd, fp);
	(void) f_setfd_or(fd, FD_CLOEXEC);

	*fdp = fd;
	return (0);
}

/*
 * Called from lx_proc_exit() when process 'p' exits.
 */
void
lx_pidfd_proc_exit(proc_t *p)
{
	lx_proc_data_t *lxpd;
	lx_pidfd_t *lpf;

	mutex_enter(&lx_pidfd_lock);

	mutex_enter(&p->p_lock);
	if ((lxpd = ptolxproc(p)) != NULL)
		lxpd->l_flags |= LX_PROC_EXITED;
	mutex_exit(&p->p_lock);

	for (lpf = list_head(&lx_pidfd_list); lpf != NULL;
	    lpf = list_next(&lx_pidfd_list, lpf)) {
		if (lpf->lpf_pid != p->p_pid ||
		    lpf->lpf_zoneid != p->p_zone->zone_id ||
		    lpf->lpf_start != p->p_mstart)
			continue;

		mutex_enter(&lpf->lpf_lock);
		lpf->lpf_exited = B_TRUE;
		mutex_exit(&lpf->lpf_lock);
		pollwakeup(&lpf->lpf_pollhead, POLLIN | POLLRDNORM);
	}

	mutex_exit(&lx_pidfd_lock);
}

/*
 * Get the pidfd for 'fd'. Returns with the file held (releasef(fd)).
 */
static int
lx_pidfd_getf(int fd, file_t **fpp, lx_pidfd_t **lpfp)
{
	file_t *fp;

	if ((fp = getf(fd)) == NULL)
		return (EBADF);
	if (!lx_pidfd_vnode(fp->f_vnode)) {
		releasef(fd);
		return (EBADF);
	}
	*fpp = fp;
	*lpfp = VTOPIDFD(fp->f_vnode);
	return (0);
}

/*
 * For waitid(P_PIDFD): translate the pidfd into the native pid to wait for.
 * Sets *nonblockp if the pidfd is non-blocking.
 */
int
lx_pidfd_waitid_pid(int fd, pid_t *pidp, boolean_t *nonblockp)
{
	lx_pidfd_t *lpf;
	file_t *fp;
	int error = 0;

	if ((error = lx_pidfd_getf(fd, &fp, &lpf)) != 0)
		return (error);

	*nonblockp = (fp->f_flag & (FNONBLOCK | FNDELAY)) != 0;

	mutex_enter(&pidlock);
	if (lx_pidfd_proc(lpf) == NULL) {
		/* Already reaped, so not a child of ours (any more) */
		error = ECHILD;
	} else {
		*pidp = lpf->lpf_pid;
	}
	mutex_exit(&pidlock);

	releasef(fd);
	return (error);
}

/*
 * B_PIDFD_OPEN: create a pidfd for the child with native pid 'spid' just
 * created by the user-level clone emulation, for CLONE_PIDFD. Like all brand
 * calls, this returns an errno value.
 */
int
lx_helper_pidfd_open(pid_t spid, int64_t *rval)
{
	int error, fd;

	if (spid <= 0)
		return (EINVAL);
	if ((error = lx_pidfd_create(spid, B_FALSE, B_TRUE, &fd)) != 0)
		return (error);

	*rval = fd;
	return (0);
}

/*
 * pidfd_open(2)
 */
long
lx_pidfd_open(int lx_pid, uint_t flags)
{
	pid_t spid;
	id_t stid;
	int error, fd;

	if ((flags & ~LX_PIDFD_NONBLOCK) != 0 || lx_pid <= 0)
		return (set_errno(EINVAL));

	if (lx_lpid_to_spair(lx_pid, &spid, &stid) != 0)
		return (set_errno(ESRCH));

	/* Only a thread group leader can be referred to by a pidfd. */
	if (stid > 1)
		return (set_errno(EINVAL));

	if ((error = lx_pidfd_create(spid,
	    (flags & LX_PIDFD_NONBLOCK) != 0, B_FALSE, &fd)) != 0)
		return (set_errno(error));

	return (fd);
}

/*
 * pidfd_send_signal(2)
 */
long
lx_pidfd_send_signal(int fd, int sig, siginfo_t *info, uint_t flags)
{
	lx_pidfd_t *lpf;
	file_t *fp;
	pid_t lxpid;
	int error = 0;

	if (flags != 0)
		return (set_errno(EINVAL));

	if ((error = lx_pidfd_getf(fd, &fp, &lpf)) != 0)
		return (set_errno(error));

	mutex_enter(&pidlock);
	if (lx_pidfd_proc(lpf) == NULL)
		error = ESRCH;
	lxpid = lpf->lpf_lxpid;
	mutex_exit(&pidlock);
	releasef(fd);

	if (error != 0)
		return (set_errno(error));

	/*
	 * There is a window in which the process could exit and its pid be
	 * reused before we send the signal; we accept that.
	 */
	if (info != NULL)
		return (lx_helper_rt_sigqueueinfo(lxpid, sig, info));
	return (lx_kill(lxpid, sig));
}

void
lx_pidfd_init(void)
{
	static const fs_operation_def_t lx_pidfd_vfsops_template[] = {
		NULL, NULL
	};
	major_t major;

	mutex_init(&lx_pidfd_lock, NULL, MUTEX_DEFAULT, NULL);
	list_create(&lx_pidfd_list, sizeof (lx_pidfd_t),
	    offsetof(lx_pidfd_t, lpf_link));

	VERIFY0(vfs_makefsops(lx_pidfd_vfsops_template, &lx_pidfd_vfsops));
	VFS_INIT(&lx_pidfd_vfs, lx_pidfd_vfsops, NULL);
	lx_pidfd_vfs.vfs_flag = VFS_RDONLY;
	if ((major = getudev()) == (major_t)-1)
		major = 0;
	lx_pidfd_vfs.vfs_dev = makedevice(major, 0);
	vfs_make_fsid(&lx_pidfd_vfs.vfs_fsid, lx_pidfd_vfs.vfs_dev, 0);

	VERIFY0(vn_make_ops("lx_pidfd", lx_pidfd_vnodeops_template,
	    &lx_pidfd_vnodeops));
}

void
lx_pidfd_fini(void)
{
	VERIFY(list_is_empty(&lx_pidfd_list));
	list_destroy(&lx_pidfd_list);
	mutex_destroy(&lx_pidfd_lock);
	vn_freevnodeops(lx_pidfd_vnodeops);
	vfs_freevfsops(lx_pidfd_vfsops);
}
