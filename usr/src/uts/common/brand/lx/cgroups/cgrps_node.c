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
 * Copyright 2021 Joyent, Inc.
 * Copyright 2026 Edgecast Cloud LLC.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/sysmacros.h>
#include <sys/systm.h>
#include <sys/time.h>
#include <sys/vfs.h>
#include <sys/vnode.h>
#include <sys/errno.h>
#include <sys/cmn_err.h>
#include <sys/cred.h>
#include <sys/stat.h>
#include <sys/mode.h>
#include <sys/policy.h>
#include <sys/sdt.h>
#include <sys/atomic.h>

#include "cgrps.h"

static int cgrp_dirmakecgnode(cgrp_node_t *, cgrp_mnt_t *, struct vattr *,
	enum de_op, cgrp_node_t **, struct cred *);
static int cgrp_diraddentry(cgrp_node_t *, cgrp_node_t *, char *);

/*
 * cgroup v1 files. Note that the top-level release_agent file is handled
 * separately in cgrp_dirinit() so that N_DIRENTS() remains the number of
 * entries in a non-root cgroup.
 */
static cgrp_subsys_dirent_t cgrp_generic_dir[] = {
	{ CG_PROCS,		"cgroup.procs",		0644,	0 },
	{ CG_NOTIFY,		"notify_on_release",	0644,	0 },
	{ CG_TASKS,		"tasks",		0644,	0 }
};

/*
 * cgroup v2 core interface files. We do not currently emulate any
 * controllers, so only the cgroup.* files exist.
 */
static cgrp_subsys_dirent_t cgrp_unified_dir[] = {
	{ CG_PROCS,		"cgroup.procs",		0644,	0 },
	{ CG_THREADS,		"cgroup.threads",	0644,	0 },
	{ CG_CONTROLLERS,	"cgroup.controllers",	0444,	0 },
	{ CG_SUBTREE_CTL,	"cgroup.subtree_control", 0644,	0 },
	{ CG_EVENTS,		"cgroup.events",	0444,
	    CGSD_NONROOT_ONLY },
	{ CG_TYPE,		"cgroup.type",		0644,
	    CGSD_NONROOT_ONLY },
	{ CG_MAX_DEPTH,		"cgroup.max.depth",	0644,	0 },
	{ CG_MAX_DESC,		"cgroup.max.descendants", 0644,	0 },
	{ CG_STAT,		"cgroup.stat",		0444,	0 }
};

typedef struct cgrp_ssde {
	cgrp_subsys_dirent_t	*cg_ssde_files;
	int			cg_ssde_nfiles;
} cgrp_ssde_t;

#define	CGDIRLISTSZ(l)		(sizeof (l) / sizeof ((l)[0]))

/*
 * Note, these entries must be in the same order as the cgrp_ssid_t entries.
 */
static cgrp_ssde_t cg_ssde_dir[] = {
	/* subsystems start at 1 */
	{NULL, 0},

	/* CG_SSID_GENERIC */
	{cgrp_generic_dir, CGDIRLISTSZ(cgrp_generic_dir)},

	/* CG_SSID_UNIFIED */
	{cgrp_unified_dir, CGDIRLISTSZ(cgrp_unified_dir)},
};


#define	CG_HASH_SIZE	8192		/* must be power of 2 */
#define	CG_MUTEX_SIZE	64

static cgrp_dirent_t	*cg_hashtable[CG_HASH_SIZE];
static kmutex_t		 cg_hashmutex[CG_MUTEX_SIZE];

#define	CG_HASH_INDEX(a)	((a) & (CG_HASH_SIZE-1))
#define	CG_MUTEX_INDEX(a)	((a) & (CG_MUTEX_SIZE-1))

#define	CG_HASH(cp, name, hash)				\
	{							\
		char Xc, *Xcp;					\
		hash = (uint_t)(uintptr_t)(cp) >> 8;		\
		for (Xcp = (name); (Xc = *Xcp) != 0; Xcp++)	\
			hash = (hash << 4) + hash + (uint_t)Xc;	\
	}

#define	MODESHIFT	3

typedef enum cgrp_nodehold {
	NOHOLD,
	HOLD
} cgrp_nodehold_t;

void
cgrp_hash_init(void)
{
	int i;

	for (i = 0; i < CG_MUTEX_SIZE; i++)
		mutex_init(&cg_hashmutex[i], NULL, MUTEX_DEFAULT, NULL);
}

static void
cgrp_hash_in(cgrp_dirent_t *c)
{
	uint_t		hash;
	cgrp_dirent_t	**prevpp;
	kmutex_t	*cg_hmtx;

	CG_HASH(c->cgd_parent, c->cgd_name, hash);
	c->cgd_hash = hash;
	prevpp = &cg_hashtable[CG_HASH_INDEX(hash)];
	cg_hmtx = &cg_hashmutex[CG_MUTEX_INDEX(hash)];
	mutex_enter(cg_hmtx);
	c->cgd_link = *prevpp;
	*prevpp = c;
	mutex_exit(cg_hmtx);
}

static void
cgrp_hash_out(cgrp_dirent_t *c)
{
	uint_t		hash;
	cgrp_dirent_t	**prevpp;
	kmutex_t	*cg_hmtx;

	hash = c->cgd_hash;
	prevpp = &cg_hashtable[CG_HASH_INDEX(hash)];
	cg_hmtx = &cg_hashmutex[CG_MUTEX_INDEX(hash)];
	mutex_enter(cg_hmtx);
	while (*prevpp != c)
		prevpp = &(*prevpp)->cgd_link;
	*prevpp = c->cgd_link;
	mutex_exit(cg_hmtx);
}

static cgrp_dirent_t *
cgrp_hash_lookup(char *name, cgrp_node_t *parent, cgrp_nodehold_t hold,
    cgrp_node_t **found)
{
	cgrp_dirent_t	*l;
	uint_t		hash;
	kmutex_t	*cg_hmtx;
	cgrp_node_t	*cnp;

	CG_HASH(parent, name, hash);
	cg_hmtx = &cg_hashmutex[CG_MUTEX_INDEX(hash)];
	mutex_enter(cg_hmtx);
	l = cg_hashtable[CG_HASH_INDEX(hash)];
	while (l) {
		if ((l->cgd_hash == hash) &&
		    (l->cgd_parent == parent) &&
		    (strcmp(l->cgd_name, name) == 0)) {
			/*
			 * We need to make sure that the cgrp_node that
			 * we put a hold on is the same one that we pass back.
			 * Hence, temporary variable cnp is necessary.
			 */
			cnp = l->cgd_cgrp_node;
			if (hold == HOLD) {
				ASSERT(cnp);
				cgnode_hold(cnp);
			}
			if (found)
				*found = cnp;
			mutex_exit(cg_hmtx);
			return (l);
		} else {
			l = l->cgd_link;
		}
	}
	mutex_exit(cg_hmtx);
	return (NULL);
}

/*
 * The following functions maintain the per-mount cgroup hash table.
 */
static void
cgrp_cg_hash_insert(cgrp_mnt_t *cgm, cgrp_node_t *cn)
{
	uint_t cgid;
	int hsh;

	ASSERT(MUTEX_HELD(&cgm->cg_contents));

	cgid = cn->cgn_id;
	hsh = cgid % CGRP_HASH_SZ;

	cn->cgn_next = cgm->cg_grp_hash[hsh];
	cgm->cg_grp_hash[hsh] = cn;
}

static void
cgrp_cg_hash_remove(cgrp_mnt_t *cgm, cgrp_node_t *cn)
{
	uint_t cgid;
	int hsh;
	cgrp_node_t *np = NULL, *curp, *prevp = NULL;

	ASSERT(MUTEX_HELD(&cgm->cg_contents));

	cgid = cn->cgn_id;
	hsh = cgid % CGRP_HASH_SZ;

	for (curp = cgm->cg_grp_hash[hsh]; curp != NULL;
	    curp = curp->cgn_next) {
		if (curp->cgn_id == cgid) {
			if (prevp == NULL) {
				cgm->cg_grp_hash[hsh] = curp->cgn_next;
			} else {
				prevp->cgn_next = curp->cgn_next;
			}
			np = curp;
			np->cgn_next = NULL;
			break;
		}

		prevp = curp;
	}

	ASSERT(np != NULL);
	ASSERT(np->cgn_task_cnt == 0);
}

/*
 * Return the cgroup that a thread with cgroup ID (br_cgroupid) 'cgid' is in.
 *
 * Unmounting the file system does not reset the cgroup ID of the threads in
 * the zone, so a thread can still have the ID of a cgroup from an earlier
 * mount. Since cgroup IDs are not reused (see cgrp_dirinit()), such an ID is
 * not found in this mount, and such a thread is in the top-level cgroup, like
 * every thread which was running when the file system was mounted.
 */
cgrp_node_t *
cgrp_cg_lwp_lookup(cgrp_mnt_t *cgm, uint_t cgid)
{
	cgrp_node_t *cn;

	ASSERT(MUTEX_HELD(&cgm->cg_contents));

	if ((cn = cgrp_cg_hash_lookup(cgm, cgid)) == NULL)
		cn = cgm->cg_rootnode;
	return (cn);
}

cgrp_node_t *
cgrp_cg_hash_lookup(cgrp_mnt_t *cgm, uint_t cgid)
{
	int hsh = cgid % CGRP_HASH_SZ;
	cgrp_node_t *curp;

	ASSERT(MUTEX_HELD(&cgm->cg_contents));

	for (curp = cgm->cg_grp_hash[hsh]; curp != NULL;
	    curp = curp->cgn_next) {
		if (curp->cgn_id == cgid) {
			return (curp);
		}
	}

	return (NULL);
}

/*
 * Calculate an inode number
 *
 * This takes various bits of info and munges them to give the inode number for
 * a cgrp pseudo file node.
 */
ino_t
cgrp_inode(cgrp_nodetype_t type, unsigned int cgrpid)
{
	/*
	 * cgroup inode format:
	 * 00000000AABBBBBB
	 *
	 * AA		- node type (from subsystem list)
	 * BBBBBB	- id of the cgroup
	 */

	return ((ino_t)(type << 24) | (cgrpid & 0xffffff));
}

/*
 * Return the number of pseudo file entries in a cgroup directory for the
 * given subsystem.
 */
int
cgrp_num_pseudo_ents(cgrp_ssid_t ssid)
{
	cgrp_ssde_t *ssdp = &cg_ssde_dir[ssid];
	int i, n = 0;

	/* Count the entries in a non-root cgroup */
	for (i = 0; i < ssdp->cg_ssde_nfiles; i++) {
		if ((ssdp->cg_ssde_files[i].cgrp_ssd_flags &
		    CGSD_ROOT_ONLY) == 0)
			n++;
	}

	return (n);
}

int
cgrp_taccess(void *vcp, int mode, cred_t *cred)
{
	cgrp_node_t *cn = vcp;
	int shift = 0;
	/*
	 * Check access based on owner, group and public perms in cgrp_node.
	 */
	if (crgetuid(cred) != cn->cgn_uid) {
		shift += MODESHIFT;
		if (groupmember(cn->cgn_gid, cred) == 0)
			shift += MODESHIFT;
	}

	return (secpolicy_vnode_access2(cred, CGNTOV(cn), cn->cgn_uid,
	    cn->cgn_mode << shift, mode));
}

/*
 * Search directory 'parent' for entry 'name'.
 *
 * 0 is returned on success and *foundcp points
 * to the found cgrp_node with its vnode held.
 */
int
cgrp_dirlookup(cgrp_node_t *parent, char *name, cgrp_node_t **foundcp,
    cred_t *cred)
{
	int error;

	ASSERT(MUTEX_HELD(&VTOCGM(parent->cgn_vnode)->cg_contents));
	*foundcp = NULL;
	if (parent->cgn_type != CG_CGROUP_DIR)
		return (ENOTDIR);

	if ((error = cgrp_taccess(parent, VEXEC, cred)))
		return (error);

	if (*name == '\0') {
		cgnode_hold(parent);
		*foundcp = parent;
		return (0);
	}

	/*
	 * Search the directory for the matching name
	 * We need the lock protecting the cgn_dir list
	 * so that it doesn't change out from underneath us.
	 * cgrp_hash_lookup() will pass back the cgrp_node
	 * with a hold on it.
	 */

	if (cgrp_hash_lookup(name, parent, HOLD, foundcp) != NULL) {
		ASSERT(*foundcp);
		return (0);
	}

	return (ENOENT);
}

/*
 * Enter a directory entry for 'name' and 'cp' into directory 'dir'
 *
 * Returns 0 on success.
 */
int
cgrp_direnter(
	cgrp_mnt_t	*cgm,
	cgrp_node_t	*dir,		/* target directory to make entry in */
	char		*name,		/* name of entry */
	enum de_op	op,		/* entry operation */
	cgrp_node_t	*cn,		/* existing cgrp_node, if rename */
	struct vattr	*va,
	cgrp_node_t	**cnp,		/* return cgrp_node, if create/mkdir */
	cred_t		*cred)
{
	cgrp_dirent_t *cdp;
	cgrp_node_t *found = NULL;
	int error = 0;
	char *s;

	ASSERT(MUTEX_HELD(&cgm->cg_contents));
	ASSERT(dir->cgn_type == CG_CGROUP_DIR);

	/*
	 * Don't allow '/' characters in pathname component,
	 */
	for (s = name; *s; s++)
		if (*s == '/')
			return (EACCES);

	if (name[0] == '\0')
		panic("cgrp_direnter: NULL name");

	/*
	 * For rename lock the source entry and check the link count
	 * to see if it has been removed while it was unlocked.
	 * Remember that we can only rename within the same directory.
	 */
	if (op == DE_RENAME) {
		if (cn->cgn_nlink == 0) {
			return (ENOENT);
		}

		if (cn->cgn_nlink == MAXLINK) {
			return (EMLINK);
		}
		cn->cgn_nlink++;
		gethrestime(&cn->cgn_ctime);
	}

	/*
	 * This might be a "dangling detached directory".
	 * it could have been removed, but a reference
	 * to it kept in u_cwd.  don't bother searching
	 * it, and with any luck the user will get tired
	 * of dealing with us and cd to some absolute
	 * pathway.  *sigh*, thus in ufs, too.
	 */
	if (dir->cgn_nlink == 0) {
		error = ENOENT;
		goto out;
	}

	/*
	 * Search for the entry. In all cases it is an error if it exists.
	 */
	cdp = cgrp_hash_lookup(name, dir, HOLD, &found);

	if (cdp) {
		ASSERT(found != NULL);
		error = EEXIST;
		mutex_exit(&cgm->cg_contents);
		cgnode_rele(found);
		mutex_enter(&cgm->cg_contents);
	} else {

		/*
		 * The entry does not exist. Check write permission in
		 * directory to see if entry can be created. DE_CREATE is only
		 * used by cgrp_addnode(), to create the pseudo files of a new
		 * cgroup, which must not fail: the permission to create the
		 * cgroup was checked on its parent, while the new cgroup's own
		 * mode (e.g. 0555, from mkdir -m or the umask) may not allow
		 * writing to it.
		 */
		if (op != DE_CREATE &&
		    (error = cgrp_taccess(dir, VWRITE, cred)) != 0)
			goto out;
		if (op == DE_CREATE || op == DE_MKDIR) {
			/*
			 * Make new cgrp_node and directory entry as required.
			 */
			error = cgrp_dirmakecgnode(dir, cgm, va, op, &cn, cred);
			if (error)
				goto out;

			if (op == DE_MKDIR) {
				/*
				 * inherit notify_on_release value from parent
				 */
				cn->cgn_notify = dir->cgn_notify;
			}
		}

		error = cgrp_diraddentry(dir, cn, name);
		if (error != 0) {
			if (op == DE_CREATE || op == DE_MKDIR) {
				/*
				 * Unmake the inode we just made.
				 */
				if ((cn->cgn_type) == CG_CGROUP_DIR) {
					ASSERT(cdp == NULL);
					/*
					 * cleanup allocs made by cgrp_dirinit
					 */
					cgrp_dirtrunc(cn);
				}
				cn->cgn_nlink = 0;
				gethrestime(&cn->cgn_ctime);
				mutex_exit(&cgm->cg_contents);
				cgnode_rele(cn);
				mutex_enter(&cgm->cg_contents);
				cn = NULL;
			}
		} else if (cnp) {
			*cnp = cn;
		} else if (op == DE_CREATE || op == DE_MKDIR) {
			mutex_exit(&cgm->cg_contents);
			cgnode_rele(cn);
			mutex_enter(&cgm->cg_contents);
		}
	}

out:
	if (error && op == DE_RENAME) {
		/* Undo bumped link count. */
		cn->cgn_nlink--;
		gethrestime(&cn->cgn_ctime);
	}
	return (error);
}

/*
 * Return the name of the pseudo files of type 'type' in this mount.
 */
static char *
cgrp_pseudo_name(cgrp_mnt_t *cgm, cgrp_nodetype_t type)
{
	cgrp_ssde_t *ssdp = &cg_ssde_dir[cgm->cg_ssid];
	int i;

	for (i = 0; i < ssdp->cg_ssde_nfiles; i++) {
		if (ssdp->cg_ssde_files[i].cgrp_ssd_type == type)
			return (ssdp->cg_ssde_files[i].cgrp_ssd_name);
	}
	return (NULL);
}

/*
 * Release the holds on a list of pseudo file nodes returned by
 * cgrp_dirdelete() for the removal of the cgroup dir 'dvp'. Must be called
 * without cg_contents held.
 *
 * For each file which was unlinked, generate a remove event first, so that
 * file event watchers learn that the file is gone. In particular, an inotify
 * watch on the file is removed, reporting IN_DELETE_SELF and IN_IGNORED, and
 * drops its hold on the vnode, which would otherwise keep the file system
 * from being unmounted.
 */
void
cgrp_rele_list(cgrp_node_t *cn, vnode_t *dvp)
{
	while (cn != NULL) {
		cgrp_node_t *next = cn->cgn_rlnext;

		ASSERT(MUTEX_NOT_HELD(&VTOCGM(cn->cgn_vnode)->cg_contents));

		cn->cgn_rlnext = NULL;
		/* An unlinked pseudo file can't be linked again */
		if (cn->cgn_nlink == 0) {
			vnevent_remove(CGNTOV(cn), dvp,
			    cgrp_pseudo_name(VTOCGM(cn->cgn_vnode),
			    cn->cgn_type), NULL);
		}
		cgnode_rele(cn);
		cn = next;
	}
}

/*
 * Delete entry cn of name "nm" from parent dir. This is used to both remove
 * a cgroup directory and to remove the pseudo file nodes within the cgroup
 * directory (by recursively calling itself). It frees the dir entry space
 * and decrements link count on cgrp_node(s).
 *
 * For DR_RMDIR, the pseudo file nodes are held while they are removed, and
 * those holds are passed back through 'rlistp' (linked through cgn_rlnext),
 * even on error. The caller must release them with cgrp_rele_list() once it
 * has dropped cg_contents, since releasing the last hold on a node takes
 * cg_contents in cgrp_inactive(). We don't drop cg_contents here, so that
 * nothing (a new task or sub-cgroup) can enter the cgroup after the caller
 * has checked that it is empty and before it is gone.
 *
 * Return 0 on success.
 */
int
cgrp_dirdelete(cgrp_node_t *dir, cgrp_node_t *cn, char *nm, enum dr_op op,
    cred_t *cred, cgrp_node_t **rlistp)
{
	cgrp_mnt_t *cgm = VTOCGM(cn->cgn_vnode);
	cgrp_dirent_t *cndp;
	int error;
	size_t namelen;
	cgrp_node_t *cnnp;
	timestruc_t now;

	ASSERT(MUTEX_HELD(&cgm->cg_contents));

	if (nm[0] == '\0')
		panic("cgrp_dirdelete: empty name for 0x%p", (void *)cn);

	/*
	 * return error when removing . and ..
	 */
	if (nm[0] == '.') {
		if (nm[1] == '\0')
			return (EINVAL);
		if (nm[1] == '.' && nm[2] == '\0')
			return (EEXIST); /* thus in ufs */
	}

	/*
	 * DR_REMOVE is only used below, to remove the pseudo files of a cgroup
	 * which is being removed. As on Linux, removing a cgroup only requires
	 * write access to its parent, which was checked by the DR_RMDIR call,
	 * and not to the cgroup itself.
	 */
	if (op != DR_REMOVE &&
	    (error = cgrp_taccess(dir, VEXEC|VWRITE, cred)) != 0)
		return (error);

	if (dir->cgn_dir == NULL)
		return (ENOENT);

	if (op == DR_RMDIR) {
		/*
		 * This is the top-level removal of a cgroup dir. Start by
		 * removing the fixed pseudo file entries from the dir. We do
		 * this by recursively calling back into this function with
		 * a different op code. The caller of this function has
		 * already verified that it is safe to remove this directory.
		 */
		cgrp_dirent_t *cdp;

		ASSERT(cn->cgn_type == CG_CGROUP_DIR);
		ASSERT(rlistp != NULL);

		cdp = cn->cgn_dir;
		while (cdp) {
			cgrp_node_t *pseudo_node;
			cgrp_dirent_t *nextp;

			if (strcmp(cdp->cgd_name, ".") == 0 ||
			    strcmp(cdp->cgd_name, "..") == 0) {
				cdp = cdp->cgd_next;
				continue;
			}

			pseudo_node = cdp->cgd_cgrp_node;
			nextp = cdp->cgd_next;

			cgnode_hold(pseudo_node);
			pseudo_node->cgn_rlnext = *rlistp;
			*rlistp = pseudo_node;
			error = cgrp_dirdelete(cn, pseudo_node,
			    cdp->cgd_name, DR_REMOVE, cred, NULL);
			/*
			 * The pseudo file may still be open, but it holds no
			 * reference on this dir, which will be freed once it
			 * is released. Orphan the file so that accesses to it
			 * fail with ENODEV instead of using the freed dir.
			 * Once cgroup.events is gone, stop posting
			 * notifications for it. We only do this once the file
			 * has been unlinked, since if the removal fails the
			 * cgroup stays around and still needs them.
			 */
			if (error != 0)
				return (error);
			pseudo_node->cgn_parent = NULL;
			if (cn->cgn_events == pseudo_node)
				cn->cgn_events = NULL;

			cdp = nextp;
		}

		cgrp_cg_hash_remove(cgm, cn);
	}

	cndp = cgrp_hash_lookup(nm, dir, NOHOLD, &cnnp);
	/* These used to be VERIFY(), but in racy conditions they can fail. */
	if (cndp == NULL) {
		/* Can't find the directory entry at all now! */
		return (ENOENT);
	}
	if (cn != cnnp) {
		/* Returned cnnp isn't our original, so it's also not-there. */
		return (ENOENT);
	}

	cgrp_hash_out(cndp);

	/* Take cndp out of the directory list. */
	ASSERT(cndp->cgd_next != cndp);
	ASSERT(cndp->cgd_prev != cndp);
	if (cndp->cgd_prev) {
		cndp->cgd_prev->cgd_next = cndp->cgd_next;
	}
	if (cndp->cgd_next) {
		cndp->cgd_next->cgd_prev = cndp->cgd_prev;
	}

	/*
	 * If the roving slot pointer happens to match cndp,
	 * point it at the previous dirent.
	 */
	if (dir->cgn_dir->cgd_prev == cndp) {
		dir->cgn_dir->cgd_prev = cndp->cgd_prev;
	}
	ASSERT(cndp->cgd_next != cndp);
	ASSERT(cndp->cgd_prev != cndp);

	/* cndp points to the correct directory entry */
	namelen = strlen(cndp->cgd_name) + 1;

	kmem_free(cndp, sizeof (cgrp_dirent_t) + namelen);
	dir->cgn_size -= (sizeof (cgrp_dirent_t) + namelen);
	dir->cgn_dirents--;

	gethrestime(&now);
	dir->cgn_mtime = now;
	dir->cgn_ctime = now;
	cn->cgn_ctime = now;

	ASSERT(cn->cgn_nlink > 0);
	cn->cgn_nlink--;
	if (op == DR_RMDIR && cn->cgn_type == CG_CGROUP_DIR) {
		cgrp_dirtrunc(cn);
		ASSERT(cn->cgn_nlink == 0);
	}
	return (0);
}

/*
 * Initialize a cgrp_node and add it to file list under mount point.
 */
void
cgrp_node_init(cgrp_mnt_t *cgm, cgrp_node_t *cn, vattr_t *vap, cred_t *cred)
{
	struct vnode *vp;
	timestruc_t now;

	ASSERT(MUTEX_HELD(&cgm->cg_contents));
	ASSERT(vap != NULL);

	cn->cgn_mode = MAKEIMODE(vap->va_type, vap->va_mode);
	cn->cgn_mask = 0;
	cn->cgn_attr.va_type = vap->va_type;
	cn->cgn_nlink = 1;
	cn->cgn_size = 0;

	if (cred == NULL) {
		cn->cgn_uid = vap->va_uid;
		cn->cgn_gid = vap->va_gid;
	} else {
		cn->cgn_uid = crgetuid(cred);
		cn->cgn_gid = crgetgid(cred);
	}

	cn->cgn_fsid = cgm->cg_dev;
	cn->cgn_rdev = vap->va_rdev;
	cn->cgn_blksize = PAGESIZE;
	cn->cgn_nblocks = 0;
	gethrestime(&now);
	cn->cgn_atime = now;
	cn->cgn_mtime = now;
	cn->cgn_ctime = now;
	cn->cgn_seq = 0;
	cn->cgn_dir = NULL;

	cn->cgn_vnode = vn_alloc(KM_SLEEP);
	vp = CGNTOV(cn);
	vn_setops(vp, cgrp_vnodeops);
	vp->v_vfsp = cgm->cg_vfsp;
	vp->v_type = vap->va_type;
	vp->v_rdev = vap->va_rdev;
	vp->v_data = (caddr_t)cn;

	cn->cgn_nodeid = cgm->cg_gen++;

	/*
	 * Add new cgrp_node to end of linked list of cgrp_nodes for this
	 * cgroup fs. Root directory is handled specially in cgrp_mount.
	 */
	if (cgm->cg_rootnode != (cgrp_node_t *)NULL) {
		cn->cgn_forw = NULL;
		cn->cgn_back = cgm->cg_rootnode->cgn_back;
		cn->cgn_back->cgn_forw = cgm->cg_rootnode->cgn_back = cn;
	}
	vn_exists(vp);
}

void
cgrp_addnode(cgrp_mnt_t *cgm, cgrp_node_t *dir, char *name,
    cgrp_nodetype_t type, struct vattr *nattr, cred_t *cr)
{
	cgrp_node_t *ncn;

	ASSERT(MUTEX_HELD(&cgm->cg_contents));

	VERIFY0(cgrp_direnter(cgm, dir, name, DE_CREATE, (cgrp_node_t *)NULL,
	    nattr, &ncn, cr));

	/*
	 * Fix the inode and assign the pseudo file type to be correct.
	 */
	ncn->cgn_nodeid = cgrp_inode(type, dir->cgn_nodeid);
	ncn->cgn_type = type;
	if (type == CG_EVENTS)
		dir->cgn_events = ncn;

	/*
	 * Since we're creating these entries here and not via the
	 * normal VOP_CREATE code path, we need to drop our hold. The node is
	 * linked (cgn_nlink is 1), so releasing the last hold would only have
	 * cgrp_inactive() decrement v_count to 0, not reclaim the node. Do
	 * that directly, rather than through VN_RELE(), which would require
	 * us to drop cg_contents (taken by cgrp_inactive()). That way a mkdir
	 * holds cg_contents throughout, from checking that the name is free
	 * and the cgroup.max.* limits are not exceeded until the new cgroup
	 * is entered into its parent and counted.
	 */
	ASSERT(ncn->cgn_nlink != 0);
	mutex_enter(&CGNTOV(ncn)->v_lock);
	VN_RELE_LOCKED(CGNTOV(ncn));
	mutex_exit(&CGNTOV(ncn)->v_lock);
}

/*
 * cgrp_dirinit is used internally to initialize a directory (dir)
 * with '.' and '..' entries without checking permissions and locking
 * It also creates the entries for the pseudo file nodes that reside in the
 * directory.
 */
void
cgrp_dirinit(cgrp_node_t *parent, cgrp_node_t *dir, cred_t *cr)
{
	cgrp_dirent_t *dot, *dotdot;
	timestruc_t now;
	cgrp_mnt_t *cgm = VTOCGM(dir->cgn_vnode);
	cgrp_ssde_t *ssdp;
	cgrp_subsys_dirent_t *pseudo_files;
	struct vattr nattr;
	int i;

	ASSERT(MUTEX_HELD(&cgm->cg_contents));
	ASSERT(dir->cgn_type == CG_CGROUP_DIR);

	ASSERT(cgm->cg_ssid > 0 && cgm->cg_ssid < CG_SSID_NUM);
	ssdp = &cg_ssde_dir[cgm->cg_ssid];

	/*
	 * If this is the top-level cgroup created by the mount then we need to
	 * count up the number of procs and tasks already running in the zone.
	 */

	/*
	 * Set the cgroup ID for this cgrp_node. The top-level cgroup always
	 * has ID 0, which is what every thread starts out with. Other IDs come
	 * from a per-zone counter, so that they are not reused if the file
	 * system is unmounted and mounted again; see cgrp_cg_lwp_lookup().
	 */
	if (parent == dir) {
		dir->cgn_id = 0;
	} else {
		lx_zone_data_t *lxzd = cgm->cg_lxzdata;
		uint_t id;

		do {
			id = atomic_inc_uint_nv(&lxzd->lxzd_cgroup_lastid);
		} while (id == 0);
		dir->cgn_id = id;
	}
	cgrp_cg_hash_insert(cgm, dir);

	/*
	 * Initialize the entries
	 */
	dot = kmem_zalloc(sizeof (cgrp_dirent_t) + 2, KM_SLEEP);
	dot->cgd_cgrp_node = dir;
	dot->cgd_offset = 0;
	dot->cgd_name = (char *)dot + sizeof (cgrp_dirent_t);
	dot->cgd_name[0] = '.';
	dot->cgd_parent = dir;
	cgrp_hash_in(dot);

	dotdot = kmem_zalloc(sizeof (cgrp_dirent_t) + 3, KM_SLEEP);
	dotdot->cgd_cgrp_node = parent;
	dotdot->cgd_offset = 1;
	dotdot->cgd_name = (char *)dotdot + sizeof (cgrp_dirent_t);
	dotdot->cgd_name[0] = '.';
	dotdot->cgd_name[1] = '.';
	dotdot->cgd_parent = dir;
	cgrp_hash_in(dotdot);

	/*
	 * Initialize directory entry list.
	 */
	dot->cgd_next = dotdot;
	dot->cgd_prev = dotdot;	/* dot's cgd_prev holds roving slot pointer */
	dotdot->cgd_next = NULL;
	dotdot->cgd_prev = dot;

	gethrestime(&now);
	dir->cgn_mtime = now;
	dir->cgn_ctime = now;

	parent->cgn_nlink++;
	parent->cgn_ctime = now;

	dir->cgn_dir = dot;
	dir->cgn_size = 2 * sizeof (cgrp_dirent_t) + 5;	/* dot and dotdot */
	dir->cgn_dirents = 2;
	dir->cgn_nlink = 2;
	dir->cgn_max_depth = CGRP_LIMIT_MAX;
	dir->cgn_max_desc = CGRP_LIMIT_MAX;

	bzero(&nattr, sizeof (struct vattr));
	nattr.va_mode = (mode_t)(0644);
	nattr.va_type = VREG;
	nattr.va_rdev = 0;

	/*
	 * If this is the top-level dir of a cgroup v1 file system then it
	 * always has a release_agent pseudo file. Only the top-level dir has
	 * this file. There is no release agent in cgroup v2; cgroup.events
	 * is used to notify about empty cgroups instead.
	 */
	if (parent == dir && !CG_IS_V2(cgm)) {
		cgrp_addnode(cgm, dir, "release_agent", CG_REL_AGENT, &nattr,
		    cr);
	}

	pseudo_files = ssdp->cg_ssde_files;
	for (i = 0; i < ssdp->cg_ssde_nfiles; i++) {
		uint_t flags = pseudo_files[i].cgrp_ssd_flags;

		if (parent == dir && (flags & CGSD_NONROOT_ONLY) != 0)
			continue;
		if (parent != dir && (flags & CGSD_ROOT_ONLY) != 0)
			continue;

		nattr.va_mode = pseudo_files[i].cgrp_ssd_mode;
		cgrp_addnode(cgm, dir, pseudo_files[i].cgrp_ssd_name,
		    pseudo_files[i].cgrp_ssd_type, &nattr, cr);
	}
}

/*
 * cgrp_dirtrunc is called to remove all directory entries under this directory.
 */
void
cgrp_dirtrunc(cgrp_node_t *dir)
{
	cgrp_dirent_t *cgdp;
	timestruc_t now;

	ASSERT(MUTEX_HELD(&VTOCGM(dir->cgn_vnode)->cg_contents));
	ASSERT(dir->cgn_type == CG_CGROUP_DIR);

	for (cgdp = dir->cgn_dir; cgdp; cgdp = dir->cgn_dir) {
		size_t namelen;
		cgrp_node_t *cn;

		ASSERT(cgdp->cgd_next != cgdp);
		ASSERT(cgdp->cgd_prev != cgdp);
		ASSERT(cgdp->cgd_cgrp_node);

		dir->cgn_dir = cgdp->cgd_next;
		namelen = strlen(cgdp->cgd_name) + 1;

		/*
		 * Adjust the link counts to account for this directory entry
		 * removal. We do hold/rele operations to free up these nodes.
		 */
		cn = cgdp->cgd_cgrp_node;
		ASSERT(cn->cgn_nlink > 0);
		cn->cgn_nlink--;

		cgrp_hash_out(cgdp);
		kmem_free(cgdp, sizeof (cgrp_dirent_t) + namelen);
		dir->cgn_size -= (sizeof (cgrp_dirent_t) + namelen);
		dir->cgn_dirents--;
	}

	gethrestime(&now);
	dir->cgn_mtime = now;
	dir->cgn_ctime = now;

	ASSERT(dir->cgn_dir == NULL);
	ASSERT(dir->cgn_size == 0);
	ASSERT(dir->cgn_dirents == 0);
}

static int
cgrp_diraddentry(cgrp_node_t *dir, cgrp_node_t *cn, char *name)
{
	cgrp_dirent_t *cdp, *cpdp;
	size_t		namelen, alloc_size;
	timestruc_t	now;

	/*
	 * Make sure the parent directory wasn't removed from
	 * underneath the caller.
	 */
	if (dir->cgn_dir == NULL)
		return (ENOENT);

	/* Check that everything is on the same filesystem. */
	if (cn->cgn_vnode->v_vfsp != dir->cgn_vnode->v_vfsp)
		return (EXDEV);

	/*
	 * Allocate and initialize directory entry. Unlike tmpfs, which this
	 * code derives from, there is no file system size limit to enforce,
	 * so we can sleep for the memory (cgrp_addnode() can't handle a
	 * failure here).
	 */
	namelen = strlen(name) + 1;
	alloc_size = namelen + sizeof (cgrp_dirent_t);
	cdp = kmem_zalloc(alloc_size, KM_SLEEP);

	cn->cgn_parent = dir;

	dir->cgn_size += alloc_size;
	dir->cgn_dirents++;
	cdp->cgd_cgrp_node = cn;
	cdp->cgd_parent = dir;

	/* The directory entry and its name were allocated sequentially. */
	cdp->cgd_name = (char *)cdp + sizeof (cgrp_dirent_t);
	(void) strcpy(cdp->cgd_name, name);

	cgrp_hash_in(cdp);

	/*
	 * Some utilities expect the size of a directory to remain
	 * somewhat static.  For example, a routine which removes
	 * subdirectories between calls to readdir(); the size of the
	 * directory changes from underneath it and so the real
	 * directory offset in bytes is invalid.  To circumvent
	 * this problem, we initialize a directory entry with an
	 * phony offset, and use this offset to determine end of
	 * file in cgrp_readdir.
	 */
	cpdp = dir->cgn_dir->cgd_prev;
	/*
	 * Install at first empty "slot" in directory list.
	 */
	while (cpdp->cgd_next != NULL && (cpdp->cgd_next->cgd_offset -
	    cpdp->cgd_offset) <= 1) {
		ASSERT(cpdp->cgd_next != cpdp);
		ASSERT(cpdp->cgd_prev != cpdp);
		ASSERT(cpdp->cgd_next->cgd_offset > cpdp->cgd_offset);
		cpdp = cpdp->cgd_next;
	}
	cdp->cgd_offset = cpdp->cgd_offset + 1;

	/*
	 * If we're at the end of the dirent list and the offset (which
	 * is necessarily the largest offset in this directory) is more
	 * than twice the number of dirents, that means the directory is
	 * 50% holes.  At this point we reset the slot pointer back to
	 * the beginning of the directory so we start using the holes.
	 * The idea is that if there are N dirents, there must also be
	 * N holes, so we can satisfy the next N creates by walking at
	 * most 2N entries; thus the average cost of a create is constant.
	 * Note that we use the first dirent's cgd_prev as the roving
	 * slot pointer; it's ugly, but it saves a word in every dirent.
	 */
	if (cpdp->cgd_next == NULL && cpdp->cgd_offset > 2 * dir->cgn_dirents)
		dir->cgn_dir->cgd_prev = dir->cgn_dir->cgd_next;
	else
		dir->cgn_dir->cgd_prev = cdp;

	ASSERT(cpdp->cgd_next != cpdp);
	ASSERT(cpdp->cgd_prev != cpdp);

	cdp->cgd_next = cpdp->cgd_next;
	if (cdp->cgd_next) {
		cdp->cgd_next->cgd_prev = cdp;
	}
	cdp->cgd_prev = cpdp;
	cpdp->cgd_next = cdp;

	ASSERT(cdp->cgd_next != cdp);
	ASSERT(cdp->cgd_prev != cdp);
	ASSERT(cpdp->cgd_next != cpdp);
	ASSERT(cpdp->cgd_prev != cpdp);

	gethrestime(&now);
	dir->cgn_mtime = now;
	dir->cgn_ctime = now;

	return (0);
}

static int
cgrp_dirmakecgnode(cgrp_node_t *dir, cgrp_mnt_t *cgm, struct vattr *va,
    enum de_op op, cgrp_node_t **newnode, struct cred *cred)
{
	cgrp_node_t *cn;

	ASSERT(MUTEX_HELD(&cgm->cg_contents));
	ASSERT(va != NULL);

	if (((va->va_mask & AT_ATIME) && TIMESPEC_OVERFLOW(&va->va_atime)) ||
	    ((va->va_mask & AT_MTIME) && TIMESPEC_OVERFLOW(&va->va_mtime)))
		return (EOVERFLOW);

	cn = kmem_zalloc(sizeof (cgrp_node_t), KM_SLEEP);
	cgrp_node_init(cgm, cn, va, cred);

	cn->cgn_vnode->v_rdev = cn->cgn_rdev = NODEV;
	cn->cgn_vnode->v_type = va->va_type;
	cn->cgn_uid = crgetuid(cred);
	cn->cgn_gid = crgetgid(cred);

	if (va->va_mask & AT_ATIME)
		cn->cgn_atime = va->va_atime;
	if (va->va_mask & AT_MTIME)
		cn->cgn_mtime = va->va_mtime;

	if (op == DE_MKDIR) {
		cn->cgn_type = CG_CGROUP_DIR;
		cgrp_dirinit(dir, cn, cred);
	}

	*newnode = cn;
	return (0);
}

/*
 * Construct the path of the cgroup 'cn', relative to the mount point of the
 * file system (e.g. "/system.slice/foo.service"). The top-level cgroup is "/".
 *
 * Returns 0 on success, or ENAMETOOLONG if the path won't fit.
 */
int
cgrp_get_path(cgrp_node_t *cn, char *buf, size_t blen)
{
	size_t off;

	ASSERT(MUTEX_HELD(&VTOCGM(cn->cgn_vnode)->cg_contents));
	ASSERT(cn->cgn_type == CG_CGROUP_DIR);
	ASSERT(blen >= 2);

	/* Build the path backwards from the end of the buffer. */
	off = blen - 1;
	buf[off] = '\0';

	while (cn->cgn_parent != NULL && cn->cgn_parent != cn) {
		cgrp_node_t *parent = cn->cgn_parent;
		cgrp_dirent_t *dp;
		size_t len;

		for (dp = parent->cgn_dir; dp != NULL; dp = dp->cgd_next) {
			if (dp->cgd_cgrp_node == cn &&
			    strcmp(dp->cgd_name, ".") != 0 &&
			    strcmp(dp->cgd_name, "..") != 0)
				break;
		}
		if (dp == NULL)
			return (ENOENT);

		len = strlen(dp->cgd_name);
		if (len + 1 > off)
			return (ENAMETOOLONG);
		off -= len;
		bcopy(dp->cgd_name, &buf[off], len);
		buf[--off] = '/';

		cn = parent;
	}

	if (off == blen - 1) {
		/* top-level cgroup */
		(void) strlcpy(buf, "/", blen);
	} else {
		ovbcopy(&buf[off], buf, blen - off);
	}

	return (0);
}

/*
 * Taskq callback to deliver cgroup.events notifications. We generate a
 * VE_RESIZE vnode event on the cgroup.events vnode, which the inotify driver
 * reports as IN_MODIFY. This is how systemd (and others) learn that a cgroup
 * has become empty (or populated) in cgroup v2.
 *
 * This is done asynchronously since the populated state changes in contexts
 * (e.g. lwp creation with p_lock held) where calling into the vnode event
 * framework is not safe.
 *
 * cgrp_evtq has a single thread, shared by all mounts (i.e. all lx zones).
 * So that a zone which keeps changing the populated state of its cgroups
 * can't hold up the notifications of other zones, we only deliver the
 * notifications which were pending when we started. If more have been
 * queued in the meantime, we dispatch ourselves again, at the end of the
 * queue.
 */
static void
cgrp_events_notify(void *arg)
{
	cgrp_mnt_t *cgm = arg;
	cgrp_node_t *cn;

	mutex_enter(&cgm->cg_contents);
	cn = cgm->cg_evlist;
	cgm->cg_evlist = NULL;
	mutex_exit(&cgm->cg_contents);

	while (cn != NULL) {
		cgrp_node_t *next;

		/*
		 * A node can be queued again as soon as it is no longer
		 * marked as pending, which reuses cgn_evnext, so take it off
		 * our batch first.
		 */
		mutex_enter(&cgm->cg_contents);
		next = cn->cgn_evnext;
		cn->cgn_evnext = NULL;
		cn->cgn_evpend = B_FALSE;
		mutex_exit(&cgm->cg_contents);

		vnevent_resize(CGNTOV(cn), NULL);
		/* Drop the hold taken in cgrp_events_post */
		cgnode_rele(cn);
		cn = next;
	}

	mutex_enter(&cgm->cg_contents);
	if (cgm->cg_evlist != NULL) {
		/* cg_evsched stays set; the taskq entry is ours again */
		taskq_dispatch_ent(cgrp_evtq, cgrp_events_notify, cgm, 0,
		    &cgm->cg_evtqent);
	} else {
		cgm->cg_evsched = B_FALSE;
		/* Wake up cgrp_events_drain() */
		cv_broadcast(&cgm->cg_evcv);
	}
	mutex_exit(&cgm->cg_contents);
	/* cgm must not be referenced after this point */
}

/*
 * Wait until no notification task is queued or running for this mount. Since
 * a task drops the hold on each node it delivers before it next checks the
 * list, all holds taken by cgrp_events_post() have been released once this
 * returns. cgrp_evtq is shared by all mounts, so we must not use taskq_wait()
 * here, which could be held up indefinitely by notifications for other zones.
 */
void
cgrp_events_drain(cgrp_mnt_t *cgm)
{
	ASSERT(MUTEX_HELD(&cgm->cg_contents));

	while (cgm->cg_evsched)
		cv_wait(&cgm->cg_evcv, &cgm->cg_contents);
}

/*
 * Queue a change notification for the cgroup.events file of cgroup 'dir'.
 */
static void
cgrp_events_post(cgrp_mnt_t *cgm, cgrp_node_t *dir)
{
	cgrp_node_t *ev = dir->cgn_events;

	ASSERT(MUTEX_HELD(&cgm->cg_contents));

	if (ev == NULL || ev->cgn_evpend)
		return;

	/*
	 * The hold keeps the node around until the notification has been
	 * delivered, even if the cgroup is removed in the meantime.
	 */
	cgnode_hold(ev);
	ev->cgn_evpend = B_TRUE;
	ev->cgn_evnext = cgm->cg_evlist;
	cgm->cg_evlist = ev;

	if (!cgm->cg_evsched) {
		cgm->cg_evsched = B_TRUE;
		taskq_dispatch_ent(cgrp_evtq, cgrp_events_notify, cgm, 0,
		    &cgm->cg_evtqent);
	}
}

/*
 * Adjust the number of threads in cgroup 'cn' by 'delta', maintaining the
 * per-subtree thread count used for the cgroup v2 "populated" state, and
 * queueing a cgroup.events notification for every cgroup whose populated state
 * changes.
 *
 * The thread counts of the top-level cgroup are not maintained. Doing so would
 * require counting the threads already running in the zone when the file
 * system is mounted, which can't be done reliably since the lwp fork hook
 * runs with p_lock held. The counts are also not needed: the top-level cgroup
 * can't be removed, has no cgroup.events file, and is never released.
 */
void
cgrp_task_adjust(cgrp_mnt_t *cgm, cgrp_node_t *cn, int delta)
{
	ASSERT(MUTEX_HELD(&cgm->cg_contents));
	ASSERT(delta == 1 || delta == -1);

	if (cn == cgm->cg_rootnode)
		return;

	if (delta > 0) {
		cn->cgn_task_cnt++;
	} else {
		ASSERT(cn->cgn_task_cnt > 0);
		cn->cgn_task_cnt--;
	}

	if (!CG_IS_V2(cgm))
		return;

	for (;;) {
		boolean_t changed;

		if (delta > 0) {
			changed = (cn->cgn_subtree_cnt++ == 0);
		} else {
			ASSERT(cn->cgn_subtree_cnt > 0);
			changed = (--cn->cgn_subtree_cnt == 0);
		}

		if (changed)
			cgrp_events_post(cgm, cn);

		cn = cn->cgn_parent;
		if (cn == NULL || cn == cgm->cg_rootnode)
			break;
	}
}

/*
 * Adjust the descendant count of all ancestors of the cgroup 'cn'. Used for
 * cgroup.stat.
 */
void
cgrp_ndesc_adjust(cgrp_node_t *cn, int delta)
{
	ASSERT(MUTEX_HELD(&VTOCGM(cn->cgn_vnode)->cg_contents));

	while (cn->cgn_parent != NULL && cn->cgn_parent != cn) {
		cn = cn->cgn_parent;
		cn->cgn_ndesc += delta;
	}
}
