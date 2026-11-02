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
 * Copyright (c) 2018, Joyent, Inc.
 * Copyright 2026 Edgecast Cloud LLC.
 */

/*
 * Linux POSIX ACL emulation.
 *
 * Linux exposes POSIX draft ACLs through the "system.posix_acl_access" and
 * "system.posix_acl_default" extended attributes.  Their encoding maps
 * directly onto illumos aclent_t entries.  On file systems with POSIX draft
 * ACLs (_ACL_ACLENT_ENABLED) the entries are stored as they are.  On file
 * systems with NFSv4 ACLs (_ACL_ACE_ENABLED, i.e. ZFS) they are translated
 * with acl_translate(), the same conversion that setfacl(1) uses.  Setting
 * one of the two attributes leaves the other part of the ACL untouched.
 *
 * File systems without ACL support (e.g. tmpfs) behave as before: reads
 * report no ACL and writes fail with EOPNOTSUPP.
 */

#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sys/errno.h>
#include <sys/cred.h>
#include <sys/sunddi.h>
#include <sys/pathname.h>
#include <sys/vnode.h>
#include <sys/vfs.h>
#include <sys/unistd.h>
#include <sys/acl.h>
#include <acl/acl_common.h>
#include <sys/lx_acl.h>


typedef struct {
	uint16_t lpaxe_tag;
	uint16_t lpaxe_perm;
	uint32_t lpaxe_id;
} lx_posix_acl_xattr_entry_t;

typedef struct {
	uint32_t			lpaxh_version;
	lx_posix_acl_xattr_entry_t	lpaxh_entries[];
} lx_posix_acl_xattr_header_t;

#define	LX_POSIX_ACL_XATTR_VERSION	0x0002

/* e_tag entry in struct posix_acl_entry */
#define	LX_ACL_USER_OBJ		0x01	/* USER_OBJ	*/
#define	LX_ACL_USER		0x02	/* USER		*/
#define	LX_ACL_GROUP_OBJ	0x04	/* GROUP_OBJ	*/
#define	LX_ACL_GROUP		0x08	/* GROUP	*/
#define	LX_ACL_MASK		0x10	/* CLASS_OBJ	*/
#define	LX_ACL_OTHER		0x20	/* OTHER_OBJ	*/

#define	LX_ACL_UNDEFINED_ID	((uint32_t)-1)
#define	LX_ACL_PERM_MASK	07

CTASSERT(LX_ACL_USER_OBJ == USER_OBJ);
CTASSERT(LX_ACL_USER == USER);
CTASSERT(LX_ACL_GROUP_OBJ == GROUP_OBJ);
CTASSERT(LX_ACL_GROUP == GROUP);
CTASSERT(LX_ACL_MASK == CLASS_OBJ);
CTASSERT(LX_ACL_OTHER == OTHER_OBJ);

static boolean_t
lx_acl_is_default(const aclent_t *ae)
{
	return ((ae->a_type & ACL_DEFAULT) != 0);
}

/*
 * Validate a set of POSIX ACL entries the same way Linux posix_acl_valid()
 * does: exactly one USER_OBJ, GROUP_OBJ and OTHER entry, at most one MASK,
 * which is required as soon as named USER or GROUP entries are present.
 */
static int
lx_acl_valid(const aclent_t *ae, uint_t cnt)
{
	uint_t nuobj = 0, ngobj = 0, nother = 0, nmask = 0, nnamed = 0;

	for (uint_t i = 0; i < cnt; i++) {
		switch (ae[i].a_type & ~ACL_DEFAULT) {
		case USER_OBJ:
			nuobj++;
			break;
		case GROUP_OBJ:
			ngobj++;
			break;
		case OTHER_OBJ:
			nother++;
			break;
		case CLASS_OBJ:
			nmask++;
			break;
		case USER:
		case GROUP:
			nnamed++;
			break;
		default:
			return (EINVAL);
		}
	}

	if (nuobj != 1 || ngobj != 1 || nother != 1 || nmask > 1 ||
	    (nnamed != 0 && nmask == 0)) {
		return (EINVAL);
	}
	return (0);
}

/*
 * Decode a Linux POSIX ACL xattr into aclent_t entries.  Entries of a
 * default ACL are tagged with ACL_DEFAULT.  An empty value yields no entries.
 */
static int
lx_acl_from_xattr(enum lx_acl_type atype, void *xattr, size_t xlen,
    aclent_t **entp, uint_t *cntp)
{
	lx_posix_acl_xattr_header_t *head = xattr;
	lx_posix_acl_xattr_entry_t *entry;
	const int dflag = (atype == LX_ACL_DEFAULT) ? ACL_DEFAULT : 0;
	aclent_t *ae;
	uint_t count;
	size_t sz;
	int err;

	*entp = NULL;
	*cntp = 0;

	if (xattr == NULL || xlen == 0)
		return (0);

	if (xlen < sizeof (*head)) {
		return (EINVAL);
	} else if (head->lpaxh_version != LX_POSIX_ACL_XATTR_VERSION) {
		return (EOPNOTSUPP);
	}

	sz = xlen - sizeof (*head);
	if (sz % sizeof (lx_posix_acl_xattr_entry_t) != 0)
		return (EINVAL);
	count = sz / sizeof (lx_posix_acl_xattr_entry_t);
	if (count == 0)
		return (0);
	if (count > MAX_ACL_ENTRIES)
		return (EINVAL);

	ae = kmem_zalloc(count * sizeof (aclent_t), KM_SLEEP);
	entry = head->lpaxh_entries;
	for (uint_t i = 0; i < count; i++, entry++) {
		switch (entry->lpaxe_tag) {
		case LX_ACL_USER:
		case LX_ACL_GROUP:
			if (entry->lpaxe_id > MAXUID) {
				kmem_free(ae, count * sizeof (aclent_t));
				return (EINVAL);
			}
			ae[i].a_id = entry->lpaxe_id;
			break;
		default:
			/* Linux uses ACL_UNDEFINED_ID for the base entries */
			ae[i].a_id = 0;
			break;
		}
		ae[i].a_type = entry->lpaxe_tag | dflag;
		ae[i].a_perm = entry->lpaxe_perm & LX_ACL_PERM_MASK;
	}

	if ((err = lx_acl_valid(ae, count)) != 0) {
		kmem_free(ae, count * sizeof (aclent_t));
		return (err);
	}

	*entp = ae;
	*cntp = count;
	return (0);
}

/*
 * Report the ACL flavor supported by the file system, or 0 if none.
 */
static int
lx_acl_flavor(vnode_t *vp, cred_t *cr)
{
	ulong_t val = 0;

	if (VOP_PATHCONF(vp, _PC_ACL_ENABLED, &val, cr, NULL) != 0)
		return (0);
	if ((val & _ACL_ACE_ENABLED) != 0)
		return (_ACL_ACE_ENABLED);
	if ((val & _ACL_ACLENT_ENABLED) != 0)
		return (_ACL_ACLENT_ENABLED);
	return (0);
}

/*
 * Fetch the current ACL of a vnode as POSIX draft entries, both access and
 * default ones.
 */
static int
lx_acl_get_aent(vnode_t *vp, int flavor, cred_t *cr, acl_t **aclpp)
{
	const boolean_t is_dir = (vp->v_type == VDIR);
	vsecattr_t vsa;
	acl_t *acl;
	int err;

	bzero(&vsa, sizeof (vsa));
	if (flavor == _ACL_ACE_ENABLED) {
		vattr_t va;

		va.va_mask = AT_UID | AT_GID;
		if ((err = VOP_GETATTR(vp, &va, 0, cr, NULL)) != 0)
			return (err);

		vsa.vsa_mask = VSA_ACE | VSA_ACECNT;
		if ((err = VOP_GETSECATTR(vp, &vsa, 0, cr, NULL)) != 0)
			return (err);

		if (vsa.vsa_aclcnt == 0 || vsa.vsa_aclentp == NULL ||
		    vsa.vsa_aclentsz != vsa.vsa_aclcnt * sizeof (ace_t)) {
			/* Empty, or containing object ACEs we can't map */
			if (vsa.vsa_aclentp != NULL)
				kmem_free(vsa.vsa_aclentp, vsa.vsa_aclentsz);
			return (EOPNOTSUPP);
		}

		acl = acl_alloc(ACE_T);
		acl->acl_aclp = vsa.vsa_aclentp;
		acl->acl_cnt = vsa.vsa_aclcnt;
		if (acl_translate(acl, _ACL_ACLENT_ENABLED, is_dir,
		    va.va_uid, va.va_gid) != 0) {
			/* The NFSv4 ACL has no POSIX draft equivalent */
			acl_free(acl);
			return (EOPNOTSUPP);
		}
	} else {
		size_t asz, dsz;

		vsa.vsa_mask = VSA_ACL | VSA_ACLCNT | VSA_DFACL | VSA_DFACLCNT;
		if ((err = VOP_GETSECATTR(vp, &vsa, 0, cr, NULL)) != 0)
			return (err);

		asz = vsa.vsa_aclcnt * sizeof (aclent_t);
		dsz = vsa.vsa_dfaclcnt * sizeof (aclent_t);
		acl = acl_alloc(ACLENT_T);
		acl->acl_cnt = vsa.vsa_aclcnt + vsa.vsa_dfaclcnt;
		if (acl->acl_cnt != 0) {
			aclent_t *ae;

			ae = kmem_alloc(asz + dsz, KM_SLEEP);
			if (asz != 0)
				bcopy(vsa.vsa_aclentp, ae, asz);
			if (dsz != 0) {
				bcopy(vsa.vsa_dfaclentp,
				    ae + vsa.vsa_aclcnt, dsz);
			}
			acl->acl_aclp = ae;
		}
		if (vsa.vsa_aclentp != NULL && asz != 0)
			kmem_free(vsa.vsa_aclentp, asz);
		if (vsa.vsa_dfaclentp != NULL && dsz != 0)
			kmem_free(vsa.vsa_dfaclentp, dsz);
	}

	*aclpp = acl;
	return (0);
}

/*
 * Store a complete set of POSIX draft entries (access and default) on a
 * vnode.  The acl_t is consumed by translation, but still owned by the
 * caller.
 */
static int
lx_acl_set_aent(vnode_t *vp, int flavor, acl_t *acl, cred_t *cr)
{
	const boolean_t is_dir = (vp->v_type == VDIR);
	aclent_t *ae = acl->acl_aclp;
	vsecattr_t vsa;
	uint_t nacc;
	int err;

	if (vn_is_readonly(vp))
		return (EROFS);

	ksort((caddr_t)ae, acl->acl_cnt, sizeof (aclent_t), cmp2acls);
	for (nacc = 0; nacc < acl->acl_cnt; nacc++) {
		if (lx_acl_is_default(&ae[nacc]))
			break;
	}
	if (nacc != acl->acl_cnt && !is_dir)
		return (EACCES);

	bzero(&vsa, sizeof (vsa));
	if (flavor == _ACL_ACE_ENABLED) {
		if ((err = acl_translate(acl, _ACL_ACE_ENABLED, is_dir,
		    0, 0)) != 0) {
			return (err);
		}
		vsa.vsa_mask = VSA_ACE;
		vsa.vsa_aclentp = acl->acl_aclp;
		vsa.vsa_aclcnt = acl->acl_cnt;
		vsa.vsa_aclentsz = acl->acl_cnt * sizeof (ace_t);
	} else {
		vsa.vsa_mask = VSA_ACL;
		vsa.vsa_aclentp = ae;
		vsa.vsa_aclcnt = nacc;
		if (nacc != acl->acl_cnt) {
			vsa.vsa_mask |= VSA_DFACL;
			vsa.vsa_dfaclentp = ae + nacc;
			vsa.vsa_dfaclcnt = acl->acl_cnt - nacc;
		}
	}

	(void) VOP_RWLOCK(vp, V_WRITELOCK_TRUE, NULL);
	err = VOP_SETSECATTR(vp, &vsa, 0, cr, NULL);
	VOP_RWUNLOCK(vp, V_WRITELOCK_TRUE, NULL);

	return (err);
}

/*
 * Report whether the access entries of an ACL carry more than the file mode,
 * i.e. whether it has named user or group entries.
 */
static boolean_t
lx_acl_access_extended(const acl_t *acl)
{
	const aclent_t *ae = acl->acl_aclp;

	for (int i = 0; i < acl->acl_cnt; i++) {
		if (lx_acl_is_default(&ae[i]))
			continue;
		if (ae[i].a_type == USER || ae[i].a_type == GROUP)
			return (B_TRUE);
	}
	return (B_FALSE);
}

static uint_t
lx_acl_count(const acl_t *acl, enum lx_acl_type atype)
{
	const aclent_t *ae = acl->acl_aclp;
	const boolean_t want_dflt = (atype == LX_ACL_DEFAULT);
	uint_t n = 0;

	for (int i = 0; i < acl->acl_cnt; i++) {
		if (lx_acl_is_default(&ae[i]) == want_dflt)
			n++;
	}
	return (n);
}

/*
 * Build a new ACL from the entries of 'cur' which are not of type 'atype',
 * plus 'cnt' new entries.
 */
static acl_t *
lx_acl_merge(const acl_t *cur, enum lx_acl_type atype, const aclent_t *ents,
    uint_t cnt)
{
	const boolean_t want_dflt = (atype == LX_ACL_DEFAULT);
	const aclent_t *cae = (cur != NULL) ? cur->acl_aclp : NULL;
	uint_t keep = 0, n = 0;
	aclent_t *ae;
	acl_t *acl;

	if (cur != NULL)
		keep = cur->acl_cnt - lx_acl_count(cur, atype);

	acl = acl_alloc(ACLENT_T);
	if (keep + cnt == 0)
		return (acl);

	ae = kmem_alloc((keep + cnt) * sizeof (aclent_t), KM_SLEEP);
	for (int i = 0; cur != NULL && i < cur->acl_cnt; i++) {
		if (lx_acl_is_default(&cae[i]) != want_dflt)
			ae[n++] = cae[i];
	}
	for (uint_t i = 0; i < cnt; i++)
		ae[n++] = ents[i];
	ASSERT3U(n, ==, keep + cnt);

	acl->acl_aclp = ae;
	acl->acl_cnt = n;
	return (acl);
}

/*
 * Replace one part of the ACL of a vnode.  When 'cnt' is 0 the part is
 * removed: a default ACL disappears, an access ACL is reduced to the
 * entries equivalent to the file mode.
 */
static int
lx_acl_replace(vnode_t *vp, int flavor, enum lx_acl_type atype,
    aclent_t *ents, uint_t cnt, boolean_t must_exist, cred_t *cr)
{
	aclent_t base[3];
	acl_t *cur = NULL, *acl;
	int err;

	/*
	 * A non-directory has no default ACL to preserve, so there is no need
	 * to read (and possibly fail to translate) its current ACL when it
	 * is given a complete new access ACL.
	 */
	if (vp->v_type == VDIR || cnt == 0) {
		if ((err = lx_acl_get_aent(vp, flavor, cr, &cur)) != 0)
			return (err);
	}

	if (cnt == 0) {
		if (atype == LX_ACL_DEFAULT) {
			if (must_exist && lx_acl_count(cur, atype) == 0) {
				acl_free(cur);
				return (ENODATA);
			}
		} else {
			const aclent_t *cae = cur->acl_aclp;
			ushort_t mask = LX_ACL_PERM_MASK;
			boolean_t have_mask = B_FALSE;

			if (must_exist && !lx_acl_access_extended(cur)) {
				acl_free(cur);
				return (ENODATA);
			}

			/*
			 * Fold the mask into the group permissions, as the
			 * group bits of the mode reflect the mask.
			 */
			bzero(base, sizeof (base));
			base[0].a_type = USER_OBJ;
			base[1].a_type = GROUP_OBJ;
			base[2].a_type = OTHER_OBJ;
			for (int i = 0; i < cur->acl_cnt; i++) {
				switch (cae[i].a_type) {
				case USER_OBJ:
					base[0].a_perm = cae[i].a_perm;
					break;
				case GROUP_OBJ:
					base[1].a_perm = cae[i].a_perm;
					break;
				case OTHER_OBJ:
					base[2].a_perm = cae[i].a_perm;
					break;
				case CLASS_OBJ:
					mask = cae[i].a_perm;
					have_mask = B_TRUE;
					break;
				default:
					break;
				}
			}
			if (have_mask)
				base[1].a_perm &= mask;
			ents = base;
			cnt = 3;
		}
	}

	acl = lx_acl_merge(cur, atype, ents, cnt);
	err = lx_acl_set_aent(vp, flavor, acl, cr);
	acl_free(acl);
	acl_free(cur);

	return (err);
}

/*
 * Fallback for file systems without ACL support.
 */
static int
lx_acl_unsupported(vnode_t *vp, cred_t *cr)
{
	int err = EOPNOTSUPP;

	/*
	 * Because systemd has decided to scope-creep its way into a position
	 * of moribund domination over all things system software, there exist
	 * work-arounds which are required to address its numerous bugs and
	 * shortcomings.  One such case involves the FreeIPA installer needing
	 * to perform setfacl(3) on /run/systemd/ask-password.
	 *
	 * The path in question resides on tmpfs, which doesn't yet support
	 * ACLs at all on illumos, so faked success is the only palatable
	 * course of action for now.  Atonement will follow.
	 *
	 * See also: https://bugzilla.redhat.com/show_bug.cgi?id=1322167
	 */
	if (crgetuid(cr) == 0) {
		char *path = kmem_alloc(MAXPATHLEN, KM_SLEEP);

		if (vnodetopath(NULL, vp, path, MAXPATHLEN, cr) == 0 &&
		    strncmp(path, "/run/systemd/", 13) == 0) {
			/* Saccharin-sweet fake success */
			err = 0;
		}
		kmem_free(path, MAXPATHLEN);
	}

	return (err);
}

int
lx_acl_setxattr(vnode_t *vp, enum lx_acl_type atype, void *data, size_t len)
{
	const boolean_t is_dir = (vp->v_type == VDIR);
	cred_t *cr = CRED();
	aclent_t *ents;
	uint_t cnt;
	int flavor, err;

	if (vp->v_type == VLNK) {
		return (EOPNOTSUPP);
	} else if (atype == LX_ACL_DEFAULT && !is_dir) {
		return (EACCES);
	}

	/* Copyin and verify the input */
	if ((err = lx_acl_from_xattr(atype, data, len, &ents, &cnt)) != 0)
		return (err);

	if ((flavor = lx_acl_flavor(vp, cr)) == 0) {
		err = lx_acl_unsupported(vp, cr);
	} else {
		err = lx_acl_replace(vp, flavor, atype, ents, cnt, B_FALSE,
		    cr);
	}

	if (ents != NULL)
		kmem_free(ents, cnt * sizeof (aclent_t));
	return (err);
}

int
lx_acl_getxattr(vnode_t *vp, enum lx_acl_type atype, void *data, size_t slen,
    ssize_t *solen)
{
	const boolean_t is_dir = (vp->v_type == VDIR);
	const boolean_t want_dflt = (atype == LX_ACL_DEFAULT);
	lx_posix_acl_xattr_header_t *head = data;
	lx_posix_acl_xattr_entry_t *entry;
	cred_t *cr = CRED();
	const aclent_t *ae;
	acl_t *acl;
	size_t need;
	uint_t cnt;
	int flavor, err;

	if (vp->v_type == VLNK) {
		return (EOPNOTSUPP);
	} else if (atype == LX_ACL_DEFAULT && !is_dir) {
		return (ENODATA);
	}

	if ((flavor = lx_acl_flavor(vp, cr)) == 0)
		return (ENODATA);

	if ((err = lx_acl_get_aent(vp, flavor, cr, &acl)) != 0)
		return ((err == ENOENT) ? ENODATA : err);

	/*
	 * An access ACL which is equivalent to the file mode is not reported,
	 * matching Linux.
	 */
	cnt = lx_acl_count(acl, atype);
	if (cnt == 0 || (!want_dflt && !lx_acl_access_extended(acl))) {
		acl_free(acl);
		return (ENODATA);
	}

	need = sizeof (*head) + cnt * sizeof (lx_posix_acl_xattr_entry_t);
	if (slen == 0) {
		/* Size query */
		acl_free(acl);
		*solen = need;
		return (0);
	} else if (slen < need) {
		acl_free(acl);
		return (ERANGE);
	}

	ksort((caddr_t)acl->acl_aclp, acl->acl_cnt, sizeof (aclent_t),
	    cmp2acls);
	head->lpaxh_version = LX_POSIX_ACL_XATTR_VERSION;
	entry = head->lpaxh_entries;
	ae = acl->acl_aclp;
	for (int i = 0; i < acl->acl_cnt; i++) {
		const int type = ae[i].a_type & ~ACL_DEFAULT;

		if (lx_acl_is_default(&ae[i]) != want_dflt)
			continue;
		entry->lpaxe_tag = type;
		entry->lpaxe_perm = ae[i].a_perm & LX_ACL_PERM_MASK;
		entry->lpaxe_id = (type == USER || type == GROUP) ?
		    ae[i].a_id : LX_ACL_UNDEFINED_ID;
		entry++;
	}
	acl_free(acl);

	*solen = need;
	return (0);
}

int
lx_acl_removexattr(vnode_t *vp, enum lx_acl_type atype)
{
	cred_t *cr = CRED();
	int flavor;

	if (vp->v_type == VLNK)
		return (EOPNOTSUPP);
	if (atype == LX_ACL_DEFAULT && vp->v_type != VDIR)
		return (ENODATA);
	if ((flavor = lx_acl_flavor(vp, cr)) == 0)
		return (ENODATA);

	return (lx_acl_replace(vp, flavor, atype, NULL, 0, B_TRUE, cr));
}

/* ARGSUSED */
int
lx_acl_listxattr(vnode_t *vp, uio_t *uio)
{
	return (0);
}
