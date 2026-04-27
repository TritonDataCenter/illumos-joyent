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
 */


#include <sys/param.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/systm.h>
#include <sys/sysmacros.h>
#include <sys/errno.h>
#include <sys/kmem.h>
#include <sys/debug.h>
#include <sys/systm.h>
#include <sys/kstat.h>
#include <sys/sdt.h>
#include <sys/ddi.h>
#include <sys/cmn_err.h>
#include <sys/time.h>
#include <sys/list.h>

#include <rpc/types.h>
#include <rpc/xdr.h>
#include <rpc/clnt.h>
#include <rpc/rpc_msg.h>
#include <rpc/svc.h>
#include <rpc/rpc_tags.h>

static int rpc_cmp_tag_nolock(rpc_xprt_taglist_t *, void *);

/*
 * Initialize a global rpc tags list for a particular xprt type.
 * taglst_off is the offset of the xprt's tag list in the
 * specific xprt type.
 */

void
rpc_taghd_init(rpc_tag_hd_t *taghd, offset_t taglst_off)
{
	mutex_init(&taghd->rth_lock, NULL, MUTEX_DEFAULT, NULL);
	list_create(&taghd->rth_list, sizeof (rpc_tag_t),
	    offsetof(rpc_tag_t, rt_next));
	taghd->rth_xpoff = taglst_off;
}

void
rpc_taghd_destroy(rpc_tag_hd_t *taghd)
{
	mutex_destroy(&taghd->rth_lock);
	list_destroy(&taghd->rth_list);
}

/*
 * Initialize a xprt's tag list
 */

void
rpc_init_taglist(void **xlst)
{
	rpc_xprt_taglist_t *xptlst;

	xptlst = kmem_zalloc(sizeof (rpc_xprt_taglist_t), KM_SLEEP);

	mutex_init(&xptlst->rxtl_lock, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&xptlst->rxtl_cv, NULL, CV_DEFAULT, NULL);
	list_create(&xptlst->rxtl_list, sizeof (rpc_xprt_tag_t),
	    offsetof(rpc_xprt_tag_t, rxt_next));
	*xlst = (void *)xptlst;
}

void
rpc_destroy_taglist(void **xlst)
{
	rpc_xprt_taglist_t *xptlst;

	xptlst = (rpc_xprt_taglist_t *)*xlst;
	mutex_destroy(&xptlst->rxtl_lock);
	cv_destroy(&xptlst->rxtl_cv);
	ASSERT(list_is_empty(&xptlst->rxtl_list));
	list_destroy(&xptlst->rxtl_list);

	kmem_free(xptlst, sizeof (rpc_xprt_taglist_t));
	*xlst = NULL;
}

void
rpc_tag_rele_nolock(rpc_tag_t *tag)
{

	ASSERT(mutex_owned(&(tag)->rt_lock));
	ASSERT((tag)->rt_ref >= 1);
	(tag)->rt_ref--;
	DTRACE_PROBE1(rpc__tag__rele, rpc_tag_t *, tag);
	if ((tag)->rt_ref == 0)
		cv_signal(&(tag)->rt_cv);
}

void
rpc_tag_rele(rpc_tag_t *tag)
{
	mutex_enter(&tag->rt_lock);
	rpc_tag_rele_nolock(tag);
	mutex_exit(&tag->rt_lock);
}

void
rpc_tag_hold(rpc_tag_t *tag)
{
	mutex_enter(&tag->rt_lock);
	RPC_TAG_HOLD_LOCKED(tag);
	mutex_exit(&tag->rt_lock);
}

/*
 * Lookup a tag from a given tag list
 * If a tag is not found and if creat == TRUE, creates a new
 * tag and adds it to the list.
 */

rpc_tag_t *
rpc_lookup_tag(rpc_tag_hd_t *taghd, void *tgid, int creat)
{
	rpc_tag_t *tag;
	mutex_enter(&taghd->rth_lock);
	tag = list_head(&taghd->rth_list);
	while (tag) {
		if (RPC_TAG_CMP(tag->rt_id, tgid) == 0) {
			mutex_enter(&tag->rt_lock);
			RPC_TAG_HOLD_LOCKED(tag);
			mutex_exit(&tag->rt_lock);
			mutex_exit(&taghd->rth_lock);
			return (tag);
		}
		tag = list_next(&taghd->rth_list, tag);
	}

	if (creat == FALSE) {
		mutex_exit(&taghd->rth_lock);
		return (NULL);
	}

	/*
	 * Create a new one
	 */
	tag = (rpc_tag_t *)kmem_zalloc(sizeof (rpc_tag_t), KM_SLEEP);
	bcopy(tgid, tag->rt_id, sizeof (tagid));

	mutex_init(&tag->rt_lock, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&tag->rt_cv, NULL, CV_DEFAULT, NULL);
	list_create(&tag->rt_xplist, sizeof (rpc_tag_xprt_t),
	    offsetof(rpc_tag_xprt_t, rtx_xprt_next));

	/*
	 * Insert onto the global tags list
	 */

	list_insert_tail(&taghd->rth_list, tag);
	tag->rt_ref = 1;

	mutex_exit(&taghd->rth_lock);
	return (tag);

}

/*
 * Given a tag, return the next xprt on the tag's xprt list.
 * A cookie "last" is passed between this function and the caller.
 * Returns the head of the xprt list if the cookie is NULL.
 * Expects tag->rt_lock to be held.
 */

void *
rpc_get_next_xprt(rpc_tag_t *tag, void **last)
{
	rpc_tag_xprt_t *rtxp = (rpc_tag_xprt_t *)*last;

	if (rtxp == NULL)
		rtxp = list_head(&tag->rt_xplist);
	else
		rtxp = list_next(&tag->rt_xplist, rtxp);

	*last = (void *)rtxp;

	/* list empty */
	if (rtxp == NULL)
		return (NULL);

	return (rtxp->rtx_xprt);

}

/*
 * Given a xprt's tagslist, compare tags. Returns TRUE if a tag
 * corresponding to the given tagid value is already present, FALSE if not.
 */
int
rpc_cmp_tag(void *xlst, void *tgid)
{
	rpc_xprt_taglist_t *xtlst;
	int ret;

	xtlst = (rpc_xprt_taglist_t *)xlst;

	mutex_enter(&xtlst->rxtl_lock);
	ret = rpc_cmp_tag_nolock(xtlst, tgid);
	mutex_exit(&xtlst->rxtl_lock);
	return (ret);
}

/*
 * requires the rxtl_lock to be held
 */

static int
rpc_cmp_tag_nolock(rpc_xprt_taglist_t *xtlst, void *tgid)
{
	rpc_xprt_tag_t *xptag;

	/*
	 * If another thread is destroying xptags, wait
	 * till it finishes.
	 */
	if (xtlst->rxtl_flags & RPC_XP_TGL_DESTROY) {
		cv_wait(&xtlst->rxtl_cv, &xtlst->rxtl_lock);
	}

	xptag = list_head(&xtlst->rxtl_list);
	while (xptag) {
		if (bcmp(tgid, xptag->rxt_tag->rt_id, sizeof (tagid)) == 0) {
			return (TRUE);
		}
		xptag = list_next(&xtlst->rxtl_list, xptag);
	}
	return (FALSE);
}

/*
 * Given a tagid, add a tag. Adds xprt to the tag's xprt list
 * and tag to the xprt's tag list.
 */

void
rpc_add_tag(rpc_tag_hd_t *taghd, void *xprt, void *tgid)
{
	rpc_xprt_taglist_t *xtlst;
	rpc_xprt_tag_t *xptag;
	rpc_tag_t *tag;
	rpc_tag_xprt_t *rtxp;

	/*
	 * rpc_lookup_tag() allocates a new tag if none present
	 * for the tagid or adds a reference to the tag if already
	 * allocated.
	 */

	tag = rpc_lookup_tag(taghd, tgid, TRUE);


	xtlst = *(XPRT2TLST(xprt, taghd->rth_xpoff));

	mutex_enter(&xtlst->rxtl_lock);

	/*
	 * Verify that the tag is not already on the list
	 */

	if (rpc_cmp_tag_nolock(xtlst, tgid)) {
		mutex_exit(&xtlst->rxtl_lock);
		return;
	}

	xptag = kmem_zalloc(sizeof (rpc_xprt_tag_t), KM_SLEEP);
	xptag->rxt_tag = tag;

	/*
	 * add into the xprt's tag list
	 */
	list_insert_tail(&xtlst->rxtl_list, xptag);
	mutex_exit(&xtlst->rxtl_lock);

	/*
	 * next add the xprt to the tags conn list
	 */
	rtxp = kmem_zalloc(sizeof (rpc_tag_xprt_t), KM_SLEEP);
	rtxp->rtx_xprt = xprt;
	mutex_enter(&tag->rt_lock);
	list_insert_tail(&tag->rt_xplist, rtxp);
	mutex_exit(&tag->rt_lock);
}

/*
 * Given an xprt remove a particular tag.
 */

void
rpc_remove_tag(rpc_tag_hd_t *tghd, void *xprt, void *tgid)
{
	rpc_xprt_tag_t *xptag;
	rpc_xprt_taglist_t *xtlst;

	/*
	 * we really need a tagid
	 */
	if (tgid == NULL)
		return;

	xtlst = *(XPRT2TLST(xprt, tghd->rth_xpoff));

	mutex_enter(&xtlst->rxtl_lock);

	/*
	 * If another thread is destroying xptags, wait
	 * till it finishes.
	 */
	if (xtlst->rxtl_flags & RPC_XP_TGL_DESTROY) {
		cv_wait(&xtlst->rxtl_cv, &xtlst->rxtl_lock);
	}

	xptag = list_head(&xtlst->rxtl_list);

	while (xptag) {
		/*
		 * if different tagid, skip it.
		 */
		if (bcmp(xptag->rxt_tag->rt_id, tgid, sizeof (tagid)) != 0) {
			xptag = list_next(&xtlst->rxtl_list, xptag);
			continue;
		}

		list_remove(&xtlst->rxtl_list, xptag);

		kmem_free(xptag, sizeof (rpc_xprt_tag_t));

		break;
	}

	mutex_exit(&xtlst->rxtl_lock);

}

/*
 * Given an xprt remove all tags and for each tag, remove the xprt
 * from the tag's xprt list as well.
 */

void
rpc_remove_all_tag(rpc_tag_hd_t *tghd, void *xprt)
{
	rpc_xprt_tag_t *xptag;
	rpc_xprt_taglist_t *xtlst;
	rpc_tag_t *tag;

	xtlst = *(XPRT2TLST(xprt, tghd->rth_xpoff));

	mutex_enter(&xtlst->rxtl_lock);
	xtlst->rxtl_flags |= RPC_XP_TGL_DESTROY;
	xptag = list_head(&xtlst->rxtl_list);

	while (xptag) {
		list_remove(&xtlst->rxtl_list, xptag);
		mutex_exit(&xtlst->rxtl_lock);

		tag = xptag->rxt_tag;
		/*
		 * While we have the tag, remove the xprt
		 * from the tags conn list
		 */
		mutex_enter(&tag->rt_lock);
		rpc_remove_xprt(tghd, tag, xprt);
		mutex_exit(&tag->rt_lock);

		kmem_free(xptag, sizeof (rpc_xprt_tag_t));

		mutex_enter(&xtlst->rxtl_lock);

		/* continue removing the tags */

		xptag = list_head(&xtlst->rxtl_list);
	}

	xtlst->rxtl_flags &= ~RPC_XP_TGL_DESTROY;
	cv_signal(&xtlst->rxtl_cv);
	mutex_exit(&xtlst->rxtl_lock);
}

/*
 * Return true if xprt's tag list is empty
 */

int
rpc_is_taglist_empty(void *xlst)
{
	int ret;
	rpc_xprt_taglist_t *xtlst;

	xtlst = (rpc_xprt_taglist_t *)xlst;
	mutex_enter(&xtlst->rxtl_lock);
	ret = list_is_empty(&xtlst->rxtl_list);
	mutex_exit(&xtlst->rxtl_lock);
	return (ret);
}


/*
 * Given a tag and xprt, remove the xprt from the
 * tag. Callers must hold tag->rt_lock.
 */
/* ARGSUSED */
void
rpc_remove_xprt(rpc_tag_hd_t *taghd, rpc_tag_t *tag, void *xprt)
{
	rpc_tag_xprt_t *rtxp;

	ASSERT(MUTEX_HELD(&tag->rt_lock));

	rtxp = list_head(&tag->rt_xplist);
	ASSERT(rtxp != NULL);

	while (rtxp) {
		if (rtxp->rtx_xprt == xprt) {
			list_remove(&tag->rt_xplist, rtxp);
			kmem_free(rtxp, sizeof (rpc_tag_xprt_t));
			RPC_TAG_RELE_LOCKED(tag);
			break;
		}
		rtxp = list_next(&tag->rt_xplist, rtxp);
	}
}

/*
 * Given a tag remove all xprt from the tag, and for each xprt
 * remove the tag from the xprt's tag list. Callers must hold tag->rt_lock.
 */
void
rpc_remove_all_xprt(rpc_tag_hd_t *taghd, rpc_tag_t *tag)
{
	rpc_tag_xprt_t *rtxp;

	ASSERT(MUTEX_HELD(&tag->rt_lock));

	rtxp = list_head(&tag->rt_xplist);
	ASSERT(rtxp != NULL);

	while (rtxp) {
		list_remove(&tag->rt_xplist, rtxp);
		rpc_remove_tag(taghd, rtxp->rtx_xprt, tag->rt_id);
		kmem_free(rtxp, sizeof (rpc_tag_xprt_t));
		RPC_TAG_RELE_LOCKED(tag);
		rtxp = list_head(&tag->rt_xplist);
	}
}

/*
 * Function to swap tag values
 */

int
rpc_tag_swap(rpc_tag_hd_t *taghd, void *oldtag, void *newtag)
{
	rpc_tag_t *tag;

	tag = rpc_lookup_tag(taghd, oldtag, FALSE);

	if (tag == NULL)
		return (FALSE);

	mutex_enter(&tag->rt_lock);
	bcopy(newtag, tag->rt_id, sizeof (tagid));
	RPC_TAG_RELE_LOCKED(tag);
	mutex_exit(&tag->rt_lock);

	return (TRUE);
}

/*
 * Given a tagid, remove all connections associated with it
 * and destroy it.
 */

void
rpc_destroy_tag(rpc_tag_hd_t *taghd, void *tgid)
{
	rpc_tag_t *tag;

	tag = rpc_lookup_tag(taghd, tgid, FALSE);

	if (tag == NULL)
		return;

	mutex_enter(&tag->rt_lock);

	/*
	 * Another thread already in destroy.
	 */
	if (tag->rt_flags & RPC_TAG_DESTROY) {
		RPC_TAG_RELE_LOCKED(tag);
		mutex_exit(&tag->rt_lock);
		return;
	}
	tag->rt_flags |= RPC_TAG_DESTROY;
	mutex_exit(&tag->rt_lock);

	/*
	 * First remove from the global tag list
	 */
	mutex_enter(&taghd->rth_lock);
	list_remove(&taghd->rth_list, tag);
	mutex_exit(&taghd->rth_lock);

	/*
	 * Next remove any connections associated with this tag.
	 */
	mutex_enter(&tag->rt_lock);

	/*
	 * Release the refcnt acquired by rpc_lookup_tag()
	 */
	RPC_TAG_RELE_LOCKED(tag);

tryagain:
	/*
	 * Iterate through all the connections in this tag,
	 * dis-associating the tag from the xprt and xprt from
	 * the tag.
	 */

	rpc_remove_all_xprt(taghd, tag);

	/*
	 * Someone else has snuck in before we removed from
	 * the global tag list, wait till they finish and try
	 * again.
	 */
	if (tag->rt_ref > 1) {
		cv_wait(&tag->rt_cv, &tag->rt_lock);
		goto tryagain;
	}

	mutex_exit(&tag->rt_lock);
	mutex_destroy(&tag->rt_lock);
	cv_destroy(&tag->rt_cv);
	ASSERT(list_is_empty(&tag->rt_xplist));
	list_destroy(&tag->rt_xplist);
	kmem_free(tag, sizeof (rpc_tag_t));

}
