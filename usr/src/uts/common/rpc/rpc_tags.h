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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * rpc_tags.h - tags implementation for rpc
 */

#ifndef	_RPC_TAGS_H
#define	_RPC_TAGS_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * rpc tags
 */

typedef char tagid[16];


#define	RPC_TAG_HOLD_LOCKED(tag)	{			\
	ASSERT(mutex_owned(&(tag)->rt_lock));			\
	(tag)->rt_ref++;					\
	DTRACE_PROBE1(rpc__tag__hold, rpc_tag_t *, tag);	\
}

#define	RPC_TAG_HOLD(tag)	{	\
	rpc_tag_hold(tag);		\
}

#define	RPC_TAG_RELE_LOCKED(tag)	{	\
	rpc_tag_rele_nolock(tag);		\
}

#define	RPC_TAG_RELE(tag)	{	\
	rpc_tag_rele(tag);		\
}

/*
 * Returns 0 if true
 */

#define	RPC_TAG_CMP(tag1, tag2) (bcmp(tag1, tag2, sizeof (tagid)))

/*
 * Return a xprt's tags list
 */

#define	XPRT2TLST(xprt, offset)		\
	((rpc_xprt_taglist_t **)(((char *)xprt) + offset))


/*
 * Global list of tags for a type of xprt.
 * rth_lock to be held for insertion/remove from the list
 * and while updating the tag's refcnt. rth_xpoff is the offset
 * of the pointer to the tags list (of type rpc_xprt_taglist_t)
 * in the xprt.
 */

typedef struct rpc_tag_hd {
	list_t rth_list;
	kmutex_t rth_lock;
	size_t rth_xpoff;
} rpc_tag_hd_t;


typedef struct rpc_tag {
	tagid rt_id;		/* tagid */
	kmutex_t rt_lock;	/* protects tag elements */
				/* must be held before accessing xprt list */
	/*
	 * Private to tags. tags consumers must not
	 * reference the below elements.
	 */
	int rt_flags;		/* synchronization flags */
	uint64_t rt_ref;	/* connections referring to this tag */
				/* taghd lock to be held for update */
	kcondvar_t rt_cv;
	list_node_t rt_next;	/* next on the global list of tags hd */
	list_t rt_xplist;	/* list of connections sharing the same tag */
} rpc_tag_t;


#define	RPC_TAG_DESTROY	0x01

/*
 * tag's container for connection list
 */

typedef struct rpc_tag_xprt {
	list_node_t rtx_xprt_next;
	void *rtx_xprt;	/* pointer to context specific xprt */
} rpc_tag_xprt_t;

/*
 * transport's tags list
 */

typedef struct rpc_xprt_taglist {
	int rxtl_flags;		/* synchronization flags */
	kcondvar_t rxtl_cv;
	kmutex_t rxtl_lock;	/* protects rxtl_list */
	list_t rxtl_list;
} rpc_xprt_taglist_t;

#define	RPC_XP_TGL_DESTROY	0x01

/*
 * transport's container for tags in the tags list
 */
typedef struct rpc_xprt_tag {
	list_node_t rxt_next;
	rpc_tag_t *rxt_tag;
} rpc_xprt_tag_t;

/* global taghd setup and destroy */

extern void rpc_taghd_init(rpc_tag_hd_t *, offset_t);
extern void rpc_taghd_destroy(rpc_tag_hd_t *);

/* functions for tag manipulation */

extern void rpc_add_tag(rpc_tag_hd_t *, void *, void *);
extern rpc_tag_t *rpc_lookup_tag(rpc_tag_hd_t *, void *, int);
extern void rpc_tag_hold(rpc_tag_t *);
extern void rpc_tag_rele(rpc_tag_t *);
extern void rpc_tag_rele_nolock(rpc_tag_t *);
extern int rpc_tag_swap(rpc_tag_hd_t *, void *, void *);
extern void rpc_destroy_tag(rpc_tag_hd_t *, void *);

/* functions to manipulate tags on the xprt's taglist */

extern void rpc_init_taglist(void **);
extern void rpc_destroy_taglist(void **);
extern int rpc_is_taglist_empty(void *);
extern int rpc_cmp_tag(void *, void *);
extern void rpc_remove_tag(rpc_tag_hd_t *, void *, void *);
extern void rpc_remove_all_tag(rpc_tag_hd_t *, void *);

/* functions to manipulate xprts in a tag */

extern void rpc_remove_xprt(rpc_tag_hd_t *, rpc_tag_t *, void *);
extern void rpc_remove_all_xprt(rpc_tag_hd_t *, rpc_tag_t *);
extern void * rpc_get_next_xprt(rpc_tag_t *, void **);

#ifdef __cplusplus
}
#endif


#endif	/* !_RPC_TAGS_H */
