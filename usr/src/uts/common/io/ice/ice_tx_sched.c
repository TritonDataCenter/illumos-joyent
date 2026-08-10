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
 * Copyright 2026 RackTop Systems, Inc.
 */

#include "ice.h"

static uint8_t ice_tx_vsi_layer(ice_t *ice);
static bool ice_tx_sched_add_children(ice_t *, ice_sched_node_t *, uint8_t *,
    uint16_t (*)(ice_sched_node_t *, void *), void *);
static bool ice_tx_sched_prune_defaults(ice_t *, ice_sched_node_t *);

ice_sched_node_t *
ice_tx_sched_find_node(ice_t *ice, ice_sched_node_t *node, uint32_t teid)
{
	ASSERT(MUTEX_HELD(&ice->ice_tx_sched_lock));

	if (node == NULL || teid == ICE_TX_SCHED_TEID_INVALID) {
		return (NULL);
	}

	if (node->isn_teid == teid) {
		return (node);
	}

	for (uint_t i = 0; i < node->isn_nchildren; i++) {
		ice_sched_node_t *child;

		child = ice_tx_sched_find_node(ice, node->isn_children[i],
		    teid);
		if (child != NULL) {
			return (child);
		}
	}

	return (NULL);
}

/*
 * If we support multiple traffic classes, we'll probably want to pass in
 * the TC as well.
 */
ice_sched_node_t *
ice_tx_sched_vsi_node(ice_vsi_t *vsi)
{
	ice_t			*ice = vsi->ivsi_ice;
	ice_sched_node_t	*node = NULL;
	uint8_t			layer;

	layer = ice_tx_vsi_layer(ice);

	mutex_enter(&ice->ice_tx_sched_lock);

	node = ice->ice_tx_sched_root;
	while (node->isn_level != layer) {
		node = node->isn_children[0];
		if (node == NULL) {
			break;
		}
	}

	while (node != NULL) {
		if (node->isn_vsi == vsi->ivsi_id) {
			break;
		}
		node = node->isn_sibling;
	}

	mutex_exit(&ice->ice_tx_sched_lock);

	return (node);
}

static ice_sched_node_t *
ice_tx_sched_txq_parent_impl(ice_t *ice, ice_sched_node_t *node,
    uint8_t parent_layer)
{
	if (node->isn_level == parent_layer) {
		uint_t max;

		max = ice->ice_tx_sched_max_sibs[node->isn_level + 1];
		if (node->isn_nchildren < max) {
			return (node);
		}

		return (NULL);
	}

	ASSERT3U(node->isn_level, <, parent_layer);
	for (uint_t i = 0; i < node->isn_nchildren; i++) {
		ice_sched_node_t *child;

		child = ice_tx_sched_txq_parent_impl(ice, node->isn_children[i],
		    parent_layer);
		if (child != NULL) {
			return (child);
		}
	}

	return (NULL);
}

/*
 * Find a parent node under the VSI node (i.e. one level from the bottom of
 * the tree) that has space to add a leaf node for a TX queue.
 */
ice_sched_node_t *
ice_tx_sched_txq_parent(ice_vsi_t *vsi)
{
	ice_t			*ice = vsi->ivsi_ice;
	ice_sched_node_t	*vsi_node;
	uint8_t			parent_layer;

	vsi_node = ice_tx_sched_vsi_node(vsi);
	ASSERT3P(vsi_node, !=, NULL);

	/*
	 * The very bottom layer (where the TX nodes are added) is
	 * ice_tx_max_layers - 1, so we want the one just above that.
	 */
	parent_layer = ice->ice_tx_max_layers - 2;

	return (ice_tx_sched_txq_parent_impl(ice, vsi_node, parent_layer));
}

bool
ice_parse_tx_sched(ice_t *ice, const uint8_t *buf, size_t buflen,
    uint8_t nbranch)
{
	const ice_hw_tx_branch_t	*br;
	const void			*end;
	bool				ret = false;

	if (nbranch > ICE_SCHED_NODE_MAX_DEPTH) {
		ice_error(ice,
		    "TX scheduler topology depth (%u) exceeds maximum",
		    nbranch);
		return (false);
	}

	end = buf + buflen;

	if (buflen < sizeof (*br)) {
		ice_error(ice, "TX scheduler topology is too small (%zu bytes)",
		    buflen);
		return (false);
	}
	br = (const ice_hw_tx_branch_t *)buf;

	mutex_enter(&ice->ice_tx_sched_lock);

	for (uint_t i = 0; i < nbranch; i++) {
		const ice_hw_tx_sched_elt_t	*el;
		uint16_t nelem;

		nelem = LE_16(br->ihtb_nelt);

		if (nelem > ICE_TX_SCHED_BR_NELT_MAX) {
			ice_error(ice, "default TX scheduler branch %u has "
			    "invalid number of elements (%u)", i, nelem);
			goto done;
		}

		if ((const void *)br > end) {
			ice_error(ice, "default TX scheduler topology is "
			    "truncated on branch %u", i);
			goto done;
		}

		for (uint_t j = 0; j < nelem; j++) {
			ice_sched_node_t		*parent, *node;
			uint32_t			pteid, teid;

			el = &br->ihtb_elts[j];

			if ((const void *)(el + 1) > end) {
				ice_error(ice, "default TX scheduler topology "
				    "is truncated on branch %u element %u",
				    i, j);
				goto done;
			}

			pteid = LE_32(el->ihtse_pteid);
			teid = LE_32(el->ihtse_teid);

			if (pteid == ICE_TX_SCHED_TEID_INVALID &&
			    ice->ice_tx_sched_root != NULL) {
				ice_error(ice, "default TX scheduler node "
				    "TEID 0x%x has invalid parent", pteid);
				goto done;
			}

			if (teid == ICE_TX_SCHED_TEID_INVALID) {
				/*
				 * Not the greatest way to identify the
				 * bad entry, but it's all we have.
				 */
				ice_error(ice, "default TX scheduler node "
				  "on branch %u index %u with parent TEID 0x%x "
				  "has invalid TEID", i, j, pteid);
				goto done;
			}

			if (pteid == teid) {
				ice_error(ice, "default TX scheduler node "
				    "on branch %u index %u has identical "
				    "TEID as its parent (0x%x)", i, j, teid);
				goto done;
			}

			parent = ice_tx_sched_find_node(ice,
			    ice->ice_tx_sched_root, pteid);

			if (parent != NULL &&
			    parent->isn_level == ICE_SCHED_NODE_MAX_DEPTH) {
				ice_error(ice, "default TX scheduler node "
				    "TEID 0x%x depth is the maximum but has "
				    "children", pteid);
				goto done;
			}
			
			if (el->ihtse_eltype == ICE_TX_SCHED_ET_SOFT_SE) {
				ice->ice_tx_sched_entry = j;
			}

			node = ice_tx_sched_alloc_node(ice, parent, teid,
			    el->ihtse_eltype);

			if (node->isn_level + 1 > ice->ice_tx_sched_depth) {
				ice->ice_tx_sched_depth = node->isn_level + 1;
			}
		}

		/*
		 * ice_sched_init_port() in the FreeBSD driver suggests
		 * that each branch always pads to ICE_TX_SCHED_BR_NELT_MAX (9)
		 * entries even if that branch contains fewer entries, so we
		 * use that to advance to the next branch.
		 */
		el = &br->ihtb_elts[ICE_TX_SCHED_BR_NELT_MAX];
		br = (const ice_hw_tx_branch_t *)el;
	}

	/*
	 * The root node as well as certain children are 'fixed'. We
	 * delete any initial children under this since the datasheet
	 * doesn't state that we can rely on anything about them or their
	 * values.
	 *
	 * The datasheet is unfortunately not clear about what is
	 * convention vs. an implicit requirement in how the TX
	 * scheduling tree is structured. While we currently don't utilize
	 * offloading traffic shaping to NICs, TX queue allocation in the
	 * NIC requires an associated TX scheduler node TEID for that
	 * queue, even if we don't require any traffic shaping for that
	 * queue.
	 *
	 * As such, we follow what the FreeBSD driver does in that we
	 * prune the default (power on) tree starting at the nodes we
	 * can modify. We then create a VSI node as the parent for all
	 * TX rings when creating the VSI as well as any necessary
	 * intermediate nodes between the VSI node and the TX queue
	 * nodes. When we start a TX ring, we will allocate the
	 * leaf node and utilize it with the TX queue context.
	 */
	ret = ice_tx_sched_prune_defaults(ice, ice->ice_tx_sched_root);

done:
	mutex_exit(&ice->ice_tx_sched_lock);
	return (ret);
}

static void
ice_tx_sched_init_elt(ice_hw_sched_elem_t *elt)
{
	bzero(elt, sizeof (*elt));

	/*
	 * The FreeBSD driver sets ihse_etype to ICE_AQC_ELEM_TYPE_SE_GENERIC
	 * despite the datasheet stating the field is reserved in the add
	 * scheduling elements command (Table 8-34).
	 *
	 * For now we'll assume that it's ignored and the FreeBSD source is
	 * technically a bug (the per group and element structs are
	 * effectively the same across the query default, add, and query
	 * node commands however some fields are only used some commands
	 * and vice versa).
	 */
	elt->ihse_valid = ICE_TX_SCHED_SECT_GENERIC | ICE_TX_SCHED_SECT_CIR_BW |
	    ICE_TX_SCHED_SECT_EIR_BW;
}

typedef struct add_vsi_args {
	ice_sched_node_t	*ava_node;
	uint8_t			ava_vsi_layer;
} add_vsi_args_t;

static uint16_t
add_vsi_nintermediate(ice_sched_node_t *parent, void *ptr)
{
	add_vsi_args_t *args = ptr;

	/*
	 * We're only adding 1 node per layer until we reach the
	 * VSI layer, so when the parent level is the VSI layer,
	 * it is the VSI node we're adding.
	 */
	if (parent->isn_level == args->ava_vsi_layer) {
		args->ava_node = parent;
		return (0);
	}

	return (1);
}

static uint16_t
add_vsi_children(ice_sched_node_t *parent, void *ptr)
{
	uint16_t *toadd = ptr;

	VERIFY3U(parent->isn_level + 1, <, ICE_SCHED_NODE_MAX_DEPTH);

	return (toadd[parent->isn_level + 1]);
}

/*
 * This creates the VSI TX scheduling node, as well as any
 * intermediate nodes as needed for the given VSI.
 *
 * If we ever support multiple TCs, this should be repeated for each TC.
 */
bool
ice_tx_sched_add_vsi_node(ice_t *ice, ice_vsi_t *vsi)
{
	uint8_t			*buf;
	ice_sched_node_t	*node;
	uint16_t		child_add[ICE_SCHED_NODE_MAX_DEPTH] = { 0 };
	add_vsi_args_t		args = { 0 };
	uint_t			i, per_node;
	bool			ret = false;

	args.ava_vsi_layer = ice_tx_vsi_layer(ice);

	buf = kmem_zalloc(ICE_CQ_MAX_BUF, KM_SLEEP);

	mutex_enter(&ice->ice_tx_sched_lock);

	/*
	 * Since we currently only support TC0, we just descend the
	 * first child until we reach either the bottom of the tree,
	 * or parent of the VSI layer.
	 */
	node = ice->ice_tx_sched_root;
	for (i = 0; i < args.ava_vsi_layer; i++) {
		ASSERT3U(node->isn_level, ==, i);

		if (node->isn_nchildren == 0) {
			break;
		}
		node = node->isn_children[0];
	}

	if (!ice_tx_sched_add_children(ice, node, buf, add_vsi_nintermediate,
	    &args)) {
		goto done;
	}
	
	node = args.ava_node;
	ASSERT3P(node, !=, NULL);

	node->isn_vsi = vsi->ivsi_id;

	/*
	 * Calculate how many nodes per level under the VSI node we
	 * need to add. For now, we distribute all the TX rings equally
	 * amongst the children at each level that's a descendant of the
	 * VSI node. If we add support for dynamically adding/removing TX
	 * rings, or offloding TX flow management to NICs, this will likely
	 * need to become more sophisticated.
	 */
	per_node = vsi->ivsi_ntxq;
	ASSERT3U(per_node, !=, 0);

	for (i = args.ava_vsi_layer + 1; i < ice->ice_tx_max_layers; i++) {
		uint16_t max = ice->ice_tx_sched_max_sibs[i];

		per_node = roundup(per_node, max);
		ASSERT3U(per_node, !=, 0);

		child_add[i] = per_node;
	}

	ret = ice_tx_sched_add_children(ice, node, buf, add_vsi_children,
	    child_add);

done:
	mutex_exit(&ice->ice_tx_sched_lock);

	kmem_free(buf, ICE_CQ_MAX_BUF);
	if (!ret) {
		ice_error(ice, "failed to add VSI TX scheduler nodes");
	}

	return (ret);
}

/*
 * The maximum number of ice_hw_schec_elt_t's that can fit in a
 * ICE_CQ_MAX_BUF sized buffer (including the ice_hw_sched_grp_t header)
 */
#define	ADD_CHILDREN_MAX	127

/*
 * Recursively adds children under the given parent. 'buf' is a
 * ICE_CQ_MAX_BUF sized buffer that's used for building the hw structures
 * required for the controlq. The cb function returns how many children
 * under the given parent to create.
 */
static bool
ice_tx_sched_add_children(ice_t *ice, ice_sched_node_t *parent, uint8_t *buf,
    uint16_t (*cb)(ice_sched_node_t *, void *), void *arg)
{
	ice_hw_sched_grp_t	*group;
	ice_hw_sched_elem_t	*elt;
	uint16_t		ngroup;
	uint16_t		nelem;
	uint16_t		i, n;

	ASSERT(MUTEX_HELD(&ice->ice_tx_sched_lock));

	/*
	 * We currently only add/remove entire subtrees (basically the
	 * VSI node for TC0 and below), we assume as we add there should
	 * not be any existing children. If we add support for dynamically
	 * adding/removing TX rings (or TC or offloading flow management
	 * to the NIC), this should be removed.
	 */
	ASSERT3U(parent->isn_nchildren, ==, 0);

	if (parent->isn_level + 1 >= ICE_SCHED_NODE_MAX_DEPTH - 1) {
		/* We shouldn't go past the last level */
		ASSERT3U(parent->isn_level + 1, ==,
		    ICE_SCHED_NODE_MAX_DEPTH - 1);

		return (true);
	}

	n = cb(parent, arg);

	/*
	 * Since we reuse buf when recursing, we must first all all
	 * of the children for this parent, then recurse into each
	 * child.
	 */
	while (n > 0) {
		nelem = MIN(ADD_CHILDREN_MAX, n);

		bzero(buf, ICE_CQ_MAX_BUF);
		group = (ice_hw_sched_grp_t *)buf;
		ngroup = 1;

		group->ihsg_pteid = LE_32(parent->isn_teid);
		group->ihsg_nelems = LE_16(nelem);
		elt = &group->ihsg_elems[0];

		for (i = 0; i < nelem; i++, elt++) {
			ice_tx_sched_init_elt(elt);
		}

		if (!ice_cmd_add_sched_elements(ice, &ngroup, group)) {
			return (false);
		}

		elt = &group->ihsg_elems[0];
		for (i = 0; i < nelem; i++, elt++) {
			(void) ice_tx_sched_alloc_node(ice, parent,
			    LE_32(elt->ihse_teid), elt->ihse_etype);
		}

		n -= nelem;
	}

	/*
	 * ice_tx_sched_alloc_node() adds the children to the parent, so
	 * we should now have the newly added children to recurse through.
	 */
	for (i = 0; i < parent->isn_nchildren; i++) {
		if (!ice_tx_sched_add_children(ice, parent->isn_children[i],
		    buf, cb, arg)) {
			return (false);
		}
	}

	return (true);
}

static bool
ice_tx_sched_del_elt_impl(ice_t *ice, ice_sched_node_t *node, bool del_from_hw)
{
	ice_sched_node_t		*parent = node->isn_parent;
	uint64_t			buf[4] = { 0 };
	ice_hw_delete_sched_elements_t	*del;
	uint_t				i;
	uint16_t			ngroup;

	/* buf should be large enough to hold 1 group w/ 1 TEID */
	CTASSERT(sizeof (buf) >= sizeof (ice_hw_delete_sched_elements_t) +
	    sizeof (uint32_t));

	/*
	 * The driver cannot delete these nodes. Note that we allow attempts
	 * to delete leaf nodes here so we can delete any post-reset
	 * leaf nodes.
	 */
	ASSERT3S(node->isn_type, !=, ICE_TX_SCHED_ET_ROOT);
	ASSERT3S(node->isn_type, !=, ICE_TX_SCHED_ET_TC);

	/* By implication, any node we're deleting should have a parent */
	ASSERT3P(node->isn_parent, !=, NULL);

	ngroup = 1;

	del = (ice_hw_delete_sched_elements_t *)buf;

	del->ihdse_pteid = LE_32(parent->isn_teid);
	del->ihdse_nelements = LE_16(ngroup);
	del->ihdse_teids[0] = LE_32(node->isn_teid);

	if (del_from_hw || node->isn_type != ICE_TX_SCHED_ET_LEAF) {
		if (!ice_cmd_del_sched_elements(ice, &ngroup, del)) {
			ASSERT3U(ngroup, ==, 0);
			return (false);
		}
	}

	/*
	 * We shouldn't be able to successfully delete a node with
	 * children (we should get EPERM), but our parent should have
	 * at least 1 child (us).
	 */
	ASSERT3U(parent->isn_nchildren, >, 0);
	ASSERT3U(node->isn_nchildren, ==, 0);

	for (i = 0; i < parent->isn_nchildren; i++) {
		if (parent->isn_children[i] != node) {
			continue;
		}

		/*
		 * If the node isn't the first child, we need to remove
		 * the node from the list of siblings.
		 */
		if (i > 0) {
			parent->isn_children[i - 1]->isn_sibling =
			    node->isn_sibling;
		}

		/*
		 * shift all of the children after node over in the
		 * parent's isn_children array.
		 */
		parent->isn_nchildren--;
		(void) memmove(&parent->isn_children[i],
		    &parent->isn_children[i + 1],
		    (parent->isn_nchildren - i) * sizeof (ice_sched_node_t *));
		parent->isn_children[parent->isn_nchildren] = NULL;

		ice_tx_sched_free_nodes(ice, node);
		return (true);
	}

	dev_err(ice->ice_dip, CE_PANIC, "TX schedule node does not exist "
	    "in parent");

	/* keep compilers happy */
	/*NOTREACHED*/
	return (false);
}

bool
ice_tx_sched_del_elt(ice_t *ice, ice_sched_node_t *node, bool del_from_hw)
{
	switch (node->isn_type) {
	case ICE_TX_SCHED_ET_ROOT:
	case ICE_TX_SCHED_ET_TC:
		/* root and tc nodes cannot be deleted by the driver. */
		return (false);
	case ICE_TX_SCHED_ET_LEAF:
		/*
		 * The wording in 8.3.4.3.6.9 is a bit confusing, but
		 * it appears that a leaf node (aside from any initial
		 * leaf nodes after reset) are deleted when the TX ring or
		 * RDMA qset associated with the node is deleted (that is
		 * the TX scheduler node is implicitly deleted when the
		 * associated entity is deleted), so we should only
		 * need to delete our ice_sched_node_t.
		 */
		ASSERT(!del_from_hw);
		break;
	default:
		break;
	}

	return (ice_tx_sched_del_elt_impl(ice, node, del_from_hw));
}

ice_sched_node_t *
ice_tx_sched_alloc_node(ice_t *ice, ice_sched_node_t *parent, uint32_t teid,
    uint8_t type)
{
	ice_sched_node_t	*node;
	size_t			childsz;
	uint8_t			max_children;
	uint8_t			level;

	ASSERT(MUTEX_HELD(&ice->ice_tx_sched_lock));

	ASSERT3P(ice_tx_sched_find_node(ice, ice->ice_tx_sched_root, teid),
	    ==, NULL);

	if (parent != NULL) {
		level = parent->isn_level + 1;
		VERIFY3U(level, <, ice->ice_tx_max_layers);

		/* We should never be adding a node to a full parent */
		max_children =
		    ice->ice_tx_sched_max_sibs[parent->isn_level + 1];
		VERIFY3U(parent->isn_nchildren, <, max_children);
	} else {
		/* Root node */
		level = 0;
	}

	max_children = ice->ice_tx_sched_max_sibs[level + 1];
	childsz = max_children * sizeof (ice_sched_node_t *);
	IMPLY(childsz == 0, type == ICE_TX_SCHED_ET_LEAF);

	node = kmem_zalloc(sizeof (*node), KM_SLEEP);
	node->isn_parent = parent;
	if (childsz > 0) {
		node->isn_children = kmem_zalloc(childsz, KM_SLEEP);
	}
	node->isn_teid = teid;
	node->isn_level = level;
	node->isn_type = type;

	if (parent != NULL) {
		if (parent->isn_nchildren > 0) {
			ice_sched_node_t *sib;

			/* append to the tail of the sibling list */
			sib = parent->isn_children[parent->isn_nchildren - 1];
			sib->isn_sibling = node;
		}

		parent->isn_children[parent->isn_nchildren++] = node;
	} else {
		VERIFY3P(ice->ice_tx_sched_root, ==, NULL);
		ice->ice_tx_sched_root = node;
	}

	return (node);
}

void
ice_tx_sched_free_nodes(ice_t *ice, ice_sched_node_t *node)
{
	size_t	max_kids;
	uint_t	i;

	/*
	 * If we never alloced an array for children, there should
	 * be 0 children, but if we've freed children later,
	 * isn_children might != NULL
	 */
	IMPLY(node->isn_children == NULL, node->isn_nchildren == 0);

	/*
	 * If we're at the deepest level, there should never be any
	 * children.
	 */
	IMPLY(node->isn_level + 1 == ICE_SCHED_NODE_MAX_DEPTH,
	    node->isn_nchildren == 0);

	if (node->isn_level + 1 < ICE_SCHED_NODE_MAX_DEPTH) {
		max_kids = ice->ice_tx_sched_max_sibs[node->isn_level + 1];
	} else {
		max_kids = 0;
	}

	for (i = 0; i < node->isn_nchildren; i++) {
		ice_tx_sched_free_nodes(ice, node->isn_children[i]);
		node->isn_children[i] = NULL;
	}

	if (max_kids > 0) {
		kmem_free(node->isn_children,
		    max_kids * sizeof (ice_sched_node_t *));
	}

	kmem_free(node, sizeof (*node));
}

static bool
ice_tx_sched_prune_defaults(ice_t *ice, ice_sched_node_t *node)
{
	uint_t	i;

	ASSERT(MUTEX_HELD(&ice->ice_tx_sched_lock));

	if (node == NULL) {
		return (true);
	}

	for (i = 0; i < node->isn_nchildren; i++) {
		if (!ice_tx_sched_prune_defaults(ice, node->isn_children[i])) {
			return (false);
		}
	}

	switch (node->isn_type) {
	case ICE_TX_SCHED_ET_ROOT:
	case ICE_TX_SCHED_ET_TC:
		/* We don't touch these */
		return (true);
	default:
		break;
	}

	return (ice_tx_sched_del_elt_impl(ice, node, true));
}

static uint8_t
ice_tx_vsi_layer(ice_t *ice)
{
	switch (ice->ice_tx_max_layers) {
	case 9:
		return (6);
	case 7:
		return (4);
	default:
		return (ice->ice_tx_sched_entry);
	}
}
