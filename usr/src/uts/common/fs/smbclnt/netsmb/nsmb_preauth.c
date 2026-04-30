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
 * Copyright 2021-2025 RackTop Systems, Inc.
 */

#include <sys/types.h>

#include <netsmb/smb_conn.h>
#include <netsmb/nsmb_kcrypt.h>

#include <netsmb/mchain.h>

/*
 * SMB 3.1.1 Preauth Integrity
 */

/*
 * (called from smb2_negotiate_common)
 */
int
nsmb_preauth_init(smb_vc_t *vcp)
{
	int rc;

	rc = nsmb_sha512_getmech(&vcp->vc3_preauthmech);
	if (rc != 0) {
		return (EAUTH);
	}

	return (rc);
}

/* ARGSUSED */
int
nsmb_preauth_calc(smb_vc_t *vcp, mblk_t *mb,
    uint8_t *in_hashval, uint8_t *out_hashval)
{
	smb_sign_ctx_t ctx = 0;
	int rc;

	if ((rc = nsmb_sha512_init(&ctx, &vcp->vc3_preauthmech)) != 0)
		return (rc);

	/* Digest current hashval */
	rc = nsmb_sha512_update(ctx, in_hashval, SHA512_DIGEST_LENGTH);
	if (rc != 0)
		return (rc);

	while (mb != NULL) {
		size_t len = MBLKL(mb);

		rc = nsmb_sha512_update(ctx, mb->b_rptr, len);
		if (rc != 0)
			return (rc);
		mb = mb->b_cont;
	}

	rc = nsmb_sha512_final(ctx, out_hashval);

	return (rc);
}
