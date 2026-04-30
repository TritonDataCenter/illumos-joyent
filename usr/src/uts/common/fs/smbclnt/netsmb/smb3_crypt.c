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
 * Copyright 2019 Nexenta Systems, Inc.  All rights reserved.
 * Copyright 2022-2025 RackTop Systems, Inc.
 */

/*
 * Support for SMB3 encryption (message privacy)
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/conf.h>
#include <sys/proc.h>
#include <sys/fcntl.h>
#include <sys/socket.h>
#include <sys/kmem.h>
#include <sys/errno.h>
#include <sys/cmn_err.h>
#include <sys/random.h>
#include <sys/stream.h>
#include <sys/strsun.h>
#include <sys/sysmacros.h>

#include <netsmb/smb_osdep.h>
#include <netsmb/smb2.h>
#include <netsmb/smb_conn.h>
#include <netsmb/smb_subr.h>
#include <netsmb/smb_dev.h>
#include <netsmb/smb_rq.h>

#include <netsmb/nsmb_kcrypt.h>

#define	SMB3_TFORM_HDR_SIZE	52
#define	SMB3_NONCE_OFFS		20
#define	SMB3_SIG_OFFS		4

static const uint8_t SMB3_CRYPT_SIG[4] = { 0xFD, 'S', 'M', 'B' };

/*
 * Initialize crypto mechanisms we'll need.
 * Called after negotiate.
 */
int
nsmb_crypt_init_mech(struct smb_vc *vcp)
{
	smb_crypto_mech_t *mech;
	int rc;

	mech = &vcp->vc3_crypt_mech;

	switch (vcp->vc3_enc_cipherid) {
	case SMB3_CIPHER_AES256_GCM:
	case SMB3_CIPHER_AES128_GCM:
		rc = nsmb_aes_gcm_getmech(mech);
		break;
	case SMB3_CIPHER_AES256_CCM:
	case SMB3_CIPHER_AES128_CCM:
		rc = nsmb_aes_ccm_getmech(mech);
		break;
	default:
		rc = -1;
		break;
	};

	return (rc);
}

void
nsmb_crypt_fini_mech(struct smb_vc *vcp)
{
	smb_crypto_mech_t *mech;

	mech = &vcp->vc3_crypt_mech;

	/* in case there's any key material in the mech */
	bzero(mech, sizeof (*mech));
}

/*
 * Initialize keys for encryption
 * Called after session setup.
 */
void
nsmb_crypt_init_keys(struct smb_vc *vcp)
{
	uint32_t derived_keylen, input_keylen;

	/*
	 * If we don't have a session key, we'll fail later when a
	 * request that requires (en/de)cryption can't be (en/de)crypted.
	 * Also bail out if negotiate dropped encryption.
	 */
	if ((vcp->vc_sopt.sv2_capabilities & SMB2_CAP_ENCRYPTION) == 0 ||
	    vcp->vc_ssnkeylen <= 0)
		return;

	/*
	 * For SMB3, the encrypt/decrypt keys are derived from
	 * the session key using KDF in counter mode.
	 *
	 * AES256 keys are derived from the 'FullSessionKey', which is the
	 * entirety of what we got from authentication (in vcp->vc_ssnkey).
	 * AES128 keys are derived from the 'SessionKey', which is the
	 * first 16 bytes of the 'FullSessionKey' (MS terminology).
	 */
	if (SMB_DIALECT(vcp) >= SMB2_DIALECT_0311) {
		if (vcp->vc3_enc_cipherid == SMB3_CIPHER_AES256_GCM ||
		    vcp->vc3_enc_cipherid == SMB3_CIPHER_AES256_CCM) {
			derived_keylen = AES256_KEY_LENGTH;
			input_keylen = vcp->vc_ssnkeylen;
		} else {
			derived_keylen = AES128_KEY_LENGTH;
			input_keylen = MIN(SMB2_KEYLEN, vcp->vc_ssnkeylen);
		}

		if (nsmb_kdf(vcp->vc3_encrypt_key, derived_keylen,
		    vcp->vc_ssnkey, input_keylen,
		    (uint8_t *)"SMBC2SCipherKey", 16,
		    vcp->vc3_preauth_hashval, SHA512_DIGEST_LENGTH) != 0)
			return;

		if (nsmb_kdf(vcp->vc3_decrypt_key, derived_keylen,
		    vcp->vc_ssnkey, input_keylen,
		    (uint8_t *)"SMBS2CCipherKey", 16,
		    vcp->vc3_preauth_hashval, SHA512_DIGEST_LENGTH) != 0)
			return;

		vcp->vc3_encrypt_key_len = derived_keylen;
		vcp->vc3_decrypt_key_len = derived_keylen;
	} else {
		derived_keylen = AES128_KEY_LENGTH;
		input_keylen = MIN(SMB2_KEYLEN, vcp->vc_ssnkeylen);

		if (nsmb_kdf(vcp->vc3_encrypt_key, derived_keylen,
		    vcp->vc_ssnkey, input_keylen,
		    (uint8_t *)"SMB2AESCCM", 11,
		    (uint8_t *)"ServerIn ", 10) != 0)
			return;

		if (nsmb_kdf(vcp->vc3_decrypt_key, derived_keylen,
		    vcp->vc_ssnkey, input_keylen,
		    (uint8_t *)"SMB2AESCCM", 11,
		    (uint8_t *)"ServerOut", 10) != 0)
			return;

		vcp->vc3_encrypt_key_len = derived_keylen;
		vcp->vc3_decrypt_key_len = derived_keylen;
	}


	(void) random_get_pseudo_bytes(
	    (uint8_t *)&vcp->vc3_nonce_low,
	    sizeof (vcp->vc3_nonce_low));
	(void) random_get_pseudo_bytes(
	    (uint8_t *)&vcp->vc3_nonce_high,
	    sizeof (vcp->vc3_nonce_high));
}

/*
 * Encrypt the message in *mpp, in place, prepending the
 * SMB3 transform header.
 *
 * Any non-zero return is an error (values not used).
 */
int
smb3_msg_encrypt(struct smb_vc *vcp, mblk_t **mpp)
{
	smb_enc_ctx_t ctx;
	mblk_t *body, *thdr, *lastm;
	struct mbchain	mbp_store;
	struct mbchain *mbp = &mbp_store;
	uint32_t bodylen;
	uint8_t *authdata;
	size_t authlen;
	boolean_t gcm = B_FALSE;
	int rc;

	ASSERT(RW_WRITE_HELD(&vcp->iod_rqlock));

	if ((vcp->vc_sopt.sv2_capabilities & SMB2_CAP_ENCRYPTION) == 0 ||
	    vcp->vc3_encrypt_key_len < SMB2_KEYLEN) {
		return (ENOTSUP);
	}

	if (vcp->vc3_enc_cipherid == SMB3_CIPHER_AES256_GCM ||
	    vcp->vc3_enc_cipherid == SMB3_CIPHER_AES128_GCM)
		gcm = B_TRUE;

	bzero(&ctx, sizeof (ctx));
	ctx.mech = vcp->vc3_crypt_mech; /* struct copy */

	body = *mpp;
	bodylen = msgdsize(body);

	/*
	 * Get a new "nonce".  Access to these counters is
	 * serialized by iod_rqlock (assert above).
	 */
	vcp->vc3_nonce_low++;
	if (vcp->vc3_nonce_low == 0) {
		vcp->vc3_nonce_low++;
		vcp->vc3_nonce_high++;
	}

	/*
	 * Build the transform header, keeping pointers to the various
	 * parts of it that we'll need to refer to later.
	 */
	(void) mb_init(mbp);
	thdr = mbp->mb_top;
	ASSERT(MBLKTAIL(thdr) >= SMB3_TFORM_HDR_SIZE);
	mb_put_mem(mbp, SMB3_CRYPT_SIG, 4, MB_MSYSTEM);
	mb_put_mem(mbp, NULL, SMB2_SIG_SIZE, MB_MZERO);	// signature (later)
	mb_put_uint64le(mbp, vcp->vc3_nonce_low);
	mb_put_uint64le(mbp, vcp->vc3_nonce_high);
	/* Zero last 5 bytes of nonce per. spec. */
	bzero(thdr->b_wptr - 5, 5);
	mb_put_uint32le(mbp, bodylen);
	mb_put_uint16le(mbp, 0);	// reserved
	mb_put_uint16le(mbp, 1);	// flags
	mb_put_uint64le(mbp, vcp->vc2_session_id);
	mbp->mb_top = NULL; // keeping thdr
	mb_done(mbp);

	/*
	 * Need pointers to the part of the transfor header
	 * after the signature (starting with the nonce).
	 */
	authdata = thdr->b_rptr + SMB3_NONCE_OFFS;
	authlen = SMB3_TFORM_HDR_SIZE - SMB3_NONCE_OFFS;

	if (gcm)
		nsmb_crypto_init_gcm_param(&ctx,
		    authdata, SMB2_SIG_SIZE,
		    authdata, authlen);
	else
		nsmb_crypto_init_ccm_param(&ctx,
		    authdata, SMB2_SIG_SIZE,
		    authdata, authlen, bodylen);

	rc = nsmb_encrypt_init(&ctx,
	    vcp->vc3_encrypt_key, vcp->vc3_encrypt_key_len);
	if (rc != 0)
		goto errout;

	/*
	 * Temporarily append the transform header onto the
	 * body mblk chain with its r/w pointers set to cover
	 * just the signature, needed for how encrypt works.
	 * Could just use linkb() but we need to unlink the
	 * block as well so just find the tail ourselves.
	 */
	ASSERT(MBLKL(thdr) == SMB3_TFORM_HDR_SIZE);
	thdr->b_rptr += SMB3_SIG_OFFS;
	thdr->b_wptr = thdr->b_rptr + SMB2_SIG_SIZE;
	lastm = body;
	while (lastm->b_cont != NULL)
		lastm = lastm->b_cont;
	lastm->b_cont = thdr;

	/*
	 * The mblk chain is ready. Encrypt!
	 */
	rc = nsmb_encrypt_mblks(&ctx, body, bodylen);
	/* check rc below */

	/* Unlink thdr and restore r/w pointers. */
	lastm->b_cont = NULL;
	thdr->b_rptr -= SMB3_SIG_OFFS;
	thdr->b_wptr = thdr->b_rptr + SMB3_TFORM_HDR_SIZE;

	/* Now check rc from encrypt */
	if (rc != 0)
		goto errout;

	/*
	 * Lastly, prepend the transform header.
	 */
	thdr->b_cont = body;
	*mpp = thdr;
	nsmb_enc_ctx_done(&ctx);
	return (0);

errout:
	freeb(thdr);
	nsmb_enc_ctx_done(&ctx);
	return (rc);
}

/*
 * Decrypt the message in *mpp, in place, removing the
 * SMB3 transform header.
 *
 * Any non-zero return is an error (values not used).
 */
int
smb3_msg_decrypt(struct smb_vc *vcp, mblk_t **mpp)
{
	smb_enc_ctx_t ctx;
	uint8_t th_sig[4];
	mblk_t *body, *thdr, *lastm;
	struct mdchain	mdp_store;
	struct mdchain *mdp = &mdp_store;
	uint64_t th_ssnid;
	uint32_t bodylen, tlen;
	uint16_t th_flags;
	uint8_t *authdata;
	size_t authlen;
	boolean_t gcm = B_FALSE;
	int rc;

	if ((vcp->vc_sopt.sv2_capabilities & SMB2_CAP_ENCRYPTION) == 0 ||
	    vcp->vc3_decrypt_key_len < SMB2_KEYLEN) {
		return (ENOTSUP);
	}

	if (vcp->vc3_enc_cipherid == SMB3_CIPHER_AES256_GCM ||
	    vcp->vc3_enc_cipherid == SMB3_CIPHER_AES128_GCM)
		gcm = B_TRUE;

	bzero(&ctx, sizeof (ctx));
	ctx.mech = vcp->vc3_crypt_mech; /* struct copy */

	/*
	 * Split off the transform header
	 * We need it contiguous.
	 */
	thdr = *mpp;
	body = m_split(thdr, SMB3_TFORM_HDR_SIZE, 1);
	if (body == NULL)
		return (ENOSR);
	thdr = m_pullup(thdr, SMB3_TFORM_HDR_SIZE);
	if (thdr == NULL)
		return (ENOSR);

	/*
	 * Decode the transform header
	 */
	(void) md_initm(mdp, thdr);
	md_get_mem(mdp, th_sig, 4, MB_MSYSTEM);
	md_get_mem(mdp, NULL, SMB2_SIG_SIZE, MB_MZERO); // signature
	md_get_mem(mdp, NULL, SMB2_SIG_SIZE, MB_MZERO); // nonce
	md_get_uint32le(mdp, &bodylen);
	md_get_uint16le(mdp, NULL);	// reserved
	md_get_uint16le(mdp, &th_flags);
	md_get_uint64le(mdp, &th_ssnid);
	mdp->md_top = NULL; // keeping thdr
	md_done(mdp);

	/*
	 * Validate transform header fields
	 */
	if (bcmp(th_sig, SMB3_CRYPT_SIG, 4) != 0) {
		rc = EPROTO;
		goto errout;
	}
	if (th_flags != 1 || th_ssnid != vcp->vc2_session_id) {
		rc = EINVAL;
		goto errout;
	}

	/*
	 * Check actual body length (trim if necessary)
	 */
	tlen = msgdsize(body);
	if (tlen < bodylen) {
		rc = EINVAL;
		goto errout;
	}
	if (tlen > bodylen) {
		/* trim from tail */
		ssize_t adj;

		adj = bodylen - tlen;
		ASSERT(adj < 0);
		(void) adjmsg(body, adj);
	}

	/*
	 * Need pointers to the part of the transfor header
	 * after the signature (starting with the nonce).
	 * tlen is now length of ciphertext
	 */
	authdata = thdr->b_rptr + SMB3_NONCE_OFFS;
	authlen = SMB3_TFORM_HDR_SIZE - SMB3_NONCE_OFFS;
	tlen = bodylen + SMB2_SIG_SIZE;

	if (gcm)
		nsmb_crypto_init_gcm_param(&ctx,
		    authdata, SMB2_SIG_SIZE,
		    authdata, authlen);
	else
		nsmb_crypto_init_ccm_param(&ctx,
		    authdata, SMB2_SIG_SIZE,
		    authdata, authlen, tlen);

	rc = nsmb_decrypt_init(&ctx,
	    vcp->vc3_decrypt_key, vcp->vc3_decrypt_key_len);
	if (rc != 0)
		goto errout;

	/*
	 * Temporarily append the transform header onto the
	 * body mblk chain with its r/w pointers set to cover
	 * just the signature, needed for how decrypt works.
	 * Could just use linkb() but we need to unlink the
	 * block as well so just find the tail ourselves.
	 */
	thdr->b_rptr += SMB3_SIG_OFFS;
	thdr->b_wptr = thdr->b_rptr + SMB2_SIG_SIZE;
	lastm = body;
	while (lastm->b_cont != NULL)
		lastm = lastm->b_cont;
	lastm->b_cont = thdr;

	/*
	 * The mblk chain is ready. Decrypt!
	 */
	rc = nsmb_decrypt_mblks(&ctx, body, tlen);
	/* check rc below */

	/* Unlink thdr and restore r/w pointers. */
	lastm->b_cont = NULL;
	thdr->b_rptr -= SMB3_SIG_OFFS;
	thdr->b_wptr = thdr->b_rptr + SMB3_TFORM_HDR_SIZE;

	/* Now check rc from decrypt */
	if (rc != 0)
		goto errout;

	/*
	 * Lastly, discard the transform header
	 * and return the body.
	 */
	freeb(thdr);
	*mpp = body;
	nsmb_enc_ctx_done(&ctx);
	return (0);

errout:
	freeb(thdr);
	nsmb_enc_ctx_done(&ctx);
	return (rc);
}
