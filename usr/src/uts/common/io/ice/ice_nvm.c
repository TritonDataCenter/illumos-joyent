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
 * Copyright 2019, Joyent, Inc.
 */

/*
 * NVM related functions. At the moment this only has routines that deal with
 * reading and initializing the NVM, it doesn't do anything with writing to it.
 */

#include "ice.h"

/*
 * XXX Not concurrency safe
 */
boolean_t
ice_nvm_read_uint16(ice_t *ice, uint16_t offset, uint16_t *datap)
{
	boolean_t ret;
	uint16_t len = 2;
	uint16_t data;

	if ((ice->ice_nvm.in_flags & ICE_NVM_PRESENT) == 0 ||
	    (ice->ice_nvm.in_flags & ICE_NVM_BLANK) != 0) {
		ice_error(ice, "invalid NVM flags present, can't read NVM");
		return (B_FALSE);
	}

	if (!ice_cmd_acquire_nvm(ice, B_FALSE)) {
		ice_error(ice, "failed to acquire NVM");
		return (B_FALSE);
	}

	ret = ice_cmd_nvm_read(ice, ICE_NVM_MODULE_TYPE_MEMORY, offset * 2,
	    &len, &data, B_TRUE);
	(void) ice_cmd_release_nvm(ice);
	if (ret) {
		*datap = LE_16(data);
	}
	return (ret);
}

/*
 * Attempt to read the PBA string from the NVM.
 */
boolean_t
ice_nvm_read_pba(ice_t *ice)
{
	boolean_t ret;
	uint16_t pba_len, len;
	void *buf;

	if ((ice->ice_nvm.in_flags & ICE_NVM_PRESENT) == 0 ||
	    (ice->ice_nvm.in_flags & ICE_NVM_BLANK) != 0) {
		ice_error(ice, "invalid NVM flags present, can't read NVM");
		return (B_FALSE);
	}

	if (!ice_cmd_acquire_nvm(ice, B_FALSE)) {
		ice_error(ice, "failed to acquire NVM");
		return (B_FALSE);
	}

	len = 2;
	ret = ice_cmd_nvm_read(ice, ICE_NVM_MODULE_TYPE_PBA, 0, &len, &pba_len,
	    B_FALSE);
	if (ret || len != 2 || pba_len == 0) {
		ret = B_FALSE;
		goto out;
	}

	pba_len--;
	buf = kmem_zalloc(pba_len * 2 + 1, KM_SLEEP);
	len = pba_len * 2;
	ret = ice_cmd_nvm_read(ice, ICE_NVM_MODULE_TYPE_PBA, 2, &len, buf,
	    B_TRUE);
	if (ret || len != pba_len * 2) {
		kmem_free(buf, pba_len * 2 + 1);
		ret = B_FALSE;
		goto out;
	}

	ice->ice_pba_len = pba_len * 2 + 1;
	ice->ice_pba = buf;

out:
	(void) ice_cmd_release_nvm(ice);
	return (ret);
}

void
ice_nvm_fini(ice_t *ice)
{
	ice_nvm_t *nvm = &ice->ice_nvm;
	mutex_destroy(&nvm->in_lock);
}

boolean_t
ice_nvm_init(ice_t *ice)
{
	uint32_t reg;
	uint16_t high, low;
	ice_nvm_t *nvm = &ice->ice_nvm;
	ice_fw_info_t *ifi = &ice->ice_fwinfo;

	mutex_init(&nvm->in_lock, NULL, MUTEX_DRIVER, NULL);

	/*
	 * NVM's missing. I guess not much more to do then.
	 */
	reg = ice_reg_read(ice, ICE_REG_GLNVM_GENS);
	if ((reg & ICE_REG_GLNVM_GENS_NVM_PRES) == 0) {
		return (B_TRUE);
	}
	nvm->in_flags |= ICE_NVM_PRESENT;

	nvm->in_sector = ICE_NVM_SECTOR_SIZE;
	nvm->in_size = (1 << ICE_REG_GLNVM_GENS_SR_SIZE(reg)) * 1024;
	reg = ice_reg_read(ice, ICE_REG_GLNVM_FLA);
	if (ICE_REG_GLNVM_FLA_LOCKED(reg) == 0) {
		nvm->in_flags |= ICE_NVM_BLANK;
	}

	if (!ice_nvm_read_uint16(ice, ICE_NVM_DEV_STARTER_VER,
	    &ifi->ifi_nvm_dev_start)) {
		ice_error(ice, "failed to read NVM Starter version");
		goto err;
	}

	if (!ice_nvm_read_uint16(ice, ICE_NVM_MAP_VERSION,
	    &ifi->ifi_nvm_map_ver)) {
		ice_error(ice, "failed to read NVM map version");
		goto err;
	}

	if (!ice_nvm_read_uint16(ice, ICE_NVM_IMAGE_VERSION,
	    &ifi->ifi_nvm_img_ver)) {
		ice_error(ice, "failed to read NVM image version");
		goto err;
	}

	if (!ice_nvm_read_uint16(ice, ICE_NVM_STRUCTURE_VERSION,
	    &ifi->ifi_nvm_struct_ver)) {
		ice_error(ice, "failed to read NVM structure version");
		goto err;
	}

	if (!ice_nvm_read_uint16(ice, ICE_NVM_EETRACK_1, &low)) {
		ice_error(ice, "failed to read NVM structure version");
		goto err;
	}

	if (!ice_nvm_read_uint16(ice, ICE_NVM_EETRACK_2, &high)) {
		ice_error(ice, "failed to read NVM structure version");
		goto err;
	}
	ifi->ifi_nvm_eetrack = (high << 16) | low;

	if (!ice_nvm_read_uint16(ice, ICE_NVM_EETRACK_1, &low)) {
		ice_error(ice, "failed to read NVM structure version");
		goto err;
	}

	if (!ice_nvm_read_uint16(ice, ICE_NVM_EETRACK_2, &high)) {
		ice_error(ice, "failed to read NVM structure version");
		goto err;
	}
	ifi->ifi_nvm_eetrack_orig = (high << 16) | low;

	return (B_TRUE);

err:
	ice_nvm_fini(ice);
	return (B_FALSE);
}
