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

#include <sys/byteorder.h>
#include <sys/firmload.h>
#include "ice.h"

/*
 * The format of the DDP package file itself. Note that segments can have
 * their own individual format versions, all of which itself is idependent from
 * the version of the package file itself.
 */
#define	ICE_PKG_FMT_VERSION_MAJ		0x01
#define	ICE_PKG_FMT_VERSION_MIN		0x00
#define	ICE_PKG_FMT_VERSION_UPDATE	0x00
#define	ICE_PKG_FMT_VERSION_DRAFT	0x00

/*
 * Section 7.11 of the E810 datasheet holds most of the details of the
 * DDP format, however some of the details appear to only be available
 * via inspection of the FreeBSD driver (specifically
 * src/dev/ice/ice_ddp_common.[ch]).
 */
#define	ICE_SIGN_TYPE_RSA2K		0x00000001
#define	ICE_SIGN_TYPE_RSA3K		0x00000002
#define	ICE_SIGN_TYPE_RSA3K_E825	0x00000005
#define	ICE_SIGN_TYPE_RSA3K_SBB		0x00000003

#define	ICE_PKG_NAME	"ice.pkg"

/*
 * An index entry for a segment in the DDP file. Note that in the segment
 * header in the DDP file, the offset and length include the segment header
 * while the indexed version does not. That is, isi_offset points to the
 * start of the segment contents (after the segment header) and isi_length
 * is the length of the segment excluding the header.
 */
typedef struct ice_seg_idx {
	uint32_t	isi_offset;
	uint32_t	isi_length;
	uint32_t	isi_type;
	ice_pkg_ver_t	isi_version;
} ice_seg_idx_t;

/*
 * Section 7.11.5 of the E810 datasheet documents the format of the
 * package file, the definitions come from there.
 */
typedef struct ice_pkg_hdr {
	ice_pkg_ver_t	iph_version;
	uint32_t	iph_seg_count;
} ice_pkg_hdr_t;
CTASSERT(sizeof (ice_pkg_hdr_t) == 8);

typedef struct ice_pkg_seg_hdr {
	uint32_t	ipsh_type;
	ice_pkg_ver_t	ipsh_version;
	uint32_t	ipsh_size;
	char		ipsh_name[32];
} ice_pkg_seg_hdr_t;
CTASSERT(sizeof (ice_pkg_seg_hdr_t) == 44);

#define	ICE_PKG_SEG_GLOBAL_METADATA	0x0001
#define	ICE_PKG_SEG_NOTES		0x0002
#define	ICE_PKG_SEG_CFG_DATA_E810	0x0010
#define	ICE_PKG_SEG_CFG_DATA_E830	0x0017
#define	ICE_PKG_SEG_SIGNING		0x1001

typedef struct ice_pkg_global_metadata {
	ice_pkg_ver_t	ipgm_version;
	uint8_t		ipgm_reserved[4];
	char		ipgm_name[32];
} ice_pkg_global_metadata_t;
CTASSERT(sizeof (ice_pkg_global_metadata_t) == 40);

typedef struct ice_pkg_sign_hdr {
	uint32_t	ipsh_id;
	uint32_t	ipsh_type;
	uint32_t	ipsh_signed_idx;
	uint32_t	ipsh_sbuf_start;
	uint32_t	ipsh_sbuf_count;
	uint32_t	ipsh_flags;
	uint8_t		ipsh_reserved[40];
} ice_pkg_sign_hdr_t;
CTASSERT(sizeof (ice_pkg_sign_hdr_t) == 64);
#define	ICE_PKG_SIGN_FLAG_VALID		0x80000000
#define	ICE_PKG_SIGN_FLAG_LAST		0x00000001

/*
 * The contents of the signing and config segments contains a number of headers
 * followed by a 4 byte buffer count and then `count` fixed sized buffers
 * of 4096 bytes. The name is unfortunately generic but we're matching
 * what's in 7.11.5 of the datasheet.
 */
#define	ICE_PKG_BUF_LEN			4096
typedef struct ice_pkg_buf_hdr {
	uint16_t	ipbh_size;
	uint16_t	ipbh_data_end;
} ice_pkg_buf_hdr_t;
CTASSERT(sizeof (ice_pkg_buf_hdr_t) == 4);

typedef struct ice_pkg_sect {
	uint32_t	ips_type;
	uint16_t	ips_offset;
	uint16_t	ips_size;
} ice_pkg_sect_t;
CTASSERT(sizeof (ice_pkg_sect_t) == 8);
#define	ICE_PKG_SECT_METADATA	0x80000000

/*
 * We care about two segments from the DDP file -- the configuration segment
 * that corresponds to the specific device and the corresponding signing
 * segment.
 */
typedef struct ice_pkg_data {
	uint32_t	ipd_cfgidx;
	void		*ipd_config;	/* Config segment contents */
	void		*ipd_sign;	/* Signing segment */
	uint32_t	ipd_cfglen;
	uint32_t	ipd_signlen;
} ice_pkg_data_t;

static bool ice_ddp_get_segs(ice_t *, firmware_handle_t, ice_seg_idx_t **,
    uint32_t *);
static bool ice_ddp_get_cfg(ice_t *, firmware_handle_t, ice_seg_idx_t *,
    uint32_t, ice_pkg_data_t *);
static bool ice_ddp_get_metadata(ice_t *, firmware_handle_t, ice_seg_idx_t *,
    uint32_t);
static bool ice_ddp_download_cfg(ice_t *, ice_pkg_data_t *);

static bool ice_ddp_check_id(ice_t *, const uint8_t **, uint32_t *);
static bool ice_ddp_check_nvm(ice_t *, const uint8_t **, uint32_t *);
static bool ice_ddp_download_pkgs(ice_t *, const void *, uint32_t, uint32_t,
    bool);
static void ice_ddp_free_data(ice_pkg_data_t *);

/*
 * NOTES on what needs to be done:
 *
 * issue GET PKG INFO LIST command (0x0c43) to device, find entry stored in NVM
 * compare version with segment version major version must match, segment minor
 * >= NVM version
 *
 */
int
ice_load_ddp(ice_t *ice)
{
	firmware_handle_t	fh;
	int			ret = 0;
	ice_seg_idx_t		*idx;
	ice_pkg_data_t		data = { 0 };
	uint32_t		nidx;

	ret = firmware_open(ICE_MODULE_NAME, "ice.pkg", &fh);
	if (ret != 0) {
		return (ret);
	}

	if (!ice_ddp_get_segs(ice, fh, &idx, &nidx)) {
		ret = EIO;
		goto done;
	}

	if (!ice_ddp_get_metadata(ice, fh, idx, nidx)) {
		ret = EIO;
		goto done;
	}
	
	if (!ice_ddp_get_cfg(ice, fh, idx, nidx, &data)) {
		ret = EIO;
		goto done;
	}

	if (!ice_ddp_download_cfg(ice, &data)) {
		ret = EIO;
	}

done:
	kmem_free(idx, nidx * sizeof (*idx));
	ice_ddp_free_data(&data);
	VERIFY0(firmware_close(fh));
	return (ret);
}

/*
 * Build an index of the segments in the DDP file. On success *idxp
 * contains an array of the indexes while *np contains the number of
 * segments.
 *
 * If successful, the offset and lengths in *idxp have been sanity checked
 * (i.e. they should exist in the DDP file).
 */
static bool
ice_ddp_get_segs(ice_t *ice, firmware_handle_t fh, ice_seg_idx_t **idxp,
    uint32_t *np)
{
	ice_pkg_hdr_t	hdr = { 0 };
	ice_seg_idx_t	*idx = NULL;
	uint32_t	*segs = NULL;
	off_t		pkglen = 0;
	uint32_t	i, n = 0;

	pkglen = firmware_get_size(fh);
	if (pkglen < sizeof (hdr)) {
		ice_error(ice, "DDP package size (%u bytes) is too small",
		    pkglen);
		return (false);
	}

	if (firmware_read(fh, 0, &hdr, sizeof (hdr)) != 0) {
		ice_error(ice, "failed to read DDP package header");
		return (false);
	}

	/*
	 * The components of the version value are 8-bits each, so we don't
	 * need to worry about endianness when checking them.
	 */
	if (hdr.iph_version.ipv_major != ICE_PKG_FMT_VERSION_MAJ ||
	    hdr.iph_version.ipv_minor != ICE_PKG_FMT_VERSION_MIN ||
	    hdr.iph_version.ipv_update != ICE_PKG_FMT_VERSION_UPDATE ||
	    hdr.iph_version.ipv_draft != ICE_PKG_FMT_VERSION_DRAFT) {
		ice_pkg_ver_t *v = &hdr.iph_version;

		ice_error(ice, "unsupported DDP package version %u.%u.%u.%u",
		    v->ipv_major, v->ipv_minor, v->ipv_update, v->ipv_draft);
		return (false);
	}

	n = LE_32(hdr.iph_seg_count);

	if (sizeof (hdr) + n * sizeof (uint32_t) > pkglen) {
		ice_error(ice, "DDP package segment count (%u) overruns "
		    "package size (%u bytes)", n, pkglen);
		return (false);
	}

	/*
	 * After the package header, there is the segment table which is an
	 * array of n 32-bit segment offsets for each section (7.11.5).
	 */
	segs = kmem_zalloc(n * sizeof (uint32_t), KM_SLEEP);
	if (firmware_read(fh, sizeof (hdr), segs, n * sizeof (uint32_t)) != 0) {
		kmem_free(segs, n * sizeof (uint32_t));
		ice_error(ice, "failed to read DDP package segment offsets");
		return (false);
	}	

	/* Sanity check the offsets */
	for (i = 0; i < n; i++) {
		/*
		 * The segment offset is a 32-bit value. Since we're only
		 * adding sizeof (ice_pkg_seg_hdr_t) bytes (44) to it, we
		 * can always safely store it in a 64-bit value without
		 * overflow (so we don't need an explicit overflow check).
		 */
		uint64_t offset = LE_32(segs[i]);

		if (offset + sizeof (ice_pkg_seg_hdr_t) > pkglen) {
			ice_error(ice, "DDP segnebt %u offset (%lu) out of "
			    "range", i, offset);
			kmem_free(segs, n * sizeof (uint32_t));
			return (false);
		}
	}

	/*
	 * After the segment table are all of the segments. Each segment
	 * contains a 44-byte header followed by segement specific data.
	 * We read in each header and fill in the corresponding index entry.
	 */
	idx = kmem_zalloc(n * sizeof (ice_seg_idx_t), KM_SLEEP);
	for (i = 0; i < n; i++) {
		ice_pkg_seg_hdr_t	shdr = { 0 };

		if (firmware_read(fh, LE_32(segs[i]), &shdr,
		    sizeof (shdr)) != 0) {
			ice_error(ice, "failed to read DDP segment %u", i);
			kmem_free(segs, n * sizeof (uint32_t));
			kmem_free(idx, n * sizeof (ice_seg_idx_t));
			return (false);
		}

		/*
		 * Sanity check the segment length. Since both the offset and
		 * length are 32-bits, using a 64-bit int avoids any potential
		 * overflow.
		 */
		if ((uint64_t)LE_32(segs[i]) + LE_32(shdr.ipsh_size) > pkglen) {
			ice_error(ice, "segment %u length (%u bytes at offset "
			    "%u) extends past end of package", i,
			    LE_32(shdr.ipsh_size), LE_32(segs[i]));
			kmem_free(segs, n * sizeof (uint32_t));
			kmem_free(idx, n * sizeof (ice_seg_idx_t));
			return (false);
		}

		/*
		 * Set isi_offset and length to refect the start of the
		 * segment's contents (i.e. exclude ice_pkg_seg_hdr_t).
		 */
		idx[i].isi_offset = LE_32(segs[i]) + sizeof (ice_pkg_seg_hdr_t);
		idx[i].isi_length = LE_32(shdr.ipsh_size)
		    - sizeof (ice_pkg_seg_hdr_t);
		idx[i].isi_type = LE_32(shdr.ipsh_type);
		idx[i].isi_version = shdr.ipsh_version;
	}

	kmem_free(segs, n * sizeof (uint32_t));
	*idxp = idx;
	*np = n;

	return (true);
}

static bool
ice_ddp_get_cfg(ice_t *ice, firmware_handle_t fh, ice_seg_idx_t *idx,
    uint32_t n, ice_pkg_data_t *dp)
{
	uint32_t	i;
	uint32_t	needed_type;

	bzero(dp, sizeof (*dp));

	/*
	 * The datasheet doesn't indicate that the segment types appear in
	 * any specific order, so we must first find the configuration
	 * segment for our NIC type, then check if a signing segment
	 * exists for that segment.
	 */
	switch (ice->ice_mac_type) {
	case ICE_MAC_E810:
	case ICE_MAC_GENERIC:
	case ICE_MAC_GENERIC_3K:
	case ICE_MAC_GENERIC_3K_E825:
	default:
		needed_type = ICE_PKG_SEG_CFG_DATA_E810;
		break;
	case ICE_MAC_E830:
		needed_type = ICE_PKG_SEG_CFG_DATA_E830;
		break;
	}

	for (i = 0; i < n; i++) {
		if (idx[i].isi_type != needed_type) {
			continue;
		}

		dp->ipd_cfgidx = i;
		dp->ipd_config = kmem_zalloc(idx[i].isi_length, KM_SLEEP);
		dp->ipd_cfglen = idx[i].isi_length;

		if (firmware_read(fh, idx[i].isi_offset, dp->ipd_config,
		    idx[i].isi_length) != 0) {
			ice_error(ice, "failed to read DDP configuration "
			    "segment %u", i);
			ice_ddp_free_data(dp);
			return (false);
		}

		break;
	}

	if (dp->ipd_config == NULL) {
		ice_error(ice, "failed to find DDP configuration segment");
		ice_ddp_free_data(dp);
		return (false);
	}

	switch (ice->ice_mac_type) {
	case ICE_MAC_GENERIC_3K:
		needed_type = ICE_SIGN_TYPE_RSA3K;
		break;
	case ICE_MAC_GENERIC_3K_E825:
		needed_type = ICE_SIGN_TYPE_RSA3K_E825;
		break;
	case ICE_MAC_E830:
		needed_type = ICE_SIGN_TYPE_RSA3K_SBB;
		break;
	default:
		needed_type = ICE_SIGN_TYPE_RSA2K;
		break;
	}

	for (i = 0; i < n; i++) {
		void			*buf = NULL;
		ice_pkg_sign_hdr_t	*shdr;

		if (idx[i].isi_type != ICE_PKG_SEG_SIGNING) {
			continue;
		}

		buf = kmem_zalloc(idx[i].isi_length, KM_SLEEP);
		if (firmware_read(fh, idx[i].isi_offset, buf,
		    idx[i].isi_length) != 0) {
			ice_error(ice, "failed to read DDP signing segment %u "
			    "header", i);
			kmem_free(buf, idx[i].isi_length);
			ice_ddp_free_data(dp);
			return (false);
		}

		shdr = buf;
		if (LE_32(shdr->ipsh_signed_idx) != dp->ipd_cfgidx ||
		    LE_32(shdr->ipsh_type) != needed_type) {
			kmem_free(buf, idx[i].isi_length);
			continue;
		}

		dp->ipd_sign = buf;
		dp->ipd_signlen = idx[i].isi_length;
		break;
	}

	return (true);
}

static bool
ice_ddp_get_metadata(ice_t *ice, firmware_handle_t fh, ice_seg_idx_t *idx,
    uint32_t n)
{
	ice_pkg_global_metadata_t	m = { 0 };
	uint_t				i = 0;

	for (i = 0; i < n; i++) {
		if (idx[i].isi_type == ICE_PKG_SEG_GLOBAL_METADATA) {
			break;
		}
	}
	if (i == n) {
		ice_error(ice,
		    "no global metadata segment present in DDP file");
		return (false);
	}

	if (idx[i].isi_length < sizeof (m)) {
		ice_error(ice, "DDP global metadata segment header size "
		    "(%u bytes) is too small", idx[i].isi_length);
		return (false);
	}

	if (firmware_read(fh, idx[i].isi_offset, &m, sizeof (m)) < 0) {
		ice_error(ice, "failed to read DDP global metadata segment");
		return (false);
	}

	ice->ice_pkg_version = m.ipgm_version;

	dev_err(ice->ice_dip, CE_CONT, "?DDP package %s version %u.%u.%u.%u\n",
	    m.ipgm_name, m.ipgm_version.ipv_major, m.ipgm_version.ipv_minor,
	    m.ipgm_version.ipv_update, m.ipgm_version.ipv_draft);

	return (true);
}

static bool
ice_ddp_download_cfg(ice_t *ice, ice_pkg_data_t *dp)
{
	const uint8_t	*p = dp->ipd_config;
	uint32_t	len = dp->ipd_cfglen;
	uint32_t	nbuf = 0;
	uint32_t	start = 0;
	uint32_t	count = 0;
	bool		ret = false;
	bool		last = true;
	

	if (!ice_ddp_check_id(ice, &p, &len)) {
		return (false);
	}

	if (!ice_ddp_check_nvm(ice, &p, &len)) {
		return (false);
	}

	/*
	 * Assume initially that we download all buffers in the segment.
	 * However apparently if a signing segment is present, this may
	 * mean we may only download a subset of the buffers in the
	 * segment (given from the signing segment) which may adjust
	 * the start and count values.
	 */
	nbuf = count = LE_32(*(uint32_t *)p);
	p += sizeof (uint32_t);
	len -= sizeof (uint32_t);

	if (nbuf * ICE_PKG_BUF_LEN > len) {
		ice_error(ice, "DDP config segment buffer count (%u) exceeds "
		    "remaining segment length (%u)", nbuf, len);
		return (false);
	}

	if (dp->ipd_sign != NULL) {
		ice_pkg_sign_hdr_t	*shdr = dp->ipd_sign;
		uint32_t		flags  = 0;

		start = LE_IN32(&shdr->ipsh_sbuf_start);
		count = LE_IN32(&shdr->ipsh_sbuf_count);
		flags = LE_IN32(&shdr->ipsh_flags);

		if (start > nbuf) {
			ice_error(ice, "DDP signing segment start buffer (%u) "
			    "is larger than segment buffer count (%u)",
			    start, nbuf);
			return (false);
		}

		if (start + count > nbuf) {
			ice_error(ice, "DDP signing segment count "
			    "(%u start %u) overruns segment buffer count (%u)",
			    count, start, nbuf);
			return (false);
		}

		if ((flags & ICE_PKG_SIGN_FLAG_VALID) != 0) {
			last = (flags & ICE_PKG_SIGN_FLAG_LAST) != 0 ?
			    true : false;
		}
	}

	if (!ice_cmd_acquire_global_lock(ice, true)) {
		return (false);
	}

	if (dp->ipd_sign != NULL) {
		ice_pkg_sign_hdr_t	*shdr = dp->ipd_sign;
		const uint8_t		*bufs = (const uint8_t *)(shdr + 1);
		uint32_t		sbcount = 0;

		sbcount = LE_IN32(bufs);
		bufs += sizeof (sbcount);

		if (!ice_ddp_download_pkgs(ice, bufs, 0, sbcount, false)) {
			ice_error(ice, "failed to download DDP signing "
			    "segment");
			goto done;
		}
	}

	if (!ice_ddp_download_pkgs(ice, p, start, count, last)) {
		ice_error(ice, "failed to download DDP config");
		goto done;
	}

	ret = true;

done:
	if (!ice_cmd_release_global_lock(ice)) {
		return (false);
	}

	return (ret);
}

static bool
is_last(const void *buf, uint32_t i, uint32_t n, bool set_last)
{
	ASSERT3U(i, <, n);

	if (!set_last) {
		return (false);
	}

	if (i + 1 == n) {
		return (true);
	}

	const ice_pkg_buf_hdr_t *bhdr = buf;
	const ice_pkg_sect_t	*sect = (const ice_pkg_sect_t *)(bhdr + 1);

	if ((LE_IN32(&sect->ips_type) & ICE_PKG_SECT_METADATA) != 0) {
		return (true);
	}

	return (false);
}

/*
 * Download the packages in the given buffers starting with buffer
 * `start` and continuing for `nbuf` buffers. Note that the caller
 * should must validate that start and nbuf are valid within buf
 */
static bool
ice_ddp_download_pkgs(ice_t *ice, const void *buf, uint32_t start,
    uint32_t nbuf, bool set_last)
{
	const uint8_t		*p = buf;
	const ice_pkg_buf_hdr_t	*bhdr;
	const ice_pkg_sect_t	*sect;

	p += ICE_PKG_BUF_LEN * start;
	bhdr = (const ice_pkg_buf_hdr_t *)p;
	sect = (const ice_pkg_sect_t *)(p + 1);

	/*
	 * The FreeBSD driver indicates that if the first section of the
	 * first buf is a metadata section, we skip everything.
	 */
	if ((LE_IN32(&sect->ips_type) & ICE_PKG_SECT_METADATA) != 0) {
		return (true);
	}

	for (uint32_t i = 0; i < nbuf; i++) {
		/*
		 * Also from the FreeBSD driver, if we encounter a
		 * metadata section while downloading, that means we're
		 * done, so check the 'next' section (if not the last one)
		 * to see if this is the final section
		 */
		bool last = is_last(p + ICE_PKG_BUF_LEN, i, nbuf, set_last);

		if (!ice_cmd_download_pkg(ice, p, ICE_PKG_BUF_LEN, last)) {
			ice_error(ice, "failed to download package %u",
			    start +i);
			return (false);
		}

		p += ICE_PKG_BUF_LEN;
	}

	return (true);
}

static bool
ice_ddp_check_id(ice_t *ice, const uint8_t **hdrp, uint32_t *lenp)
{
	const uint8_t *p = *hdrp;
	uint32_t len = *lenp;
	uint32_t i, n;

	if (len < sizeof (uint32_t)) {
		ice_error(ice, "DDP configuration segment size (%u) too small: "
		    "failed to read device ID count");
		return (false);
	}

	/* These might not be aligned, so we use LE_INxx() to read */
	n = LE_IN32(p);
	p += sizeof (n);
	len -= sizeof (n);

	if (n * 4 * sizeof (uint16_t) < len) {
		ice_error(ice, "DDP configuration segment device ID count (%u)"
		    "overflow", n);
		return (false);
	}

	for (i = 0; i < n; i++) {
		uint16_t devid, venid, subdevid, subvenid;

		/*
		 * We checked the length just prior to the loop, so we can
		 * safely grab all 4 values.
		 */
		devid = LE_IN16(p);
		p += sizeof (uint16_t);
		venid = LE_IN16(p);
		p += sizeof (uint16_t);
		subdevid = LE_IN16(p);
		p += sizeof (uint16_t);
		subvenid = LE_IN16(p);
		p += sizeof (uint16_t);

		if (devid == ice->ice_pci_did && venid == ice->ice_pci_vid &&
		    subdevid == ice->ice_pci_sdid &&
		    subvenid == ice->ice_pci_svid) {
			const uint8_t *end;
			uint32_t total = n * 4 * sizeof (uint16_t);

			/*
			 * Set *hdrp and *lenp to reflect the remainder of
			 * the segment after the device ID table.
			 */
			end = *hdrp + sizeof (uint32_t) + total;
			*hdrp = end;
			*lenp = len;

			return (true);
		}
	}

	ice_error(ice, "DDP configuration segment does not contain a matching "
	    "PCI id for device");
	return (false);
}

static bool
ice_ddp_check_nvm(ice_t *ice, const uint8_t **pp, uint32_t *lenp)
{
	const uint8_t *p = *pp;
	const uint8_t *end;
	uint32_t len = *lenp;
	uint32_t n, sz;

	if (len < sizeof (uint32_t)) {
		ice_error(ice, "NVM version table is truncated");
		return (false);
	}

	n = LE_IN32(p);
	p += sizeof (uint32_t);
	len -= sizeof (n);

	sz = n * sizeof (uint32_t);
	if (sz > len) {
		ice_error(ice, "NVM version table size (%u entries) overflow",
		    n);
		return (false);
	}

	end = p + sz;
	len -= sz;

	/* TODO */

	*pp = end;
	*lenp = len;
	return (true);
}

static void
ice_ddp_free_data(ice_pkg_data_t *dp)
{
	if (dp == NULL) {
		return;
	}

	if (dp->ipd_config != NULL) {
		ASSERT3U(dp->ipd_cfglen, >, 0);
		kmem_free(dp->ipd_config, dp->ipd_cfglen);
		dp->ipd_config = NULL;
		dp->ipd_cfglen = 0;
	}

	if (dp->ipd_sign != NULL) {
		ASSERT3U(dp->ipd_sign, >, 0);
		kmem_free(dp->ipd_sign, dp->ipd_signlen);
		dp->ipd_sign = NULL;
		dp->ipd_signlen = 0;
	}
}
