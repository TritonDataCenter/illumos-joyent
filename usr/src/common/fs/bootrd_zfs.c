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
 * Copyright 2025 MNX Cloud, Inc.
 */

/*
 * Minimal zfs reader for boot_archive. Interface is exported via
 * global bzfs_ops structure.
 *
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/bootconf.h>
#include <sys/bootvfs.h>
#include <sys/filep.h>
#include <sys/nvpair.h>
#include <sys/queue.h>
#include <sys/sysmacros.h>

#include <sys/dmu_objset.h>
#include <sys/dsl_dir.h>
#include <sys/zap_impl.h>
#include <sys/sa_impl.h>
#include <sys/zfs_sa.h>
#include <sys/uberblock_impl.h>
#include <sys/vdev_impl.h>

extern struct bootops *ops;
extern int bootrd_debug;
extern void kobj_printf(char *fmt, ...) __KPRINTFLIKE(1);

static int bzfs_mountroot(char *str);
static int bzfs_unmountroot(void);
static int bzfs_open(char *filename, int flags);
static int bzfs_close(int fd);
static ssize_t bzfs_read(int fd, caddr_t buf, size_t size);
static off_t bzfs_lseek(int filefd, off_t addr, int whence);
static int bzfs_fstat(int filefd, struct bootstat *buf);
static void bzfs_closeall(int flag);
static int bzfs_getdents(int fd, struct dirent *buf, unsigned size);

static int bzfs_read_bp(const blkptr_t *, void *);
static int bzfs_mzap_lookup(const mzap_phys_t *, size_t, const char *,
    uint64_t *);
static int bzfs_zap_lookup(const dnode_phys_t *, const char *,
    uint64_t, uint64_t, void *);

/*
 * We need to describe our vdev a bit.
 */
struct rd_vdev {
	struct rd_vdev	*vdev_top;
	int		vdev_ashift;
};

/* on disk data structures */
struct nvpair_phys {
	uint32_t esize;
	uint32_t dsize;
	uint32_t nsize;
	char	 name[];
};

struct nvdata_phys {
	uint32_t type;
	uint32_t nelem;
	char data[];
};

struct nvstring {
	uint32_t size;
	char data[];
};

/*
 * This structure represents an open file.
 */
struct filei {
	int fd;
	off_t off;
	dnode_phys_t dnode;
	struct bootstat stat;
	TAILQ_ENTRY(filei) next;
};

/* "mounted" pool config. */
struct bzfs_mount {
	char *label;
	struct rd_vdev vroot;
	struct rd_vdev vdev;
	uberblock_t ub;			/* byteswapped copy of ub */
	objset_phys_t mos;
	uint64_t zfs_crc64_table[256];
	uint64_t rootfs;
	objset_phys_t objset;
	TAILQ_HEAD(file_list, filei) open_files;

	/*
	 * caches. Our ramdisk is memory, so we can use boot block area
	 * (3.5MB) for local caches.
	 * on boot archive, we do not use large blocks.
	 */
	const dnode_phys_t *dnode_cache_obj;
	uint64_t dnode_cache_bn;
	char *dnode_cache_buf;	/* SPA_MAXBLOCKSIZE */
	char *zap_scratch;	/* SPA_MAXBLOCKSIZE */
	char *zfs_temp_buf;	/* VDEV_BOOT_SIZE - 2 * SPA_MAXBLOCKSIZE */
	char *zfs_temp_end;
	char *zfs_temp_ptr;
};

/* our mounted rootfs data */
static struct bzfs_mount *mount;

/*
 * Trivial alloc/free to keep track our scrath buffer allocations.
 */
static void *
bzfs_alloc(size_t size)
{
	char *ptr;

	if (mount->zfs_temp_ptr + size > mount->zfs_temp_end) {
		panic("ZFS: out of temporary buffer space\n");
	}
	ptr = mount->zfs_temp_ptr;
	mount->zfs_temp_ptr += size;

	return (ptr);
}

static void
bzfs_free(void *ptr, size_t size)
{
	if (ptr == NULL)
		return;

	mount->zfs_temp_ptr -= size;
	if (mount->zfs_temp_ptr != ptr) {
		panic("ZFS: bzfs_alloc()/bzfs_free() mismatch\n");
	}
}

/*
 * lookup name from list of nvpairs.
 * return pointer to data.
 *
 * array of xdr packed nvpairs
 *     4B encoded nvpair size
 *     4B decoded nvpair size
 *     4B name string size
 *     name string
 *     4B data type
 *     4B # of data elements
 *     data
 *  8B of 0
 */
static struct nvdata_phys *
nv_lookup(char *nv, char *name, data_type_t type)
{
	struct nvpair_phys *nvp;
	uint32_t nvsize;
	uint32_t size;
	struct nvdata_phys *nvdata;

	nvp = (struct nvpair_phys *)nv;
	for (nvsize = ntohl(nvp->esize);
	    nvsize != 0;
	    nvsize = ntohl(nvp->esize)) {
		size = ntohl(nvp->nsize);
		nvdata = (struct nvdata_phys *)
		    P2ROUNDUP((uintptr_t)nvp->name + size, 4);
		if (type == ntohl(nvdata->type) &&
		    strncmp(name, nvp->name, size) == 0)
			return (nvdata);
		nv += nvsize;
		nvp = (struct nvpair_phys *)nv;
	}
	return (NULL);
}

static void
bzfs_byteswap_uint64_array(void *vbuf, size_t size)
{
        uint64_t *buf = vbuf;
        size_t count = size >> 3;
        int i;

        ASSERT((size & 7) == 0);

        for (i = 0; i < count; i++)
                buf[i] = BSWAP_64(buf[i]);
}

/* Uberblock operations */
static int
bzfs_uberblock_verify(uberblock_t *ub)
{
	if (ub->ub_magic == BSWAP_64((uint64_t)UBERBLOCK_MAGIC)) {
		bzfs_byteswap_uint64_array(ub, sizeof (uberblock_t));
	}

	if (ub->ub_magic != UBERBLOCK_MAGIC ||
	    !SPA_VERSION_IS_SUPPORTED(ub->ub_version))
		return (EINVAL);

	return (0);
}

static int
bzfs_uberblock_compare(const uberblock_t *ub1, const uberblock_t *ub2)
{
	int cmp = TREE_CMP(ub1->ub_txg, ub2->ub_txg);

	if (cmp != 0)
		return (cmp);

	return (TREE_CMP(ub1->ub_timestamp, ub2->ub_timestamp));
}

/*
 * Passthrough.
 */
static int
bzio_checksum_verify(const blkptr_t *bp __unused, void *buf __unused)
{
	return (0);
}

/*
 * read from ramdisk
 */
static int
bzio_read_rd(const blkptr_t *bp, void *pbuf, off_t offset, size_t size)
{
	fileid_t filep;

	filep.fi_blocknum = (offset + VDEV_LABEL_START_SIZE) / DEV_BSIZE;
	filep.fi_count = size;
	filep.fi_memp = pbuf;

	if (diskread(&filep) != 0)
		return (EIO);

	return (bzio_checksum_verify(bp, pbuf));
}

static int
bzio_read_gang(const blkptr_t *bp, void *buf)
{
	blkptr_t gbh_bp;
	zio_gbh_phys_t zio_gb;
	char *pbuf;
	int i, error;

	/* Artificial BP for gang block header. */
	gbh_bp = *bp;
	BP_SET_PSIZE(&gbh_bp, SPA_GANGBLOCKSIZE);
	BP_SET_LSIZE(&gbh_bp, SPA_GANGBLOCKSIZE);
	BP_SET_CHECKSUM(&gbh_bp, ZIO_CHECKSUM_GANG_HEADER);
	BP_SET_COMPRESS(&gbh_bp, ZIO_COMPRESS_OFF);
	for (i = 0; i < SPA_DVAS_PER_BP; i++)
		DVA_SET_GANG(&gbh_bp.blk_dva[i], 0);

	/* Read gang header block using the artificial BP. */
	error = bzfs_read_bp(&gbh_bp, &zio_gb);
	if (error != 0)
		return (error);

	pbuf = buf;
	for (i = 0; i < SPA_GBH_NBLKPTRS; i++) {
		blkptr_t *gbp = &zio_gb.zg_blkptr[i];

		if (BP_IS_HOLE(gbp))
			continue;
		error = bzfs_read_bp(gbp, pbuf);
		if (error != 0)
			return (error);
		pbuf += BP_GET_PSIZE(gbp);
	}

	error = bzio_checksum_verify(bp, buf);
	return (error);
}

static int
bzfs_decode_embedded_bp_compressed(const blkptr_t *bp, void *buf)
{
	int psize;
	uint8_t *buf8 = buf;
	uint64_t w = 0;
	const uint64_t *bp64 = (const uint64_t *)bp;

	psize = BPE_GET_PSIZE(bp);

	/*
	 * Decode the words of the block pointer into the byte array.
	 * Low bits of first word are the first byte (little endian).
	 */
	for (int i = 0; i < psize; i++) {
		if (i % sizeof (w) == 0) {
			/* beginning of a word */
			ASSERT3P(bp64, <, bp + 1);
			w = *bp64;
			bp64++;
			if (!BPE_IS_PAYLOADWORD(bp, bp64))
				bp64++;
		}
		buf8[i] = BF64_GET(w, (i % sizeof (w)) * NBBY, NBBY);
	}
	return (0);
}

static zio_compress_info_t bzio_compress_table[ZIO_COMPRESS_FUNCTIONS] = {
	{"inherit",		0,	NULL,	NULL},
	{"on",			0,	NULL,	NULL},
	{"uncompressed",	0,	NULL,	NULL},
	{"lzjb",		0,	NULL,	lzjb_decompress},
	{"empty",		0,	NULL,	NULL},
	{"gzip-1",		1,	NULL,	gzip_decompress},
	{"gzip-2",		2,	NULL,	gzip_decompress},
	{"gzip-3",		3,	NULL,	gzip_decompress},
	{"gzip-4",		4,	NULL,	gzip_decompress},
	{"gzip-5",		5,	NULL,	gzip_decompress},
	{"gzip-6",		6,	NULL,	gzip_decompress},
	{"gzip-7",		7,	NULL,	gzip_decompress},
	{"gzip-8",		8,	NULL,	gzip_decompress},
	{"gzip-9",		9,	NULL,	gzip_decompress},
	{"zle",			64,	NULL,	zle_decompress},
	{"lz4",			0,	NULL,	lz4_decompress}
};

static int
bzfs_decompress_data(enum zio_compress c, void *src, size_t s_len,
    void *dst, size_t d_len)
{
	zio_compress_info_t *ci;

	if ((uint_t)c >= ZIO_COMPRESS_FUNCTIONS)
		return (EINVAL);

	ci = &bzio_compress_table[c];
	if (ci->ci_decompress == NULL)
		return (EINVAL);

	return (ci->ci_decompress(src, dst, s_len, d_len, ci->ci_level));
}

#ifdef BP_GET_NDVAS
#undef BP_GET_NDVAS
#endif
/*
 * We do not support encryption, therefore create simple macro.
 */
#define	BP_GET_NDVAS(bp)			\
	(!!DVA_GET_ASIZE(&(bp)->blk_dva[0]) +	\
	!!DVA_GET_ASIZE(&(bp)->blk_dva[1]) +	\
	!!DVA_GET_ASIZE(&(bp)->blk_dva[2]))

/*
 * Read data referenced by block pointer.
 */
static int
bzfs_read_bp(const blkptr_t *bp, void *buf)
{
	void *pbuf;
	uint64_t size;
	enum zio_compress c = BP_GET_COMPRESS(bp);
	int error = EIO;

	if (BP_IS_EMBEDDED(bp)) {
		size = BPE_GET_PSIZE(bp);

		if (c != ZIO_COMPRESS_OFF)
			pbuf = bzfs_alloc(size);
		else
			pbuf = buf;

		error = bzfs_decode_embedded_bp_compressed(bp, pbuf);
		if (error == 0 && c != ZIO_COMPRESS_OFF) {
			error = bzfs_decompress_data(c, pbuf,
			    size, buf, BP_GET_LSIZE(bp));
		}
		if (c != ZIO_COMPRESS_OFF)
			bzfs_free(pbuf, size);
		return (error);
	}

	for (int i = 0; i < BP_GET_NDVAS(bp); i++) {
		const dva_t *dva = &bp->blk_dva[i];
		off_t offset;

		size = BP_GET_PSIZE(bp);
		offset = DVA_GET_OFFSET(dva);
		if (c != ZIO_COMPRESS_OFF)
			pbuf = bzfs_alloc(size);
		else
			pbuf = buf;

		if (DVA_GET_GANG(dva))
			error = bzio_read_gang(bp, pbuf);
		else
			error = bzio_read_rd(bp, pbuf, offset, size);

		if (error == 0 && c != ZIO_COMPRESS_OFF) {
			error = bzfs_decompress_data(c, pbuf,
			    size, buf, BP_GET_LSIZE(bp));
		}

		if (c != ZIO_COMPRESS_OFF)
			bzfs_free(pbuf, size);
		if (error == 0)
			break;
	}
	return (error);
}

static int
bzfs_dnode_read(const dnode_phys_t *dnode, off_t offset,
    void *buf, size_t buflen)
{
	int ibshift = dnode->dn_indblkshift - SPA_BLKPTRSHIFT;
	int bsize = dnode->dn_datablkszsec << SPA_MINBLOCKSHIFT;
	int nlevels = dnode->dn_nlevels;
	int i, rc;

        if (bsize > SPA_OLD_MAXBLOCKSIZE) {
                return (EIO);
        }

	/*
	 * Handle odd block sizes, mirrors dmu_read_impl().  Data can't exist
	 * past the first block, so we'll clip the read to the portion of the
	 * buffer within bsize and zero out the remainder.
	 */
	if (dnode->dn_maxblkid == 0) {
		size_t newbuflen;

		newbuflen = offset > bsize ? 0 : MIN(buflen, bsize - offset);
		bzero((char *)buf + newbuflen, buflen - newbuflen);
		buflen = newbuflen;
	}

	/*
	 * Note: bsize may not be a power of two here so we need to do an
	 * actual divide rather than a bitshift.
	 */
	while (buflen > 0) {
		uint64_t bn = offset / bsize;
		int boff = offset % bsize;
		int ibn;
		const blkptr_t *indbp;
		blkptr_t bp;

		if (dnode == mount->dnode_cache_obj &&
		    bn == mount->dnode_cache_bn)
			goto cached;

		indbp = dnode->dn_blkptr;
		for (i = 0; i < nlevels; i++) {
			/*
			 * Copy the bp from the indirect array so that
			 * we can re-use the scratch buffer for multi-level
			 * objects.
			 */
			ibn = bn >> ((nlevels - i - 1) * ibshift);
			ibn &= ((1 << ibshift) - 1);
			bp = indbp[ibn];
			if (BP_IS_HOLE(&bp)) {
				bzero(mount->dnode_cache_buf, bsize);
				break;
			}
			rc = bzfs_read_bp(&bp, mount->dnode_cache_buf);
			if (rc)
				return (rc);
			indbp = (const blkptr_t *) mount->dnode_cache_buf;
		}
		mount->dnode_cache_obj = dnode;
		mount->dnode_cache_bn = bn;
cached:

		/*
		 * The buffer contains our data block. Copy what we
		 * need from it and loop.
		 */
		i = bsize - boff;
		if (i > buflen)
			i = buflen;
		bcopy(&mount->dnode_cache_buf[boff], buf, i);
		buf = ((char *)buf) + i;
		offset += i;
		buflen -= i;
	}

	return (0);
}

static int
bzfs_objset_get_dnode(const objset_phys_t *os, uint64_t objnum,
    dnode_phys_t *dnode)
{
        off_t offset;

        offset = objnum * sizeof (dnode_phys_t);
        return (bzfs_dnode_read(&os->os_meta_dnode, offset,
            dnode, sizeof (dnode_phys_t)));
}

typedef struct fat_zap {
	int zap_block_shift;			/* block size shift */
	zap_phys_t *zap_phys;
	const dnode_phys_t *zap_dnode;
} fat_zap_t;

#undef FZAP_BLOCK_SHIFT
#define	FZAP_BLOCK_SHIFT(zap)	((zap)->zap_block_shift)

/*
 * The embedded pointer table starts half-way through the block.  Since
 * the pointer table itself is half the block, it starts at (64-bit)
 * word number (1<<ZAP_EMBEDDED_PTRTBL_SHIFT(zap)).
 */
#undef ZAP_EMBEDDED_PTRTBL_ENT
#define	ZAP_EMBEDDED_PTRTBL_ENT(zap, idx) \
	((uint64_t *)(zap)->zap_phys) \
	[(idx) + (1<<ZAP_EMBEDDED_PTRTBL_SHIFT(zap))]

#define	ZAP_LEAF_MAGIC 0x2AB1EAF

/* chunk size = 24 bytes */
#define	ZAP_LEAF_CHUNKSIZE 24

/*
 * The amount of space available for chunks is:
 * block size (1<<l->l_bs) - hash entry size (2) * number of hash
 * entries - header space (2*chunksize)
 */
#define	ZAP_LEAF_NUMCHUNKS(l) \
	(((1<<(l)->l_bs) - 2*ZAP_LEAF_HASH_NUMENTRIES(l)) / \
	ZAP_LEAF_CHUNKSIZE - 2)

/*
 * The amount of space within the chunk available for the array is:
 * chunk size - space for type (1) - space for next pointer (2)
 */
#define	ZAP_LEAF_ARRAY_BYTES (ZAP_LEAF_CHUNKSIZE - 3)

#define	ZAP_LEAF_ARRAY_NCHUNKS(bytes) \
	(((bytes)+ZAP_LEAF_ARRAY_BYTES-1)/ZAP_LEAF_ARRAY_BYTES)

/*
 * Low water mark:  when there are only this many chunks free, start
 * growing the ptrtbl.  Ideally, this should be larger than a
 * "reasonably-sized" entry.  20 chunks is more than enough for the
 * largest directory entry (MAXNAMELEN (256) byte name, 8-byte value),
 * while still being only around 3% for 16k blocks.
 */
#define	ZAP_LEAF_LOW_WATER (20)

/*
 * The leaf hash table has block size / 2^5 (32) number of entries,
 * which should be more than enough for the maximum number of entries,
 * which is less than block size / CHUNKSIZE (24) / minimum number of
 * chunks per entry (3).
 */
#define	ZAP_LEAF_HASH_SHIFT(l) ((l)->l_bs - 5)
#define	ZAP_LEAF_HASH_NUMENTRIES(l) (1 << ZAP_LEAF_HASH_SHIFT(l))

/*
 * The chunks start immediately after the hash table.  The end of the
 * hash table is at l_hash + HASH_NUMENTRIES, which we simply cast to a
 * chunk_t.
 */
#define	ZAP_LEAF_CHUNK(l, idx) \
	((zap_leaf_chunk_t *) \
	((l)->l_phys->l_hash + ZAP_LEAF_HASH_NUMENTRIES(l)))[idx]
#define	ZAP_LEAF_ENTRY(l, idx) (&ZAP_LEAF_CHUNK(l, idx).l_entry)

/*
 * TAKE NOTE:
 * If zap_leaf_phys_t is modified, zap_leaf_byteswap() must be modified.
 */
typedef struct zap_leaf_phys {
	struct zap_leaf_header {
		/* Public to ZAP */
		uint64_t lh_block_type;		/* ZBT_LEAF */
		uint64_t lh_pad1;
		uint64_t lh_prefix;		/* hash prefix of this leaf */
		uint32_t lh_magic;		/* ZAP_LEAF_MAGIC */
		uint16_t lh_nfree;		/* number free chunks */
		uint16_t lh_nentries;		/* number of entries */
		uint16_t lh_prefix_len;		/* num bits used to id this */

		/* Private to zap_leaf */
		uint16_t lh_freelist;		/* chunk head of free list */
		uint8_t lh_flags;		/* ZLF_* flags */
		uint8_t lh_pad2[11];
	} l_hdr; /* 2 24-byte chunks */

	/*
	 * The header is followed by a hash table with
	 * ZAP_LEAF_HASH_NUMENTRIES(zap) entries.  The hash table is
	 * followed by an array of ZAP_LEAF_NUMCHUNKS(zap)
	 * zap_leaf_chunk structures.  These structures are accessed
	 * with the ZAP_LEAF_CHUNK() macro.
	 */

	uint16_t l_hash[1];
} zap_leaf_phys_t;

typedef union zap_leaf_chunk {
	struct zap_leaf_entry {
		uint8_t le_type;		/* always ZAP_CHUNK_ENTRY */
		uint8_t le_value_intlen;	/* size of value's ints */
		uint16_t le_next;		/* next entry in hash chain */
		uint16_t le_name_chunk;		/* first chunk of the name */
		uint16_t le_name_numints;	/* ints in name (incl null) */
		uint16_t le_value_chunk;	/* first chunk of the value */
		uint16_t le_value_numints;	/* value length in ints */
		uint32_t le_cd;			/* collision differentiator */
		uint64_t le_hash;		/* hash value of the name */
	} l_entry;
	struct zap_leaf_array {
		uint8_t la_type;		/* always ZAP_CHUNK_ARRAY */
		uint8_t la_array[ZAP_LEAF_ARRAY_BYTES];
		uint16_t la_next;		/* next blk or CHAIN_END */
	} l_array;
		struct zap_leaf_free {
		uint8_t lf_type;		/* always ZAP_CHUNK_FREE */
		uint8_t lf_pad[ZAP_LEAF_ARRAY_BYTES];
		uint16_t lf_next;	/* next in free list, or CHAIN_END */
	} l_free;
} zap_leaf_chunk_t;

typedef struct zap_leaf {
	int l_bs;			/* block size shift */
	zap_leaf_phys_t *l_phys;
} zap_leaf_t;

/*
 * Compare a name with a zap leaf entry. Return non-zero if the name
 * matches.
 */
static int
bzfs_fzap_name_equal(const zap_leaf_t *zl, const zap_leaf_chunk_t *zc,
    const char *name)
{
	size_t namelen;
	const zap_leaf_chunk_t *nc;
	const char *p;

	namelen = zc->l_entry.le_name_numints;

	nc = &ZAP_LEAF_CHUNK(zl, zc->l_entry.le_name_chunk);
	p = name;
	while (namelen > 0) {
		size_t len;

		len = namelen;
		if (len > ZAP_LEAF_ARRAY_BYTES)
			len = ZAP_LEAF_ARRAY_BYTES;
		if (memcmp(p, nc->l_array.la_array, len))
			return (0);
		p += len;
		namelen -= len;
		nc = &ZAP_LEAF_CHUNK(zl, nc->l_array.la_next);
	}

	return (1);
}

/*
 * Extract a uint64_t value from a zap leaf entry.
 */
static uint64_t
bzfs_fzap_leaf_value(const zap_leaf_t *zl, const zap_leaf_chunk_t *zc)
{
	const zap_leaf_chunk_t *vc;
	int i;
	uint64_t value;
	const uint8_t *p;

	vc = &ZAP_LEAF_CHUNK(zl, zc->l_entry.le_value_chunk);
	for (i = 0, value = 0, p = vc->l_array.la_array; i < 8; i++) {
		value = (value << 8) | p[i];
	}

	return (value);
}

static void
bzfs_stv(int len, void *addr, uint64_t value)
{
	switch (len) {
	case 1:
		*(uint8_t *)addr = value;
		return;
	case 2:
		*(uint16_t *)addr = value;
		return;
	case 4:
		*(uint32_t *)addr = value;
		return;
	case 8:
		*(uint64_t *)addr = value;
		return;
	}
}

/*
 * Extract a array from a zap leaf entry.
 */
static void
bzfs_fzap_leaf_array(const zap_leaf_t *zl, const zap_leaf_chunk_t *zc,
    uint64_t integer_size, uint64_t num_integers, void *buf)
{
	uint64_t array_int_len = zc->l_entry.le_value_intlen;
	uint64_t value = 0;
	uint64_t *u64 = buf;
	char *p = buf;
	int len = MIN(zc->l_entry.le_value_numints, num_integers);
	int chunk = zc->l_entry.le_value_chunk;
	int byten = 0;

	if (integer_size == 8 && len == 1) {
		*u64 = bzfs_fzap_leaf_value(zl, zc);
		return;
	}

	while (len > 0) {
		struct zap_leaf_array *la = &ZAP_LEAF_CHUNK(zl, chunk).l_array;
		int i;

		for (i = 0; i < ZAP_LEAF_ARRAY_BYTES && len > 0; i++) {
			value = (value << 8) | la->la_array[i];
			byten++;
			if (byten == array_int_len) {
				bzfs_stv(integer_size, p, value);
				byten = 0;
				len--;
				if (len == 0)
					return;
				p += integer_size;
			}
		}
		chunk = la->la_next;
	}
}

static int
bzfs_fzap_check_size(uint64_t integer_size, uint64_t num_integers)
{
	switch (integer_size) {
	case 1:
	case 2:
	case 4:
	case 8:
		break;
	default:
		return (EINVAL);
	}

	if (integer_size * num_integers > ZAP_MAXVALUELEN)
		return (E2BIG);

	return (0);
}

static void
bzfs_zap_leaf_free(zap_leaf_t *leaf)
{
	bzfs_free(leaf->l_phys, 1 << leaf->l_bs);
	bzfs_free(leaf, sizeof (*leaf));
}

static int
bzfs_zap_get_leaf_byblk(fat_zap_t *zap, uint64_t blk, zap_leaf_t **lp)
{
	int bs = FZAP_BLOCK_SHIFT(zap);
	int err;

	*lp = bzfs_alloc(sizeof (**lp));

	(*lp)->l_bs = bs;
	(*lp)->l_phys = bzfs_alloc(1 << bs);

	err = bzfs_dnode_read(zap->zap_dnode, blk << bs, (*lp)->l_phys,
	    1 << bs);
	if (err != 0) {
		bzfs_zap_leaf_free(*lp);
	}
	return (err);
}

static int
bzfs_zap_table_load(fat_zap_t *zap, zap_table_phys_t *tbl, uint64_t idx,
    uint64_t *valp)
{
	int bs = FZAP_BLOCK_SHIFT(zap);
	uint64_t blk = idx >> (bs - 3);
	uint64_t off = idx & ((1 << (bs - 3)) - 1);
	uint64_t *buf;
	int rc;

	buf = bzfs_alloc(1 << zap->zap_block_shift);
	rc = bzfs_dnode_read(zap->zap_dnode, (tbl->zt_blk + blk) << bs,
	    buf, 1 << zap->zap_block_shift);
	if (rc == 0)
		*valp = buf[off];
	bzfs_free(buf, 1 << zap->zap_block_shift);
	return (rc);
}

static int
bzfs_zap_idx_to_blk(fat_zap_t *zap, uint64_t idx, uint64_t *valp)
{
	if (zap->zap_phys->zap_ptrtbl.zt_numblks == 0) {
		*valp = ZAP_EMBEDDED_PTRTBL_ENT(zap, idx);
		return (0);
	} else {
		return (bzfs_zap_table_load(zap, &zap->zap_phys->zap_ptrtbl,
		    idx, valp));
	}
}

#define	ZAP_HASH_IDX(hash, n)	(((n) == 0) ? 0 : ((hash) >> (64 - (n))))
static int
bzfs_zap_deref_leaf(fat_zap_t *zap, uint64_t h, zap_leaf_t **lp)
{
	uint64_t idx, blk;
	int err;

	idx = ZAP_HASH_IDX(h, zap->zap_phys->zap_ptrtbl.zt_shift);
	err = bzfs_zap_idx_to_blk(zap, idx, &blk);
	if (err != 0)
		return (err);
	return (bzfs_zap_get_leaf_byblk(zap, blk, lp));
}

#define	CHAIN_END	0xffff	/* end of the chunk chain */
#define	LEAF_HASH(l, h) \
	((ZAP_LEAF_HASH_NUMENTRIES(l)-1) & \
	((h) >> \
	(64 - ZAP_LEAF_HASH_SHIFT(l) - (l)->l_phys->l_hdr.lh_prefix_len)))
#define	LEAF_HASH_ENTPTR(l, h)  (&(l)->l_phys->l_hash[LEAF_HASH(l, h)])

static int
bzfs_zap_leaf_lookup(zap_leaf_t *zl, uint64_t hash, const char *name,
    uint64_t integer_size, uint64_t num_integers, void *value)
{
	int rc;
	uint16_t *chunkp;
	struct zap_leaf_entry *le;

	/*
	 * Make sure this chunk matches our hash.
	 */
	if (zl->l_phys->l_hdr.lh_prefix_len > 0 &&
	    zl->l_phys->l_hdr.lh_prefix !=
	    hash >> (64 - zl->l_phys->l_hdr.lh_prefix_len))
		return (EIO);

	rc = ENOENT;
	for (chunkp = LEAF_HASH_ENTPTR(zl, hash);
	    *chunkp != CHAIN_END; chunkp = &le->le_next) {
		zap_leaf_chunk_t *zc;
		uint16_t chunk = *chunkp;

		le = ZAP_LEAF_ENTRY(zl, chunk);
		if (le->le_hash != hash)
			continue;
		zc = &ZAP_LEAF_CHUNK(zl, chunk);
		if (bzfs_fzap_name_equal(zl, zc, name)) {
			if (zc->l_entry.le_value_intlen > integer_size) {
				rc = EINVAL;
			} else {
				bzfs_fzap_leaf_array(zl, zc, integer_size,
				    num_integers, value);
				rc = 0;
			}
			break;
		}
	}
	return (rc);
}

static int
bzfs_ilog2(int n)
{
	int v;

	for (v = 0; v < 32; v++)
		if (n == (1 << v))
			return (v);
	return (-1);
}

#define	ZAP_HASHBITS		28

static uint64_t
bzfs_zap_hash(uint64_t salt, const char *name, uint64_t zap_flags)
{
	const uint8_t *cp;
	uint8_t c;
	uint64_t crc = salt;

	for (cp = (const uint8_t *)name; (c = *cp) != '\0'; cp++)
		crc = (crc >> 8) ^ mount->zfs_crc64_table[(crc ^ c) & 0xFF];

	/*
	 * Only use 28 bits, since we need 4 bits in the cookie for the
	 * collision differentiator.  We MUST use the high bits, since
	 * those are the onces that we first pay attention to when
	 * chosing the bucket.
	 */
	crc &= ~((1ULL << (64 - ZAP_HASHBITS)) - 1);

	return (crc);
}

/*
 * Lookup a value in a fatzap directory.
 */
static int
bzfs_fzap_lookup(const dnode_phys_t *dnode, zap_phys_t *zh,
    const char *name, uint64_t integer_size, uint64_t num_integers,
    void *value)
{
	int bsize = dnode->dn_datablkszsec << SPA_MINBLOCKSHIFT;
	fat_zap_t z;
	zap_leaf_t *zl;
	uint64_t hash;
	int rc;

	if (zh->zap_magic != ZAP_MAGIC)
		return (EIO);

	if ((rc = bzfs_fzap_check_size(integer_size, num_integers)) != 0)
		return (rc);

	z.zap_block_shift = bzfs_ilog2(bsize);
	z.zap_phys = zh;
	z.zap_dnode = dnode;

	hash = bzfs_zap_hash(zh->zap_salt, name, zh->zap_flags);
	rc = bzfs_zap_deref_leaf(&z, hash, &zl);
	if (rc != 0)
		return (rc);

	rc = bzfs_zap_leaf_lookup(zl, hash, name, integer_size,
	    num_integers, value);

	bzfs_zap_leaf_free(zl);
	return (rc);
}

/*
 * Lookup a value in a microzap directory.
 */
static int
bzfs_mzap_lookup(const mzap_phys_t *mz, size_t size, const char *name,
    uint64_t *value)
{
	const mzap_ent_phys_t *mze;
	int chunks, i;

	/*
	 * Microzap objects use exactly one block. Read the whole
	 * thing.
	 */
	chunks = size / MZAP_ENT_LEN - 1;
	for (i = 0; i < chunks; i++) {
		mze = &mz->mz_chunk[i];
		if (strcmp(mze->mze_name, name) == 0) {
			*value = mze->mze_value;
			return (0);
		}
	}

	return (ENOENT);
}

/*
 * Lookup a name in a zap object and return its value as a uint64_t.
 */
static int
bzfs_zap_lookup(const dnode_phys_t *dnode, const char *name,
    uint64_t integer_size, uint64_t num_integers, void *value)
{
	int rc;
	zap_phys_t *zap;
	size_t size = dnode->dn_datablkszsec << SPA_MINBLOCKSHIFT;

	zap = bzfs_alloc(size);

	rc = bzfs_dnode_read(dnode, 0, zap, size);
	if (rc)
		goto done;

	switch (zap->zap_block_type) {
	case ZBT_MICRO:
		rc = bzfs_mzap_lookup((const mzap_phys_t *)zap, size,
		    name, value);
		break;
	case ZBT_HEADER:
		rc = bzfs_fzap_lookup(dnode, zap, name, integer_size,
		    num_integers, value);
		break;
	default:
		rc = EIO;
	}
done:
	bzfs_free(zap, size);
	return (rc);
}

/*
 * Find the object set pointed to by the BOOTFS property or the root
 * dataset if there is none and return its details in *objset
 */
static int
bzfs_get_root(objset_phys_t *objset)
{
	dnode_phys_t dir, propdir;
	dsl_dataset_phys_t *ds;
	uint64_t props, root = 0;

	/*
	 * Start with the MOS directory object.
	 */
	if (bzfs_objset_get_dnode(&mount->mos,
	    DMU_POOL_DIRECTORY_OBJECT, &dir)) {
		return (EIO);
	}

	/*
	 * Lookup the pool_props and see if we can find a bootfs.
	 */
	if (bzfs_zap_lookup(&dir, DMU_POOL_PROPS,
	    sizeof (props), 1, &props) == 0 &&
	    bzfs_objset_get_dnode(&mount->mos, props, &propdir) == 0) {
		(void) bzfs_zap_lookup(&propdir, "bootfs",
		    sizeof (root), 1, &root);
	}

	if (root == 0) {
		/* Lookup the root dataset directory */
		if (bzfs_zap_lookup(&dir, DMU_POOL_ROOT_DATASET,
		    sizeof (root), 1, &root) ||
		    bzfs_objset_get_dnode(&mount->mos, root, &dir)) {
			return (EIO);
		} else {
			/*
			 * Use the information from the dataset directory's
			 * bonus buffer to find the dataset object and from
			 * that the object set itself.
			 */
			dsl_dir_phys_t *dd = (dsl_dir_phys_t *)&dir.dn_bonus;
			root = dd->dd_head_dataset_obj;
		}
	}

	if (bzfs_objset_get_dnode(&mount->mos, root, &dir)) {
                return (EIO);
        }

        ds = (dsl_dataset_phys_t *)&dir.dn_bonus;
        if (bzfs_read_bp(&ds->ds_bp, objset)) {
                return (EIO);
        }

	mount->rootfs = root;
	return (0);
}

static void
bzfs_zfs_init_crc(void)
{
	int i, j;
	uint64_t *ct;

	/*
	 * Calculate the crc64 table (used for the zap hash
	 * function).
	 */
	bzero(mount->zfs_crc64_table, sizeof (mount->zfs_crc64_table));
	for (i = 0; i < 256; i++) {
		ct = mount->zfs_crc64_table + i;
		for (*ct = i, j = 8; j > 0; j--)
			*ct = (*ct >> 1) ^
			    (-(*ct & 1) & ZFS_CRC64_POLY);
	}
}

static int
bzfs_dnode_stat(dnode_phys_t *dn, struct bootstat *sb)
{
	if (dn->dn_bonustype != DMU_OT_SA) {
		znode_phys_t *zp = (znode_phys_t *)dn->dn_bonus;

		sb->st_mode = zp->zp_mode;
		sb->st_uid = zp->zp_uid;
		sb->st_gid = zp->zp_gid;
		sb->st_size = zp->zp_size;
	} else {
		sa_hdr_phys_t *sahdrp;
		int hdrsize;
		size_t size = 0;
		void *buf = NULL;

		if (dn->dn_bonuslen != 0) {
			sahdrp = (sa_hdr_phys_t *)DN_BONUS(dn);
		} else {
			if ((dn->dn_flags & DNODE_FLAG_SPILL_BLKPTR) != 0) {
				blkptr_t *bp = DN_SPILL_BLKPTR(dn);
				int error;

				size = BP_GET_LSIZE(bp);
				buf = bzfs_alloc(size);
				error = bzfs_read_bp(bp, buf);

				if (error != 0) {
					bzfs_free(buf, size);
					return (error);
				}
				sahdrp = buf;
			} else {
				return (EIO);
			}
		}
		hdrsize = SA_HDR_SIZE(sahdrp);
		sb->st_mode = *(uint64_t *)((char *)sahdrp + hdrsize +
		    SA_MODE_OFFSET);
		sb->st_uid = *(uint64_t *)((char *)sahdrp + hdrsize +
		    SA_UID_OFFSET);
		sb->st_gid = *(uint64_t *)((char *)sahdrp + hdrsize +
		    SA_GID_OFFSET);
		sb->st_size = *(uint64_t *)((char *)sahdrp + hdrsize +
		    SA_SIZE_OFFSET);
		bzfs_free(buf, size);
	}

	return (0);
}

#define	SA_SYMLINK_OFFSET	160

static int
bzfs_dnode_readlink(dnode_phys_t *dn, char *path, size_t psize)
{
	int rc = 0;

	if (dn->dn_bonustype == DMU_OT_SA) {
		sa_hdr_phys_t *sahdrp = NULL;
		size_t size = 0;
		void *buf = NULL;
		int hdrsize;
		char *p;

		if (dn->dn_bonuslen != 0) {
			sahdrp = (sa_hdr_phys_t *)DN_BONUS(dn);
		} else {
			blkptr_t *bp;

			if ((dn->dn_flags & DNODE_FLAG_SPILL_BLKPTR) == 0)
				return (EIO);
			bp = DN_SPILL_BLKPTR(dn);

			size = BP_GET_LSIZE(bp);
			buf = bzfs_alloc(size);
			rc = bzfs_read_bp(bp, buf);
			if (rc != 0) {
				bzfs_free(buf, size);
				return (rc);
			}
			sahdrp = buf;
		}
		hdrsize = SA_HDR_SIZE(sahdrp);
		p = (char *)((uintptr_t)sahdrp + hdrsize + SA_SYMLINK_OFFSET);
		bcopy(p, path, psize);
		bzfs_free(buf, size);
		return (0);
	}
	/*
	 * Second test is purely to silence bogus compiler
	 * warning about accessing past the end of dn_bonus.
	 */
	if (psize + sizeof (znode_phys_t) <= dn->dn_bonuslen &&
	    sizeof (znode_phys_t) <= sizeof (dn->dn_bonus)) {
		bcopy(&dn->dn_bonus[sizeof (znode_phys_t)], path, psize);
	} else {
		rc = bzfs_dnode_read(dn, 0, path, psize);
	}
	return (rc);
}

struct obj_list {
	uint64_t		objnum;
	STAILQ_ENTRY(obj_list)	entry;
};

/*
 * Lookup a file and return its dnode.
 */
static int
bzfs_lookup(const char *upath, dnode_phys_t *dnode)
{
	int rc;
	uint64_t objnum;
	dnode_phys_t dn;
	const char *p, *q;
	char element[256];
	char path[1024];
	int symlinks_followed = 0;
	struct bootstat sb;
	struct obj_list *entry, *tentry;
	STAILQ_HEAD(, obj_list) on_cache = STAILQ_HEAD_INITIALIZER(on_cache);

	if (mount->objset.os_type != DMU_OST_ZFS) {
		return (EIO);
	}

	entry = bzfs_alloc(sizeof (struct obj_list));

	/*
	 * Get the root directory dnode.
	 */
	rc = bzfs_objset_get_dnode(&mount->objset, MASTER_NODE_OBJ, &dn);
	if (rc != 0) {
		bzfs_free(entry, sizeof (struct obj_list));
		return (rc);
	}

	rc = bzfs_zap_lookup(&dn, ZFS_ROOT_OBJ, sizeof (objnum), 1, &objnum);
	if (rc != 0) {
		bzfs_free(entry, sizeof (struct obj_list));
		return (rc);
	}
	entry->objnum = objnum;
	STAILQ_INSERT_HEAD(&on_cache, entry, entry);

	rc = bzfs_objset_get_dnode(&mount->objset, objnum, &dn);
	if (rc != 0)
		goto done;

	p = upath;
	while (p != NULL && *p != '\0') {
		rc = bzfs_objset_get_dnode(&mount->objset, objnum, &dn);
		if (rc != 0)
			goto done;

		while (*p == '/')
			p++;
		if (*p == '\0')
			break;
		q = p;
		while (*q != '\0' && *q != '/')
			q++;

		/* skip dot */
		if (p + 1 == q && p[0] == '.') {
			p++;
			continue;
		}
		/* double dot */
		if (p + 2 == q && p[0] == '.' && p[1] == '.') {
			p += 2;
			if (STAILQ_FIRST(&on_cache) ==
			    STAILQ_LAST(&on_cache, obj_list, entry)) {
				rc = ENOENT;
				goto done;
			}
			entry = STAILQ_FIRST(&on_cache);
			STAILQ_REMOVE_HEAD(&on_cache, entry);
			bzfs_free(entry, sizeof (struct obj_list));
			objnum = (STAILQ_FIRST(&on_cache))->objnum;
			continue;
		}
		if (q - p + 1 > sizeof (element)) {
			rc = ENAMETOOLONG;
			goto done;
		}
		bcopy(p, element, q - p);
		element[q - p] = 0;
		p = q;

		if ((rc = bzfs_dnode_stat(&dn, &sb)) != 0)
			goto done;
		if (!S_ISDIR(sb.st_mode)) {
			rc = ENOTDIR;
			goto done;
		}

		rc = bzfs_zap_lookup(&dn, element, sizeof (objnum), 1, &objnum);
		if (rc != 0)
			goto done;
		objnum = ZFS_DIRENT_OBJ(objnum);

		entry = bzfs_alloc(sizeof (struct obj_list));
		entry->objnum = objnum;
		STAILQ_INSERT_HEAD(&on_cache, entry, entry);
		rc = bzfs_objset_get_dnode(&mount->objset, objnum, &dn);
		if (rc != 0)
			goto done;

		/*
		 * Check for symlink.
		 */
		rc = bzfs_dnode_stat(&dn, &sb);
		if (rc != 0)
			goto done;
		if (S_ISLNK(sb.st_mode)) {
			if (symlinks_followed > 10) {
				rc = EMLINK;
				goto done;
			}
			symlinks_followed++;

			/*
			 * Read the link value and copy the tail of our
			 * current path onto the end.
			 */
			if (sb.st_size + strlen(p) + 1 > sizeof (path)) {
				rc = ENAMETOOLONG;
				goto done;
			}
			strcpy(&path[sb.st_size], p);

			rc = bzfs_dnode_readlink(&dn, path, sb.st_size);
			if (rc != 0)
				goto done;

			/*
			 * Restart with the new path, starting either at
			 * the root or at the parent depending whether or
			 * not the link is relative.
			 */
			p = path;
			if (*p == '/') {
				while (STAILQ_FIRST(&on_cache) !=
				    STAILQ_LAST(&on_cache, obj_list, entry)) {
					entry = STAILQ_FIRST(&on_cache);
					STAILQ_REMOVE_HEAD(&on_cache, entry);
					bzfs_free(entry,
					    sizeof (struct obj_list));
				}
			} else {
				entry = STAILQ_FIRST(&on_cache);
				STAILQ_REMOVE_HEAD(&on_cache, entry);
				bzfs_free(entry, sizeof (struct obj_list));
			}
			objnum = (STAILQ_FIRST(&on_cache))->objnum;
		}
	}

	*dnode = dn;
done:
	STAILQ_FOREACH_SAFE(entry, &on_cache, entry, tentry)
		bzfs_free(entry, sizeof (struct obj_list));
	return (rc);
}

/*
 * Locate and check pool config from label. We only read first copy.
 *
 * returns 0 on success, -1 on error.
 */
static int
bzfs_mountroot(char *str __unused)
{
	fileid_t filep;
	char *nv;
	struct nvdata_phys *nvdata;
	vdev_label_t *label;
	uint32_t len;
	uint64_t value;
	struct rd_vdev *vd;
	uberblock_t ub;
	char *name = NULL;

	filep.fi_blocknum = 0;
	filep.fi_count = sizeof (vdev_label_t);
	filep.fi_memp = NULL;
	if (diskread(&filep) != 0)
		return (-1);

	/* Use first 16k of label reserved area for state data */
	mount = (struct bzfs_mount *)filep.fi_memp;
	bzfs_zfs_init_crc();
	TAILQ_INIT(&mount->open_files);

	/*
	 * Use bootblock area (3.5MB) for caches.
	 * We do not support large block feature for boot pool
	 * (one can always zpool upgrade), so we use 128k blocks for caches.
	 */
	mount->dnode_cache_buf = filep.fi_memp + VDEV_BOOT_OFFSET;
	mount->zap_scratch = mount->dnode_cache_buf + SPA_OLD_MAXBLOCKSIZE;
	mount->zfs_temp_buf = mount->zap_scratch + SPA_OLD_MAXBLOCKSIZE;
	mount->zfs_temp_ptr = mount->zfs_temp_buf;
	mount->zfs_temp_end = mount->zfs_temp_buf + VDEV_BOOT_SIZE -
	    (2 * SPA_OLD_MAXBLOCKSIZE);

	label = (vdev_label_t *)filep.fi_memp;
	nv = &label->vl_vdev_phys.vp_nvlist[0];

	/* Tests. Try to read txg and pool name. */
	nvdata = nv_lookup(nv + 12, ZPOOL_CONFIG_POOL_TXG, DATA_TYPE_UINT64);
	if (nvdata == NULL) {
		return (-1);
	}
	value = ntohll(*(uint64_t *)(nvdata->data));
	if (value == 0) {
		return (-1);
	}
	nvdata = nv_lookup(nv + 12, ZPOOL_CONFIG_POOL_NAME, DATA_TYPE_STRING);
	if (nvdata == NULL) {
		return (-1);
	}
	struct nvstring *nvs = (struct nvstring *)nvdata->data;
	len = ntohl(nvs->size);
	name = nvs->data;
	if (bootrd_debug)
		kobj_printf("boot pool: %*s\n", len, name);
	mount->label = nv;
	mount->vroot.vdev_top = NULL;
	mount->vroot.vdev_ashift = 9;	/* We only do use 512B */
	mount->vdev.vdev_top = &mount->vroot;
	mount->vdev.vdev_ashift = 9;
	vd = &mount->vdev;
	bzero(&mount->ub, sizeof (mount->ub));

	/*
	 * We need to have copy of ub there, because we need to
	 * byteswap the data.
	 */
	for (int n = 0; n < VDEV_UBERBLOCK_COUNT(vd); n++) {
		bcopy(&label->vl_uberblock[n << VDEV_UBERBLOCK_SHIFT(vd)],
		    &ub, sizeof (ub));
		if (bzfs_uberblock_verify(&ub) != 0)
			continue;
		if (bzfs_uberblock_compare(&ub, &mount->ub) > 0)
			mount->ub = ub;
	}

	/* Did we get UB? */
	if (mount->ub.ub_magic != UBERBLOCK_MAGIC)
		return (-1);

	/* Finally, get root dataset */
	if (bzfs_read_bp(&mount->ub.ub_rootbp, &mount->mos) != 0)
		return (-1);

	/*
	 * Get bootfs or root dataset if bootfs is not set.
	 */
	if (bzfs_get_root(&mount->objset) != 0)
		return (-1);

	/*
	 * If we are requested to use ramdisk as rootfs,
	 * provide "zfs-bootpool", "zfs-bootvdev" and "zfs-bootfs" properties.
	 *
	 * I think it is enough to check if the "zfs-rootdisk-path"
	 * property exists.
	 */
	if (BOP_GETPROPLEN(ops, "zfs-rootdisk-path") > 0) {
		/* space for pool name + / + guid + NUL */
		char buf[MAXNAMELEN + 20 + 2];

		nvdata = nv_lookup(nv + 12, ZPOOL_CONFIG_POOL_GUID,
		    DATA_TYPE_UINT64);
		if (nvdata == NULL) {
			return (-1);
		}
		value = ntohll(*(uint64_t *)(nvdata->data));
		(void) snprintf(buf, sizeof (buf), "%lu", value);
		BOP_SETPROP(ops, "zfs-bootpool", buf);
		(void) snprintf(buf, sizeof (buf), "%*s/%lu",
		    len, name, mount->rootfs);
		BOP_SETPROP(ops, "zfs-bootfs", buf);

		/*
		 * for "zfs-bootvdev", we need vdev_tree and from it the
		 * children. By nature, missing data there is not
		 * fatal in context of bootrd, but it would indicate
		 * broken pool config - so we will error out anyhow.
		 */
		nvdata = nv_lookup(nv + 12, ZPOOL_CONFIG_VDEV_TREE,
		    DATA_TYPE_NVLIST);
		if (nvdata == NULL) {
			return (-1);
		}
		nvdata = nv_lookup(nvdata->data + 8, ZPOOL_CONFIG_GUID,
		    DATA_TYPE_UINT64);
		if (nvdata == NULL) {
			return (-1);
		}
		value = ntohll(*(uint64_t *)(nvdata->data));
		(void) snprintf(buf, sizeof (buf), "%lu", value);
		BOP_SETPROP(ops, "zfs-bootvdev", buf);
	}
	return (0);
}

static int
bzfs_unmountroot(void)
{
	return (0);
}

static int
bzfs_open(char *filename, int flags __unused)
{
	struct filei *fp, *p;

	fp = bzfs_alloc(sizeof (*fp));
	fp->fd = 0;
	TAILQ_FOREACH(p, &mount->open_files, next) {
		if (p->fd > fp->fd)
			break;
		fp->fd++;
	}
	fp->off = 0;
	if (bzfs_lookup(filename, &fp->dnode) != 0) {
		bzfs_free(fp, sizeof (*fp));
		return (-1);
	}

	if (bzfs_dnode_stat(&fp->dnode, &fp->stat) != 0) {
		bzfs_free(fp, sizeof (*fp));
		return (-1);
	}

	if (TAILQ_EMPTY(&mount->open_files)) {
		TAILQ_INSERT_HEAD(&mount->open_files, fp, next);
		return (0);
	}

	if (p != NULL)
		TAILQ_INSERT_BEFORE(p, fp, next);
	else
		TAILQ_INSERT_TAIL(&mount->open_files, fp, next);

	return (fp->fd);
}

static struct filei *
bzfs_get_filei(int fd)
{
	struct filei *fp;

	TAILQ_FOREACH(fp, &mount->open_files, next) {
		if (fp->fd == fd)
			break;
	}
	return (fp);
}

static int
bzfs_close(int fd)
{
	struct filei *fp = bzfs_get_filei(fd);

	if (fp == NULL)
		return (-1);

	TAILQ_REMOVE(&mount->open_files, fp, next);
	bzfs_free(fp, sizeof (*fp));
	return (0);
}

static ssize_t
bzfs_read(int fd, caddr_t buf, size_t size)
{
	struct filei *fp = bzfs_get_filei(fd);

	if (fp == NULL)
		return (-1);

	if (size == 0)
		return (0);

	if (fp->off + size > fp->stat.st_size)
		size = fp->stat.st_size - fp->off;

	if (bzfs_dnode_read(&fp->dnode, fp->off, buf, size) != 0)
		return (-1);
	fp->off += size;
	return (size);
}

static off_t
bzfs_lseek(int fd, off_t addr, int whence)
{
	struct filei *fp = bzfs_get_filei(fd);

	if (fp == NULL)
		return (-1);

	switch (whence) {
	case SEEK_CUR:
		fp->off += addr;
		break;
	case SEEK_SET:
		fp->off = addr;
		break;
	case SEEK_END:
		fp->off = fp->stat.st_size;
		break;
	default:
		return (-1);
	}

	return (0);
}

static int
bzfs_fstat(int fd, struct bootstat *buf)
{
	struct filei *fp = bzfs_get_filei(fd);

	if (fp == NULL)
		return (-1);

	*buf = fp->stat;
	return (0);
}

static void
bzfs_closeall(int flag __unused)
{
	struct filei *fp;

	while (!TAILQ_EMPTY(&mount->open_files)) {
		fp = TAILQ_FIRST(&mount->open_files);
		(void) bzfs_close(fp->fd);
	}
}

struct boot_fs_ops bzfs_ops = {
	.fsw_name = "boot_zfs",
	.fsw_mountroot = bzfs_mountroot,
	.fsw_unmountroot = bzfs_unmountroot,
	.fsw_open = bzfs_open,
	.fsw_close = bzfs_close,
	.fsw_read = bzfs_read,
	.fsw_lseek = bzfs_lseek,
	.fsw_fstat = bzfs_fstat,
	.fsw_closeall = bzfs_closeall,
};
