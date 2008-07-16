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
#ifndef _NFS4_ATTRMAP_H
#define	_NFS4_ATTRMAP_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef _KERNEL
#ifdef	__cplusplus
extern "C" {
#endif

/*
 * ATTRMAP_SET sets (to 1) bits in tgt_map
 * which are set in mask_map.
 */
#define	ATTRMAP_SET(tgt_map, mask_map) {	\
	(tgt_map).d.d0 |= (mask_map).d.d0;	\
	(tgt_map).d.d1 |= (mask_map).d.d1;	\
}

/*
 * ATTRMAP_CLR clears (sets to 0) bits in tgt_map
 * which are set in mask_map
 */
#define	ATTRMAP_CLR(tgt_map, mask_map) {	\
	(tgt_map).d.d0 &= ~(mask_map).d.d0;	\
	(tgt_map).d.d1 &= ~(mask_map).d.d1;	\
}

/*
 * ATTRMAP_MASK clears (sets to 0) bits in tgt_map
 * which are not set in mask_map
 */
#define	ATTRMAP_MASK(tgt_map, mask_map) {	\
	(tgt_map).d.d0 &= (mask_map).d.d0;	\
	(tgt_map).d.d1 &= (mask_map).d.d1;	\
}

/*
 * ATTRMAP_XOR xors tgt_map and mask_map.
 * Result is stored in tgt_map.
 */
#define	ATTRMAP_XOR(tgt_map, mask_map) {	\
	(tgt_map).d.d0 ^= (mask_map).d.d0;	\
	(tgt_map).d.d1 ^= (mask_map).d.d1;	\
}


/*
 * ATTRMAP_TST evaluates to nonzero if any of the mask_map bits
 * are set in map.
 */
#define	ATTRMAP_TST(map, mask_map)		\
	(((map).d.d0 & (mask_map).d.d0) != 0 ||	\
	    ((map).d.d1 & (mask_map).d.d1) != 0)

/*
 * ATTRMAP_TST_CMPL evaluates to nonzero if any bits not set
 * in mask_map are set in map.  (tests complement of map mask)
 */
#define	ATTRMAP_TST_CMPL(map, mask_map)		\
	(((map).d.d0 & ~((mask_map).d.d0)) != 0 ||	\
	    ((map).d.d1 & ~((mask_map).d.d1)) != 0)

/*
 * ATTRMAP_EQL evaluates to nonzero if both dwords of map1 are
 * equal to both dwords of map2
 */
#define	ATTRMAP_EQL(map1, map2)		\
	((map1).d.d0 == (map2).d.d0 && (map1).d.d1 == (map2).d.d1)

/*
 * ATTRMAP_EMPTY evaluates to nonzero if both map dwords are 0
 * (no bits are set in map)
 */
#define	ATTRMAP_EMPTY(map)	((map).d.d0 == 0 && (map).d.d1 == 0)


#if defined(_BIG_ENDIAN)

struct am4word {
	uint32_t w0;
	uint32_t w1;
	uint32_t w2;
	uint32_t w3;
};

#elif defined(_LITTLE_ENDIAN)

struct am4word {
	uint32_t w1;
	uint32_t w0;
	uint32_t w3;
	uint32_t w2;
};

#endif

typedef struct am4word am4word_t;

struct am4dword {
	uint64_t d0;
	uint64_t d1;
};
typedef struct am4dword am4dword_t;


union attrmap4_u {
	am4dword_t	d;
	am4word_t	w;
};
typedef union attrmap4_u attrmap4;

/*
 * The ATTR_* macros take an attrmap4 and the short
 * attribute name.  The short name doesn't include
 * the FATTR4_ prefix (or the _MASK suffix).
 *
 * ATTR_ISSET evaluates to non-zero if the attr_nm is set
 * in the attrmap (am4).
 *
 * ATTR_CLR sets the attr bit in am4 to 0
 *
 * ATTR_SET sets the attr bit in am4 to 1
 */
#define	ATTR_ISSET(am4, attr_nm) \
	(((am4).__dw_##attr_nm & FATTR4_##attr_nm##_MASK) != 0)

#define	ATTR_CLR(am4, attr_nm) \
	(am4).__dw_##attr_nm &= ~(FATTR4_##attr_nm##_MASK)

#define	ATTR_SET(am4, attr_nm) \
	(am4).__dw_##attr_nm |= FATTR4_##attr_nm##_MASK

#ifdef	__cplusplus
}
#endif
#endif /* _KERNEL */
#endif /* _NFS4_ATTRMAP_H */
