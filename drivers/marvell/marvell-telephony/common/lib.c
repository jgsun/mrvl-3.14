/*
 * utilities
 *
 * This software program is licensed subject to the GNU General Public License
 * (GPL).Version 2,June 1991, available at http://www.fsf.org/copyleft/gpl.html

 * (C) Copyright 2015 Marvell International Ltd.
 * All Rights Reserved
 */

#include <linux/module.h>
#include <linux/types.h>
#include "lib.h"

void *memset_aligned(void *buf, int c, size_t n)
{
	u64 cc = c & 0xff;
	union {
		long p;
		u8 *p8;
		u16 *p16;
		u32 *p32;
		u64 *p64;
	} addr;

	addr.p8 = buf;

	cc = cc | (cc << 8);
	cc = cc | (cc << 16);
	cc = cc | (cc << 32);

	if (n >= 1 && addr.p & 0x01) {
		*addr.p8++ = cc;
		n--;
	}
	if (n >= 2 && addr.p & 0x02) {
		*addr.p16++ = cc;
		n -= 2;
	}
	if (n >= 4 && addr.p & 0x04) {
		*addr.p32++ = cc;
		n -= 4;
	}

	while (n >= 8) {
		*addr.p64++ = cc;
		n -= 8;
	}

	if (n >= 4) {
		*addr.p32++ = cc;
		n -= 4;
	}
	if (n >= 2) {
		*addr.p16++ = cc;
		n -= 2;
	}
	if (n >= 1) {
		*addr.p8++ = cc;
		n--;
	}

	return buf;
}
EXPORT_SYMBOL(memset_aligned);
