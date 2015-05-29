/*
    Marvell PXA9XX ACIPC-MSOCKET driver for Linux
    Copyright (C) 2010 Marvell International Ltd.

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License version 2 as
    published by the Free Software Foundation.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef PSD_SHM_V2_H_
#define PSD_SHM_V2_H_

#include <linux/types.h>
#include <asm/byteorder.h>

/*
 * interface between AP and CP
 */

#define PSD_UL_CH_CNT (8)
#define PSD_DL_CH_CNT (8)
#define PSD_UL_CH_TOTAL_LEN (2 * PSD_UL_CH_CNT * 512)
#define PSD_DL_CH_TOTAL_LEN (2048)
#define PSD_UF_CH_TOTAL_LEN (2 * 4 * 512)
#define PSD_DF_CH_TOTAL_LEN (PSD_DL_CH_TOTAL_LEN)
#define INVALID_CID (0xff)

#define PSD_CACHELINE_SIZE (64)

#define SLOT_FREE_FLAG (0x66524565) /* fREe */

struct channel_info {
	/* bitmap, each channel has one bit, close = 0 open = 1 */
	u16 ap_chan_status;
	u16 cp_chan_status;
	u16 resv1[30];
	/* MSB(bit 15) is SIM id, 0 - SIM1, 1 - SIM2, not supported */
	u16 chan_cid[PSD_UL_CH_CNT];
	/* reserved */
	u16 chan_qci[PSD_DL_CH_CNT];
	/* ul default priority channel length */
	u16 ul_defl_chan_len[PSD_UL_CH_CNT];
	/* ul high priority channel length */
	u16 ul_high_chan_len[PSD_UL_CH_CNT];
};

/*
 *
 * psd pdu format
 *
|                                                     |
|<--------------------- PSD PDU --------------------->|
|                                                     |
+-----------------+-----------------+-----------------+
|                 |                 |                 |
| extended header |  padding data   |   packet data   |
| (exthdr_length) | (packet_offset) | (packet_length) |
|                 |                 |                 |
+-----------------+-----------------+-----------------+
 *
 */

struct ul_descriptor {
	/* offset between buffer address and shm start address */
	u32 buffer_offset;
	/* extended header length */
	u8 exhdr_length;
	/* offset between actual data and buffer start address */
	u8 packet_offset;
	/* actual packet length */
	u16 packet_length;
#if defined(__LITTLE_ENDIAN_BITFIELD)
	u8 cid:7;
	/* sim id: 0 SIM1, 1 SIM2 */
	u8 simid:1;
#elif defined(__BIG_ENDIAN_BITFIELD)
	/* sim id: 0 SIM1, 1 SIM2 */
	u8 simid:1;
	u8 cid:7;
#else
#error "incorrect endian"
#endif
	u8 reserved[3];
};

struct dl_descriptor {
	/* offset between buffer address and shm start address */
	u32 buffer_offset;
	/* extended header length */
	u8 exhdr_length;
	/* offset between actual data and buffer start address */
	u8 packet_offset;
	/* actual packet length */
	u16 packet_length;
#if defined(__LITTLE_ENDIAN_BITFIELD)
	u8 cid:7;
	/* sim id: 0 SIM1, 1 SIM2 */
	u8 simid:1;
#elif defined(__BIG_ENDIAN_BITFIELD)
	/* sim id: 0 SIM1, 1 SIM2 */
	u8 simid:1;
	u8 cid:7;
#else
#error "incorrect endian"
#endif
	u8 reserved[3];
};

struct free_descriptor {
	/* offset between buffer address and shm start address */
	u32 buffer_offset;
	/* buffer length */
	u16 length;
	u16 reserved;
};

struct ul_skctl {
	union {
		struct {
			u16 defl_wptr[PSD_UL_CH_CNT];
			u16 high_wptr[PSD_UL_CH_CNT];
			u16 free_rptr;
		};
		u8 resv1[PSD_CACHELINE_SIZE];
	};
	union {
		struct {
			u16 defl_rptr[PSD_UL_CH_CNT];
			u16 high_rptr[PSD_UL_CH_CNT];
			u16 free_wptr;
			/* used to reduce interrupt, 1: remote is receiving */
			u16 active;
		};
		u8 resv2[PSD_CACHELINE_SIZE];
	};
	/*
	 * the descriptor pool
	 * default priority channel first, then high priority channels
	 */
	struct ul_descriptor desc[PSD_UL_CH_TOTAL_LEN];
	struct free_descriptor free_desc[PSD_UF_CH_TOTAL_LEN];
};

struct dl_skctl {
	union {
		struct {
			u16 wptr;
			u16 free_rptr;
		};
		u8 resv1[PSD_CACHELINE_SIZE];
	};
	union {
		struct {
			u16 rptr;
			u16 free_wptr;
			/* used to reduce interrupt, 1: remote is receiving */
			u16 active;
		};
		u8 resv2[PSD_CACHELINE_SIZE];
	};
	struct dl_descriptor desc[PSD_DL_CH_TOTAL_LEN];
	struct free_descriptor free_desc[PSD_DF_CH_TOTAL_LEN];
};

struct psd_skctl {
	struct channel_info ci;
	struct ul_skctl us;
	struct dl_skctl ds;
};

#endif /* PSD_SHM_V2_H_ */
