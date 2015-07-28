#ifndef __FLC_H__
#define __FLC_H__

#ifdef CONFIG_FLC
/* Now FLC cache line is designed as 32KB = 4KB * 8 */
#define FLC_ENTRY_SHIFT		(15)	/* 32KB */
#define	FLC_ENTRY_SIZE		(_AC(1, UL) << FLC_ENTRY_SHIFT)
#define FLC_ENTRY_ORDER		(FLC_ENTRY_SHIFT - PAGE_SHIFT)
#define FLC_ENTRY_SIZE_PER_PAGE	(1 << FLC_ENTRY_ORDER)

/* FLC MNT Req, (FLC_MNT_REQ) */
#define FLC_NUM_EVLN_OFFSET	26
#define FLC_NUM_LINE_OFFSET	16
#define FLC_NUM_LINE_LENGTH	(0x3FF)
#define FLC_NUM_LINE_MASK	(FLC_NUM_LINE_LENGTH << 16)
#define FLC_UNLOCK_REQ		(1 << 11)
#define FLC_CLEAN_REQ		(1 << 10)
#define FLC_CLR_DIRTY_REQ	(1 << 9)
#define FLC_CHK_STATE_REQ	(1 << 8)
#define FLC_INVLD_ALL		(1 << 6)
#define FLC_INVLD_CLEAN		(1 << 5)
#define FLC_INVLD_REQ		(1 << 4)
#define FLC_ALLOC_FILLZ		(1 << 3)
#define FLC_ALLOC_LF		(1 << 2)
#define FLC_ALLOC_LOCK		(1 << 1)
#define FLC_ALLOC_REQ		(1 << 0)

extern struct device *flc_dev;
extern bool flc_available;

extern void set_flc_dev(struct device *dev);

/* TO BE DONE: FLC Maintenance APIs */
/* lock/unlock, clean, clear dirty, check state request etc */
static inline int flc_mnt_req(u32 addr, u32 order, u32 req_flags) { return 0; }

#else
static inline void set_flc_dev(struct device *dev){}
static inline int flc_mnt_req(u32 addr, u32 order, u32 req_flags) { return 0; }
#endif

#endif /* __FLC_H__ */
