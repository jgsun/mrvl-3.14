#ifndef __FLC_H__
#define __FLC_H__

#ifdef CONFIG_FLC
extern struct device *flc_dev;
extern bool flc_available;

extern void set_flc_dev(struct device *dev);
#else
static inline void set_flc_dev(struct device *dev){}
#endif

#endif /* __FLC_H__ */
