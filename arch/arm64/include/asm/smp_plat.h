/*
 * Definitions specific to SMP platforms.
 *
 * Copyright (C) 2013 ARM Ltd.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef __ASM_SMP_PLAT_H
#define __ASM_SMP_PLAT_H

#include <linux/cpumask.h>
#include <linux/err.h>
#include <asm/types.h>

struct mpidr_hash {
	u64	mask;
	u32	shift_aff[4];
	u32	bits;
};

extern struct mpidr_hash mpidr_hash;

static inline u32 mpidr_hash_size(void)
{
	return 1 << mpidr_hash.bits;
}

/*
 * Logical CPU mapping.
 */
extern u64 __cpu_logical_map[NR_CPUS];
#define cpu_logical_map(cpu)    __cpu_logical_map[cpu]
/*
 * Retrieve logical cpu index corresponding to a given MPIDR[23:0]
 *  - mpidr: MPIDR[23:0] to be used for the look-up
 *
 * Returns the cpu logical index or -EINVAL on look-up error
 */
static inline int get_logical_index(u32 mpidr)
{
	int cpu;
	for (cpu = 0; cpu < nr_cpu_ids; cpu++)
		if (cpu_logical_map(cpu) == mpidr)
			return cpu;
	return -EINVAL;
}

#define MAX_NR_CLST (2)

struct cpu_clst_info {
	int is_big;
	int clst_index;
	int first_cpu;
	int nr_cpu;
};

struct cpu_clst_info *get_clst_info(int clst_index);

#endif /* __ASM_SMP_PLAT_H */
