/*
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

#ifndef SHMEM_M3_H_
#define SHMEM_M3_H_

struct rm_m3_addr;
int m3_shm_ch_init(const struct rm_m3_addr *addr);
void m3_shm_ch_deinit(void);
int m3_ioctl_handler(unsigned int cmd, unsigned long arg);

extern struct portq_group pgrp_m3;

#endif /* SHMEM_M3_H_ */
