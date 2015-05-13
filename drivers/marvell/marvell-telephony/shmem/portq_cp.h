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

#ifndef SHMEM_CP_H_
#define SHMEM_CP_H_

#include "util.h"

int register_first_cp_synced(struct notifier_block *nb);
void acipc_ap_block_cpuidle_axi(bool block);
int cp_ioctl_handler(unsigned int cmd, unsigned long arg);
DECLARE_BLOCKING_NOTIFIER(cp_link_status);

extern bool cp_is_synced;
extern struct wakeup_source acipc_wakeup;
extern struct portq_group pgrp_cp;

#endif /* SHMEM_CP_H_ */
