/*
 * Copyright (C) 2015 Marvell International Ltd.
 *		Lisa Du <cldu@marvell.com>
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */
#include <linux/device.h>

struct device *flc_dev;
bool flc_available __read_mostly;

void set_flc_dev(struct device *dev)
{
	flc_dev = dev;
}
