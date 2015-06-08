/*
 * Pxa988 series CP Operations header
 *
 * This software program is licensed subject to the GNU General Public License
 * (GPL).Version 2,June 1991, available at http://www.fsf.org/copyleft/gpl.html

 * (C) Copyright 2015 Marvell International Ltd.
 * All Rights Reserved
 */

#ifndef _PXA988_SERIES_H_
#define _PXA988_SERIES_H_

extern void __cp988_releasecp(void);
extern void __cp988_holdcp(void);
extern bool __cp988_get_status(void);

#endif /* _PXA988_SERIES_H_ */
