/*
    Marvell io device driver for Linux
    Copyright (C) 2015 Marvell International Ltd.

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

#ifndef _CSD_MISC_H_
#define _CSD_MISC_H_

#include <linux/errno.h>
#include <linux/types.h>
#include <linux/spinlock.h>

#include "common_datastub.h"
#include "ci_opt_dat_types.h"
#include "ci_stub_ttc_macro.h"

#define DEF_CID 1

#define TIOPPPON _IOW('T', 208, int)
#define TIOPPPOFF _IOW('T', 209, int)
#define TIOPPPONCSD _IOW('T', 211, int)

static u32 dataSvgHandle;
static DATAHANDLELIST *hCsdataList;
DEFINE_SPINLOCK(data_handle_list_lock);

static int currcid_csd = DEF_CID;
static int get_csd_cid(void)
{
	return currcid_csd;
}

static void set_csd_cid(int cid)
{
	currcid_csd = cid;
}

static void remove_handle_by_cid(DATAHANDLELIST **plist, unsigned char cid)
{
	DATAHANDLELIST *pCurrNode, *pPrevNode;

	pPrevNode = NULL;	/* pPrevNode set to NULL */
	pCurrNode = *plist;	/* pCurrNode set to header */

	/* search list to find which cid equals */
	while (pCurrNode && pCurrNode->handle.m_cid != cid) {
		pPrevNode = pCurrNode;
		pCurrNode = pCurrNode->next;
	}

	if (pCurrNode) {	/* if found it */
		if (!pPrevNode) {	/* first node */
			*plist = pCurrNode->next;
		} else {	/* in the middle */
			pPrevNode->next = pCurrNode->next;
		}

		/* in any case, free node memory */
		kfree(pCurrNode);
	}
	/* else nothing to do */
}

static void add_to_handle_list(DATAHANDLELIST **plist,
			       DATAHANDLELIST *newdrvnode)
{
	/* we add the new node before header */
	newdrvnode->next = *plist;
	*plist = newdrvnode;
}

DATAHANDLELIST *search_handlelist_by_cid(DATAHANDLELIST *pHeader,
					 unsigned char cid)
{
	DATAHANDLELIST *pCurrNode = pHeader;

	while (pCurrNode && pCurrNode->handle.m_cid != cid)
		pCurrNode = pCurrNode->next;

	return pCurrNode;
}

static long ccidatastub_ioctl(struct io_device *iod,
			      unsigned int cmd, unsigned long arg)
{
	DATAHANDLELIST *pNode, **plist;
	struct datahandle_obj dataHandle;
	unsigned char cid;

	if (_IOC_TYPE(cmd) != CCIDATASTUB_IOC_MAGIC) {
		pr_err("ccidatastub_ioctl: cci magic number is wrong!\n");
		return -ENOTTY;
	}

	pr_info("ccidatastub_ioctl,cmd=0x%x\n", cmd);
	switch (cmd) {
	case CCIDATASTUB_DATAHANDLE:
		if (copy_from_user(&dataHandle, (struct datahandle_obj *)arg,
				   sizeof(dataHandle)))
			return -EFAULT;
		pr_info("CCIDATASTUB_DATAHANDLE: cid =%d, type =%d\n",
		       dataHandle.m_cid, dataHandle.m_connType);
		if (dataHandle.m_connType == CI_DAT_CONNTYPE_PS)
			break;

		spin_lock_irq(&data_handle_list_lock);

		plist = &hCsdataList;

		if (!search_handlelist_by_cid(*plist, dataHandle.m_cid)) {
			pNode = kmalloc(sizeof(*pNode), GFP_ATOMIC);
			if (!pNode) {
				spin_unlock_irq(&data_handle_list_lock);
				return -ENOMEM;
			}
			pNode->handle = dataHandle;
			pNode->next = NULL;
			add_to_handle_list(plist, pNode);
		} else {
			pr_info("CCIDATASTUB_DATAHANDLE: cid already exist\n");
		}

		spin_unlock_irq(&data_handle_list_lock);

		break;

	case CCIDATASTUB_DATASVGHANDLE:
		dataSvgHandle = arg;
		pr_info("ccidatastub_ioctl,dataSvgHandle=0x%x\n",
				dataSvgHandle);
		break;

	case CCIDATASTUB_CS_CHNOK:
		cid = (unsigned char)arg;
		pr_info("CCIDATASTUB_CS_CHNOK: cid =%d\n", cid);

		spin_lock_irq(&data_handle_list_lock);
		remove_handle_by_cid(&hCsdataList, cid);
		spin_unlock_irq(&data_handle_list_lock);
		break;
	}
	return 0;
}

long cctdatadev_ioctl(struct io_device *iod, unsigned int cmd,
		unsigned long arg)
{
	switch (cmd) {
	case TIOPPPON:
	case TIOPPPONCSD:
		set_csd_cid(arg);
		break;
	case TIOPPPOFF:
		set_csd_cid(DEF_CID);
		break;
	default:
		pr_debug("cctdatadev_ioctl cmd: %d.\n", cmd);
		return -ENOIOCTLCMD;
	}
	return 0;

}

/* csd skb tx_fixup */
static ssize_t tx_fixup_csd(struct io_device *iod,
		const char __user *data, size_t count,
		struct sk_buff_head *txq, u16 hdr_reserved)
{
	int ret = -1;
	struct sk_buff *skb;
	static UINT32 reqHandle;
	CiDatPduInfo *p_ciPdu;
	CiStubInfo *p_header;
	DATAHANDLELIST *plist, *pNode;
	unsigned long flags;
	unsigned int csd_hdr = sizeof(*p_ciPdu);
	int left = 0, once = 0;
	int slice_len = 160;

	spin_lock_irqsave(&data_handle_list_lock, flags);
	plist = hCsdataList;
	pNode = search_handlelist_by_cid(plist, get_csd_cid());
	if (!pNode) {
		pr_err_ratelimited("sendCsdDataReq: no cid %d!\n",
				get_csd_cid());
		spin_unlock_irqrestore(&data_handle_list_lock, flags);
		ret = -EINVAL;
		goto out_error;
	}
	spin_unlock_irqrestore(&data_handle_list_lock, flags);

	left = count;
	while (left > 0) {
		once = count;
		if (once > slice_len)
			once = slice_len;
		left -= once;

		skb = alloc_skb(once + hdr_reserved + csd_hdr, GFP_KERNEL);
		if (!skb) {
			pr_err("Data_channel: %s: out of memory.\n", __func__);
			ret = -ENOMEM;
			goto out_error;
		}

		skb_reserve(skb, hdr_reserved + csd_hdr);
		if (copy_from_user(skb_put(skb, once), data, once)) {
			kfree_skb(skb);
			pr_err("%s: %s: copy_from_user failed.\n",
				   __func__, iod->name);
			ret = -ENOMEM;
			goto out_error;
		}

		p_ciPdu = (CiDatPduInfo *) skb_push(skb, sizeof(*p_ciPdu));

		p_header = (CiStubInfo *) p_ciPdu->aciHeader;
		p_header->info.type = CI_DATA_PDU;
		p_header->info.param1 = CI_DAT_INTERNAL_BUFFER;
		p_header->info.param2 = 0;
		p_header->info.param3 = 0;
		p_header->gHandle.svcHandle = dataSvgHandle;
		p_header->cHandle.reqHandle = reqHandle++;
		p_ciPdu->ciHeader.connId = get_csd_cid();
		p_ciPdu->ciHeader.connType = CI_DAT_CONNTYPE_CS;
		p_ciPdu->ciHeader.datType = CI_DAT_TYPE_RAW;

		p_ciPdu->ciHeader.isLast = TRUE;
		p_ciPdu->ciHeader.seqNo = 0;
		p_ciPdu->ciHeader.datLen = once;
		p_ciPdu->ciHeader.pPayload = 0;

		skb_queue_tail(txq, skb);
	}
	return count;

out_error:
	while (!skb_queue_empty(txq)) {
		skb = skb_dequeue(txq);
		kfree_skb(skb);
	}
	return ret;
}

int rx_fixup_csd(struct sk_buff *skb)
{
	skb_pull(skb, sizeof(CiDatPrimRecvDataOptInd));
	return 1;
}

#ifdef CONFIG_SSIPC_SUPPORT
static int set_csd_init_cfg(void)
{
	struct datahandle_obj dataHandle;
	DATAHANDLELIST *pNode, **plist;
	spin_lock_irq(&data_handle_list_lock);
	plist = &hCsdataList;
	dataHandle.m_connType = CI_DAT_CONNTYPE_CS;
	dataHandle.connectionType = ATCI_LOCAL;
	dataHandle.m_cid = 0x1;

	if (!search_handlelist_by_cid(*plist, dataHandle.m_cid)) {
		pNode = kmalloc(sizeof(*pNode), GFP_ATOMIC);
		if (!pNode) {
			spin_unlock_irq(&data_handle_list_lock);
			return -ENOMEM;
		}
		pNode->handle = dataHandle;
		pNode->next = NULL;
		add_to_handle_list(plist, pNode);
	} else
		pr_info("%s: cid already exist\n", __func__);

	spin_unlock_irq(&data_handle_list_lock);
	dataSvgHandle = 0x10000008;
	pr_info("%s done\n", __func__);
	return 0;
}
#endif

#endif /* _CSD_MISC_H_ */
