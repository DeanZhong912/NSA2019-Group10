/*****************************************************************************
 *
 * Copyright (C) 2001 Uppsala University and Ericsson AB.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Author: Erik Nordström, <erik.nordstrom@it.uu.se>
 *
 *****************************************************************************/
#ifndef _KAODV_EXPL_H
#define _KAODV_EXPL_H

#ifdef __KERNEL__

#include <linux/list.h>

struct expl_entry {        //路由表信息到期列表
	struct list_head l;
	unsigned long expires;  //到期时间
	unsigned short flags;
	__u32 daddr;//__u32这个变量占4字节         目的地址
	__u32 nhop; //下一跳
	int ifindex;//编号
};

void kaodv_expl_init(void);//初始化
void kaodv_expl_flush(void);//对内核中的expl表清空
int kaodv_expl_get(__u32 daddr, struct expl_entry *e_in);//按目的地址读取内核中的表项
int kaodv_expl_add(__u32 daddr, __u32 nhop, unsigned long time,
		   unsigned short flags, int ifindex);//添加表项
int kaodv_expl_update(__u32 daddr, __u32 nhop, unsigned long time,
		      unsigned short flags, int ifindex);//表项更新

int kaodv_expl_del(__u32 daddr);//按目的地址删除expl表项
void kaodv_expl_fini(void);

#endif				/* __KERNEL__ */

#endif				/* _KAODV_EXPL_H */
