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
#ifndef _KAODV_QUEUE_H
#define _KAODV_QUEUE_H

#define KAODV_QUEUE_DROP 1//设置丢弃为1，发送为2
#define KAODV_QUEUE_SEND 2

int kaodv_queue_find(__u32 daddr);//查找
int kaodv_queue_enqueue_packet(struct sk_buff *skb,
			       int (*okfn) (struct sk_buff *));//把packet入队
int kaodv_queue_set_verdict(int verdict, __u32 daddr);//设置命令
void kaodv_queue_flush(void);//清空队列
int kaodv_queue_init(void);//队列初始化
void kaodv_queue_fini(void);//队列清除

#endif
