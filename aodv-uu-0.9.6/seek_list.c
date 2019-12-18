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
 * Authors: Erik Nordstr�m, <erik.nordstrom@it.uu.se>
 *          
 *
 *****************************************************************************/
#include <stdlib.h>

#ifdef NS_PORT
#include "ns-2/aodv-uu.h"
#include "list.h"
#else
#include "seek_list.h"
#include "timer_queue.h"
#include "aodv_timeout.h"
#include "defs.h"
#include "params.h"
#include "debug.h"
#include "list.h"
#endif

#ifndef NS_PORT
/* The seek list is a linked list of destinations we are seeking
   (with RREQ's). */

static LIST(seekhead);

#ifdef SEEK_LIST_DEBUG
void seek_list_print();//打印查找列表
#endif
#endif				/* NS_PORT */

seek_list_t *NS_CLASS seek_list_insert(struct in_addr dest_addr,//向查找列表中插入节点
				       u_int32_t dest_seqno,
				       int ttl, u_int8_t flags,
				       struct ip_data *ipd)
{
    seek_list_t *entry;

    if ((entry = (seek_list_t *) malloc(sizeof(seek_list_t))) == NULL) {
	fprintf(stderr, "Failed malloc\n");//开辟空间
	exit(-1);
    }

    entry->dest_addr = dest_addr;
    entry->dest_seqno = dest_seqno;
    entry->flags = flags;
    entry->reqs = 0;
    entry->ttl = ttl;
    entry->ipd = ipd;//赋值操作

    timer_init(&entry->seek_timer, &NS_CLASS route_discovery_timeout, entry);//定时器初始化

    list_add(&seekhead, &entry->l);//链表加入
#ifdef SEEK_LIST_DEBUG
    seek_list_print();//打印函数
#endif
    return entry;
}

int NS_CLASS seek_list_remove(seek_list_t * entry)//从查找链表中移除节点
{
    if (!entry)//空节点处理
	return 0;

    list_detach(&entry->l);//将entry设置为独立节点，保证定时器是可移除的

    /* Make sure any timers are removed */
    timer_remove(&entry->seek_timer);将查找时间的定时器移除

    if (entry->ipd)
	free(entry->ipd);

    free(entry);//释放空间
    return 1;
}

seek_list_t *NS_CLASS seek_list_find(struct in_addr dest_addr)//根据目的地址查找节点的函数
{
    list_t *pos;

    list_foreach(pos, &seekhead) {//从头结点向下遍历，直到为空
	seek_list_t *entry = (seek_list_t *) pos;

	if (entry->dest_addr.s_addr == dest_addr.s_addr)//查找到时返回
	    return entry;
    }
    return NULL;
}

#ifdef SEEK_LIST_DEBUG
void NS_CLASS seek_list_print()//打印函数
{
    list_t *pos;

    list_foreach(pos, &seekhead) {//从头向下遍历
	seek_list_t *entry = (seek_list_t *) pos;
	printf("%s %u %d %d\n", ip_to_str(entry->dest_addr),//格式化打印
	       entry->dest_seqno, entry->reqs, entry->ttl);
    }
}
#endif
