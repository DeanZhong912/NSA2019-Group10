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

#include <time.h>

#ifdef NS_PORT
#include "ns-2/aodv-uu.h"
#else
#include "defs.h"
#include "aodv_timeout.h"
#include "aodv_socket.h"
#include "aodv_neighbor.h"
#include "aodv_rreq.h"
#include "aodv_hello.h"
#include "aodv_rerr.h"
#include "timer_queue.h"
#include "debug.h"
#include "params.h"
#include "routing_table.h"
#include "seek_list.h"
#include "nl.h"

extern int expanding_ring_search, local_repair;
void route_delete_timeout(void *arg);//路由删除超时

#endif

/* These are timeout functions which are called when timers expire... */

void NS_CLASS route_discovery_timeout(void *arg)//路由发现超时
{
	struct timeval now;
	seek_list_t *seek_entry;
	rt_table_t *rt, *repair_rt;
	seek_entry = (seek_list_t *) arg;

#define TTL_VALUE seek_entry->ttl

	/* Sanity check... */
	if (!seek_entry)
		return;

	gettimeofday(&now, NULL);

	DEBUG(LOG_DEBUG, 0, "%s", ip_to_str(seek_entry->dest_addr));

	if (seek_entry->reqs < RREQ_RETRIES) {

		if (expanding_ring_search) {//是否禁用扩展环搜索RREQs

			if (TTL_VALUE < TTL_THRESHOLD)//7
				TTL_VALUE += TTL_INCREMENT;//2
			else {
				TTL_VALUE = NET_DIAMETER;//35
				seek_entry->reqs++;
			}
			/* Set a new timer for seeking this destination */
			timer_set_timeout(&seek_entry->seek_timer,
					  RING_TRAVERSAL_TIME);//2 * NODE_TRAVERSAL_TIME * (TTL_VALUE + TIMEOUT_BUFFER)
		} else {
			seek_entry->reqs++;
			timer_set_timeout(&seek_entry->seek_timer,
					  seek_entry->reqs * 2 *
					  NET_TRAVERSAL_TIME);
		}
		/* AODV should use a binary exponential backoff RREP waiting
		   time. */
		DEBUG(LOG_DEBUG, 0, "Seeking %s ttl=%d wait=%d",
		      ip_to_str(seek_entry->dest_addr),
		      TTL_VALUE, 2 * TTL_VALUE * NODE_TRAVERSAL_TIME);

		/* A routing table entry waiting for a RREP should not be expunged
		   before 2 * NET_TRAVERSAL_TIME... */
		rt = rt_table_find(seek_entry->dest_addr);//找到目的地址的路由表项

		if (rt && timeval_diff(&rt->rt_timer.timeout, &now) <
		    (2 * NET_TRAVERSAL_TIME))
			rt_table_update_timeout(rt, 2 * NET_TRAVERSAL_TIME);//设置发现超时的时限为2 * NET_TRAVERSAL_TIME

		rreq_send(seek_entry->dest_addr, seek_entry->dest_seqno,
			  TTL_VALUE, seek_entry->flags);//发送rreq消息

	} else {

		DEBUG(LOG_DEBUG, 0, "NO ROUTE FOUND!");

#ifdef NS_PORT
		packet_queue_set_verdict(seek_entry->dest_addr, PQ_DROP);//包队列设置判断
#else
		nl_send_no_route_found_msg(seek_entry->dest_addr);//发出没有找到的信息
#endif
		repair_rt = rt_table_find(seek_entry->dest_addr);//找到超时的路由表项，并赋值

		seek_list_remove(seek_entry);

		/* If this route has been in repair, then we should timeout
		   the route at this point. */
		if (repair_rt && (repair_rt->flags & RT_REPAIR)) {//如果节点处于修复状态
			DEBUG(LOG_DEBUG, 0, "REPAIR for %s failed!",//打印修复失败消息
			      ip_to_str(repair_rt->dest_addr));
			local_repair_timeout(repair_rt);//本地修复超时
		}
	}
}

void NS_CLASS local_repair_timeout(void *arg)//本地修复超时函数
{
	rt_table_t *rt;
	struct in_addr rerr_dest;
	RERR *rerr = NULL;//错误消息

	rt = (rt_table_t *) arg;

	if (!rt)
		return;

	rerr_dest.s_addr = AODV_BROADCAST;	/* Default destination *///错误信息广播到所有节点

	/* Unset the REPAIR flag */
	rt->flags &= ~RT_REPAIR;//修复中

#ifndef NS_PORT
	nl_send_del_route_msg(rt->dest_addr, rt->next_hop, rt->hcnt);//发送删除路由的信息
#endif
	/* Route should already be invalidated. */

	if (rt->nprec) {//nprec为先驱表的数量

		rerr = rerr_create(0, rt->dest_addr, rt->dest_seqno);//创建错误数据

		if (rt->nprec == 1) {
			rerr_dest = FIRST_PREC(rt->precursors)->neighbor;//只有一个先驱表时，错误消息发给它的邻居

			aodv_socket_send((AODV_msg *) rerr, rerr_dest,
					 RERR_CALC_SIZE(rerr), 1,
					 &DEV_IFINDEX(rt->ifindex));
		} else {
			int i;

			for (i = 0; i < MAX_NR_INTERFACES; i++) {//10
				if (!DEV_NR(i).enabled)
					continue;
				aodv_socket_send((AODV_msg *) rerr, rerr_dest,
						 RERR_CALC_SIZE(rerr), 1,
						 &DEV_NR(i));
			}
		}
		DEBUG(LOG_DEBUG, 0, "Sending RERR about %s to %s",
		      ip_to_str(rt->dest_addr), ip_to_str(rerr_dest));
	}
	precursor_list_destroy(rt);//销毁先驱表

	/* Purge any packets that may be queued */
	/* packet_queue_set_verdict(rt->dest_addr, PQ_DROP); */

	rt->rt_timer.handler = &NS_CLASS route_delete_timeout;
	timer_set_timeout(&rt->rt_timer, DELETE_PERIOD);//delete_period = DELETE_PERIOD_HELLO;

	DEBUG(LOG_DEBUG, 0, "%s removed in %u msecs",
	      ip_to_str(rt->dest_addr), DELETE_PERIOD);
}


void NS_CLASS route_expire_timeout(void *arg)//路由到期超时，即很久没收到hello消息默认废除此条路由
{
	rt_table_t *rt;

	rt = (rt_table_t *) arg;

	if (!rt) {
		alog(LOG_WARNING, 0, __FUNCTION__,
		     "arg was NULL, ignoring timeout!");
		return;
	}

	DEBUG(LOG_DEBUG, 0, "Route %s DOWN, seqno=%d",
	      ip_to_str(rt->dest_addr), rt->dest_seqno);

	if (rt->hcnt == 1)
		neighbor_link_break(rt);//邻居节点断开
	else {
		rt_table_invalidate(rt);//将其无效化
		precursor_list_destroy(rt);//先驱表销毁
	}

	return;
}

void NS_CLASS route_delete_timeout(void *arg)//路由删除超时
{
	rt_table_t *rt;

	rt = (rt_table_t *) arg;

	/* Sanity check: */
	if (!rt)
		return;

	DEBUG(LOG_DEBUG, 0, "%s", ip_to_str(rt->dest_addr));

	rt_table_delete(rt);//删除操作
}

/* This is called when we stop receiveing hello messages from a
   node. For now this is basically the same as a route timeout. */
void NS_CLASS hello_timeout(void *arg)//hello消息超时
{
	rt_table_t *rt;
	struct timeval now;

	rt = (rt_table_t *) arg;

	if (!rt)
		return;

	gettimeofday(&now, NULL);

	DEBUG(LOG_DEBUG, 0, "LINK/HELLO FAILURE %s last HELLO: %d",
	      ip_to_str(rt->dest_addr), timeval_diff(&now,
						     &rt->last_hello_time));//计算当前时间和最后一次发送hello消息的时间差，来判断有没有超时

	if (rt && rt->state == VALID && !(rt->flags & RT_UNIDIR)) {

		/* If the we can repair the route, then mark it to be
		   repaired.. */
		if (local_repair && rt->hcnt <= MAX_REPAIR_TTL) {//3 * NET_DIAMETER / 10
			rt->flags |= RT_REPAIR;
			DEBUG(LOG_DEBUG, 0, "Marking %s for REPAIR",
			      ip_to_str(rt->dest_addr));
#ifdef NS_PORT
			/* Buffer pending packets from interface queue */
			interfaceQueue((nsaddr_t) rt->dest_addr.s_addr,
				       IFQ_BUFFER);
#endif
		}
		neighbor_link_break(rt);
	}
}

void NS_CLASS rrep_ack_timeout(void *arg)//路由回复超时
{
	rt_table_t *rt;

	/* We must be really sure here, that this entry really exists at
	   this point... (Though it should). */
	rt = (rt_table_t *) arg;

	if (!rt)
		return;

	/* When a RREP transmission fails (i.e. lack of RREP-ACK), add to
	   blacklist set... */
	rreq_blacklist_insert(rt->dest_addr);//插入到路由请求黑名单

	DEBUG(LOG_DEBUG, 0, "%s", ip_to_str(rt->dest_addr));
}

void NS_CLASS wait_on_reboot_timeout(void *arg)//重启等待超时
{
	*((int *) arg) = 0;

	DEBUG(LOG_DEBUG, 0, "Wait on reboot over!!");
}

#ifdef NS_PORT
void NS_CLASS packet_queue_timeout(void *arg)//数据包等待超时
{
	packet_queue_garbage_collect();
	timer_set_timeout(&PQ.garbage_collect_timer, GARBAGE_COLLECT_TIME);
}
#endif
