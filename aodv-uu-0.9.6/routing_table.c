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
 *****************************************************************************/

#include <time.h>

#ifdef NS_PORT
#include "ns-2/aodv-uu.h"
#else
#include "routing_table.h"
#include "aodv_timeout.h"
#include "aodv_rerr.h"
#include "aodv_hello.h"
#include "aodv_socket.h"
#include "aodv_neighbor.h"
#include "timer_queue.h"
#include "defs.h"
#include "debug.h"
#include "params.h"
#include "seek_list.h"
#include "nl.h"
#endif				/* NS_PORT */

static unsigned int hashing(struct in_addr *addr, hash_value * hash);//计算哈希值

extern int llfeedback;

void NS_CLASS rt_table_init()//路由表初始化
{
	int i;

	rt_tbl.num_entries = 0;
	rt_tbl.num_active = 0;

	/* We do a for loop here... NS does not like us to use memset() */
	for (i = 0; i < RT_TABLESIZE; i++) {
		INIT_LIST_HEAD(&rt_tbl.tbl[i]);//用数组对路由表初始化
	}
}

void NS_CLASS rt_table_destroy()//销毁路由表
{
	int i;
	list_t *tmp = NULL, *pos = NULL;

	for (i = 0; i < RT_TABLESIZE; i++) {
		list_foreach_safe(pos, tmp, &rt_tbl.tbl[i]) {//安全遍历
			rt_table_t *rt = (rt_table_t *) pos;

			rt_table_delete(rt);//删除节点
		}
	}
}

/* Calculate a hash value and table index given a key... */
unsigned int hashing(struct in_addr *addr, hash_value * hash)//计算哈希值
{
	/*   *hash = (*addr & 0x7fffffff); */
	*hash = (hash_value) addr->s_addr;

	return (*hash & RT_TABLEMASK);//#define RT_TABLEMASK (RT_TABLESIZE - 1)
}

rt_table_t *NS_CLASS rt_table_insert(struct in_addr dest_addr,//路由表中插入信息
				     struct in_addr next,
				     u_int8_t hops, u_int32_t seqno,
				     u_int32_t life, u_int8_t state,
				     u_int16_t flags, unsigned int ifindex)
{
	hash_value hash;
	unsigned int index;
	list_t *pos;
	rt_table_t *rt;
	struct in_addr nm;
	nm.s_addr = 0;

	/* Calculate hash key */
	index = hashing(&dest_addr, &hash);//计算哈希值

	/* Check if we already have an entry for dest_addr */
	list_foreach(pos, &rt_tbl.tbl[index]) {//从当前位置向后遍历表
		rt = (rt_table_t *) pos;
		if (memcmp(&rt->dest_addr, &dest_addr, sizeof(struct in_addr))//比较buf1和buf2的前count个字节 int memcmp(const void *buf1, const void *buf2, unsigned int count)
		    == 0) {
			DEBUG(LOG_INFO, 0, "%s already exist in routing table!",
			      ip_to_str(dest_addr));//将ip从int型转化为字符串型

			return NULL;
		}
	}

	if ((rt = (rt_table_t *) malloc(sizeof(rt_table_t))) == NULL) {//开辟空间
		fprintf(stderr, "Malloc failed!\n");
		exit(-1);
	}

	memset(rt, 0, sizeof(rt_table_t));//memset(数组名, 值, sizeof(数组名));用于初始化数组

	rt->dest_addr = dest_addr;
	rt->next_hop = next;
	rt->dest_seqno = seqno;
	rt->flags = flags;
	rt->hcnt = hops;
	rt->ifindex = ifindex;
	rt->hash = hash;
	rt->state = state;//赋值操作

	timer_init(&rt->rt_timer, &NS_CLASS route_expire_timeout, rt);

	timer_init(&rt->ack_timer, &NS_CLASS rrep_ack_timeout, rt);

	timer_init(&rt->hello_timer, &NS_CLASS hello_timeout, rt);//初始化操作

	rt->last_hello_time.tv_sec = 0;
	rt->last_hello_time.tv_usec = 0;
	rt->hello_cnt = 0;

	rt->nprec = 0;
	INIT_LIST_HEAD(&rt->precursors);

	/* Insert first in bucket... */

	rt_tbl.num_entries++;

	DEBUG(LOG_INFO, 0, "Inserting %s (bucket %d) next hop %s",
	      ip_to_str(dest_addr), index, ip_to_str(next));//转化格式并检查数据帧格式

	list_add(&rt_tbl.tbl[index], &rt->l);//添加路由表项

	if (state == INVALID) {//若路由无效

		if (flags & RT_REPAIR) {
			rt->rt_timer.handler = &NS_CLASS local_repair_timeout;//修复定时器操作
			life = ACTIVE_ROUTE_TIMEOUT;//active_route_timeout
		} else {
			rt->rt_timer.handler = &NS_CLASS route_delete_timeout;//删除定时器操作
			life = DELETE_PERIOD;//delete_period
		}

	} else {
		rt_tbl.num_active++;//活跃节点数增加
#ifndef NS_PORT
		nl_send_add_route_msg(dest_addr, next, hops, life, flags,
				      ifindex);//用于内核发送增加路由表信息
#endif
	}

#ifdef CONFIG_GATEWAY_DISABLE
	if (rt->flags & RT_GATEWAY)
		rt_table_update_inet_rt(rt, life);//更新插入表项的信息，生存时间
#endif

//#ifdef NS_PORT
	DEBUG(LOG_INFO, 0, "New timer for %s, life=%d",
	      ip_to_str(rt->dest_addr), life);//数据转换并检查格式

	if (life != 0)
		timer_set_timeout(&rt->rt_timer, life);//将life时间加入到rt的定时器中
//#endif
	/* In case there are buffered packets for this destination, we
	 * send them on the new route. */
	if (rt->state == VALID && seek_list_remove(seek_list_find(dest_addr))) {
#ifdef NS_PORT
		if (rt->flags & RT_INET_DEST)
			packet_queue_set_verdict(dest_addr, PQ_ENC_SEND);
		else
			packet_queue_set_verdict(dest_addr, PQ_SEND);
#endif
	}
	return rt;
}

rt_table_t *NS_CLASS rt_table_update(rt_table_t * rt, struct in_addr next,//更新路由表
				     u_int8_t hops, u_int32_t seqno,
				     u_int32_t lifetime, u_int8_t state,
				     u_int16_t flags)
{
	struct in_addr nm;
	nm.s_addr = 0;

	if (rt->state == INVALID && state == VALID) {//将到期的但是即将变得活跃的表项加入到路由表项中

		/* If this previously was an expired route, but will now be
		   active again we must add it to the kernel routing
		   table... */
		rt_tbl.num_active++;

		if (rt->flags & RT_REPAIR)
			flags &= ~RT_REPAIR;

#ifndef NS_PORT
		nl_send_add_route_msg(rt->dest_addr, next, hops, lifetime,
				      flags, rt->ifindex);
#endif

	} else if (rt->next_hop.s_addr != 0 &&
		   rt->next_hop.s_addr != next.s_addr) {

		DEBUG(LOG_INFO, 0, "rt->next_hop=%s, new_next_hop=%s",
		      ip_to_str(rt->next_hop), ip_to_str(next));

#ifndef NS_PORT
		nl_send_add_route_msg(rt->dest_addr, next, hops, lifetime,
				      flags, rt->ifindex);
#endif
	}

	if (hops > 1 && rt->hcnt == 1) {
		rt->last_hello_time.tv_sec = 0;
		rt->last_hello_time.tv_usec = 0;
		rt->hello_cnt = 0;
		timer_remove(&rt->hello_timer);
		/* Must also do a "link break" when updating a 1 hop
		neighbor in case another routing entry use this as
		next hop... */
		neighbor_link_break(rt);//邻居节点断开处理
	}
	
	rt->flags = flags;
	rt->dest_seqno = seqno;
	rt->next_hop = next;
	rt->hcnt = hops;

#ifdef CONFIG_GATEWAY
	if (rt->flags & RT_GATEWAY)
		rt_table_update_inet_rt(rt, lifetime);
#endif

//#ifdef NS_PORT
	rt->rt_timer.handler = &NS_CLASS route_expire_timeout;

	if (!(rt->flags & RT_INET_DEST))
		rt_table_update_timeout(rt, lifetime);
//#endif

	/* Finally, mark as VALID */
	rt->state = state;

	/* In case there are buffered packets for this destination, we send
	 * them on the new route. */
	if (rt->state == VALID
	    && seek_list_remove(seek_list_find(rt->dest_addr))) {
#ifdef NS_PORT
		if (rt->flags & RT_INET_DEST)
			packet_queue_set_verdict(rt->dest_addr, PQ_ENC_SEND);
		else
			packet_queue_set_verdict(rt->dest_addr, PQ_SEND);
#endif
	}
	return rt;
}

NS_INLINE rt_table_t *NS_CLASS rt_table_update_timeout(rt_table_t * rt,//更新路由表的定时器信息
						       u_int32_t lifetime)
{
	struct timeval new_timeout;

	if (!rt)
		return NULL;

	if (rt->state == VALID) {
		/* Check if the current valid timeout is larger than the new
		   one - in that case keep the old one. */
		gettimeofday(&new_timeout, NULL);
		timeval_add_msec(&new_timeout, lifetime);

		if (timeval_diff(&rt->rt_timer.timeout, &new_timeout) < 0)//判断当前定时器和新的定时器的时间
			timer_set_timeout(&rt->rt_timer, lifetime);
	} else
		timer_set_timeout(&rt->rt_timer, lifetime);

	return rt;
}

/* Update route timeouts in response to an incoming or outgoing data packet. */
void NS_CLASS rt_table_update_route_timeouts(rt_table_t * fwd_rt,//更新输入或输出包路由时的定时器
					     rt_table_t * rev_rt)
{
	rt_table_t *next_hop_rt = NULL;

	/* When forwarding a packet, we update the lifetime of the
	   destination's routing table entry, as well as the entry for the
	   next hop neighbor (if not the same). AODV draft 10, section
	   6.2. */

	if (fwd_rt && fwd_rt->state == VALID) {

		if (llfeedback || fwd_rt->flags & RT_INET_DEST || 
		    fwd_rt->hcnt != 1 || fwd_rt->hello_timer.used)
			rt_table_update_timeout(fwd_rt, ACTIVE_ROUTE_TIMEOUT);

		next_hop_rt = rt_table_find(fwd_rt->next_hop);

		if (next_hop_rt && next_hop_rt->state == VALID &&
		    next_hop_rt->dest_addr.s_addr != fwd_rt->dest_addr.s_addr &&
		    (llfeedback || fwd_rt->hello_timer.used))
			rt_table_update_timeout(next_hop_rt,
						ACTIVE_ROUTE_TIMEOUT);

	}
	/* Also update the reverse route and reverse next hop along the
	   path back, since routes between originators and the destination
	   are expected to be symmetric. */
	if (rev_rt && rev_rt->state == VALID) {

		if (llfeedback || rev_rt->hcnt != 1 || rev_rt->hello_timer.used)
			rt_table_update_timeout(rev_rt, ACTIVE_ROUTE_TIMEOUT);

		next_hop_rt = rt_table_find(rev_rt->next_hop);

		if (next_hop_rt && next_hop_rt->state == VALID && rev_rt &&
		    next_hop_rt->dest_addr.s_addr != rev_rt->dest_addr.s_addr &&
		    (llfeedback || rev_rt->hello_timer.used))
			rt_table_update_timeout(next_hop_rt,
						ACTIVE_ROUTE_TIMEOUT);

		/* Update HELLO timer of next hop neighbor if active */
/* 	if (!llfeedback && next_hop_rt->hello_timer.used) { */
/* 	    struct timeval now; */

/* 	    gettimeofday(&now, NULL); */
/* 	    hello_update_timeout(next_hop_rt, &now,  */
/* 				 ALLOWED_HELLO_LOSS * HELLO_INTERVAL); */
/* 	} */
	}
}

rt_table_t *NS_CLASS rt_table_find(struct in_addr dest_addr)//根据目的地址查找路由表项
{
	hash_value hash;
	unsigned int index;
	list_t *pos;

	if (rt_tbl.num_entries == 0)//路由表中没有信息
		return NULL;

	/* Calculate index */
	index = hashing(&dest_addr, &hash);

	/* Handle collisions: */
	list_foreach(pos, &rt_tbl.tbl[index]) {//遍历路由表
		rt_table_t *rt = (rt_table_t *) pos;

		if (rt->hash != hash)
			continue;

		if (memcmp(&dest_addr, &rt->dest_addr, sizeof(struct in_addr))//比较字节
		    == 0)
			return rt;

	}
	return NULL;
}

rt_table_t *NS_CLASS rt_table_find_gateway()//查找默认网关
{
	rt_table_t *gw = NULL;
	int i;

	for (i = 0; i < RT_TABLESIZE; i++) {
		list_t *pos;
		list_foreach(pos, &rt_tbl.tbl[i]) {//遍历
			rt_table_t *rt = (rt_table_t *) pos;

			if (rt->flags & RT_GATEWAY && rt->state == VALID) {//查找到默认网关
				if (!gw || rt->hcnt < gw->hcnt)
					gw = rt;
			}
		}
	}
	return gw;
}

#ifdef CONFIG_GATEWAY
int NS_CLASS rt_table_update_inet_rt(rt_table_t * gw, u_int32_t life)//设置默认状态下，所有包的下一跳均转发给默认网关
{
	int n = 0;
	int i;

	if (!gw)
		return -1;

	for (i = 0; i < RT_TABLESIZE; i++) {
		list_t *pos;
		list_foreach(pos, &rt_tbl.tbl[i]) {
			rt_table_t *rt = (rt_table_t *) pos;

			if (rt->flags & RT_INET_DEST && rt->state == VALID) {/* Mark for Internet destinations (to be relayed
				 * through a Internet gateway. */
				rt_table_update(rt, gw->dest_addr, gw->hcnt, 0,//更新网关信息
						life, VALID, rt->flags);
				n++;
			}
		}
	}
	return n;
}
#endif				/* CONFIG_GATEWAY_DISABLED */

/* Route expiry and Deletion. */
int NS_CLASS rt_table_invalidate(rt_table_t * rt)//路由表超时无效化
{
	struct timeval now;

	gettimeofday(&now, NULL);

	if (rt == NULL)
		return -1;

	/* If the route is already invalidated, do nothing... */
	if (rt->state == INVALID) {
		DEBUG(LOG_DEBUG, 0, "Route %s already invalidated!!!",
		      ip_to_str(rt->dest_addr));//路由已经过期无效了
		return -1;
	}

	if (rt->hello_timer.used) {
		DEBUG(LOG_DEBUG, 0, "last HELLO: %ld",
		      timeval_diff(&now, &rt->last_hello_time));//判断过期
	}

	/* Remove any pending, but now obsolete timers. */
	timer_remove(&rt->rt_timer);
	timer_remove(&rt->hello_timer);
	timer_remove(&rt->ack_timer);//移除操作

	/* Mark the route as invalid */
	rt->state = INVALID;//无效化
	rt_tbl.num_active--;

	rt->hello_cnt = 0;

	/* When the lifetime of a route entry expires, increase the sequence
	   number for that entry. */
	seqno_incr(rt->dest_seqno);

	rt->last_hello_time.tv_sec = 0;
	rt->last_hello_time.tv_usec = 0;

#ifndef NS_PORT
	nl_send_del_route_msg(rt->dest_addr, rt->next_hop, rt->hcnt);
#endif


#ifdef CONFIG_GATEWAY
	/* If this was a gateway, check if any Internet destinations were using
	 * it. In that case update them to use a backup gateway or invalide them
	 * too. */
	if (rt->flags & RT_GATEWAY) {
		int i;

		rt_table_t *gw = rt_table_find_gateway();//找到默认网关

		for (i = 0; i < RT_TABLESIZE; i++) {
			list_t *pos;
			list_foreach(pos, &rt_tbl.tbl[i]) {
				rt_table_t *rt2 = (rt_table_t *) pos;

				if (rt2->state == VALID
				    && (rt2->flags & RT_INET_DEST)
				    && (rt2->next_hop.s_addr ==
					rt->dest_addr.s_addr)) {
					if (0) {
						DEBUG(LOG_DEBUG, 0,
						      "Invalidated GW %s but found new GW %s for %s",
						      ip_to_str(rt->dest_addr),
						      ip_to_str(gw->dest_addr),
						      ip_to_str(rt2->
								dest_addr));
						rt_table_update(rt2,
								gw->dest_addr,
								gw->hcnt, 0,
								timeval_diff
								(&rt->rt_timer.
								 timeout, &now),
								VALID,
								rt2->flags);
					} else {
						rt_table_invalidate(rt2);
						precursor_list_destroy(rt2);//销毁rt2的先驱表
					}
				}
			}
		}
	}
#endif

	if (rt->flags & RT_REPAIR) {
		/* Set a timeout for the repair */

		rt->rt_timer.handler = &NS_CLASS local_repair_timeout;
		timer_set_timeout(&rt->rt_timer, ACTIVE_ROUTE_TIMEOUT);

		DEBUG(LOG_DEBUG, 0, "%s kept for repairs during %u msecs",
		      ip_to_str(rt->dest_addr), ACTIVE_ROUTE_TIMEOUT);//修复时间
	} else {

		/* Schedule a deletion timer */
		rt->rt_timer.handler = &NS_CLASS route_delete_timeout;
		timer_set_timeout(&rt->rt_timer, DELETE_PERIOD);

		DEBUG(LOG_DEBUG, 0, "%s removed in %u msecs",
		      ip_to_str(rt->dest_addr), DELETE_PERIOD);//移除时间
	}

	return 0;
}

void NS_CLASS rt_table_delete(rt_table_t * rt)//路由表项删除
{
	if (!rt) {//路由表内容为空
		DEBUG(LOG_ERR, 0, "No route entry to delete");
		return;
	}

	list_detach(&rt->l);将rt拿出来

	precursor_list_destroy(rt);//删除rt的前驱表

	if (rt->state == VALID) {

#ifndef NS_PORT
		nl_send_del_route_msg(rt->dest_addr, rt->next_hop, rt->hcnt);
#endif
		rt_tbl.num_active--;
	}
	/* Make sure timers are removed... */
	timer_remove(&rt->rt_timer);
	timer_remove(&rt->hello_timer);
	timer_remove(&rt->ack_timer);

	rt_tbl.num_entries--;

	free(rt);
	return;
}

/****************************************************************/

/* Add an neighbor to the active neighbor list. */

void NS_CLASS precursor_add(rt_table_t * rt, struct in_addr addr)//先驱表添加节点
{
	precursor_t *pr;
	list_t *pos;

	/* Sanity check */
	if (!rt)
		return;

	/* Check if the node is already in the precursors list. */
	list_foreach(pos, &rt->precursors) {
		pr = (precursor_t *) pos;

		if (pr->neighbor.s_addr == addr.s_addr)
			return;
	}

	if ((pr = (precursor_t *) malloc(sizeof(precursor_t))) == NULL) {
		perror("Could not allocate memory for precursor node!!\n");
		exit(-1);
	}

	DEBUG(LOG_INFO, 0, "Adding precursor %s to rte %s",
	      ip_to_str(addr), ip_to_str(rt->dest_addr));

	pr->neighbor.s_addr = addr.s_addr;

	/* Insert in precursors list */

	list_add(&rt->precursors, &pr->l);
	rt->nprec++;

	return;
}

/****************************************************************/

/* Remove a neighbor from the active neighbor list. */

void NS_CLASS precursor_remove(rt_table_t * rt, struct in_addr addr)//先驱表移除节点
{
	list_t *pos;

	/* Sanity check */
	if (!rt)
		return;

	list_foreach(pos, &rt->precursors) {
		precursor_t *pr = (precursor_t *) pos;
		if (pr->neighbor.s_addr == addr.s_addr) {
			DEBUG(LOG_INFO, 0, "Removing precursor %s from rte %s",
			      ip_to_str(addr), ip_to_str(rt->dest_addr));

			list_detach(pos);
			rt->nprec--;
			free(pr);
			return;
		}
	}
}

/****************************************************************/

/* Delete all entries from the active neighbor list. */

void precursor_list_destroy(rt_table_t * rt)//先驱链表销毁
{
	list_t *pos, *tmp;

	/* Sanity check */
	if (!rt)
		return;

	list_foreach_safe(pos, tmp, &rt->precursors) {
		precursor_t *pr = (precursor_t *) pos;
		list_detach(pos);
		rt->nprec--;
		free(pr);//释放表项
	}
}
