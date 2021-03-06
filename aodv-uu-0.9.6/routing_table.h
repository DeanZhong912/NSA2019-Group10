/*****************************************************************************
 *
 * Copyright (C) 2001 Uppsala University & Ericsson AB.
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
#ifndef _ROUTING_TABLE_H
#define _ROUTING_TABLE_H

#ifndef NS_NO_GLOBALS
#include "defs.h"
#include "list.h"

typedef struct rt_table rt_table_t;

/* Neighbor struct for active routes in Route Table */
typedef struct precursor {//定义结构体先驱表项
    list_t l;
    struct in_addr neighbor;
} precursor_t;

#define FIRST_PREC(h) ((precursor_t *)((h).next))

#define seqno_incr(s) ((s == 0) ? 0 : ((s == 0xFFFFFFFF) ? s = 1 : s++))//s为0时返回0，否则判断s是否为0xFFFFFFFF,是则令s=1否则s自增1

typedef u_int32_t hash_value;	/* A hash value */

struct timeval
{
__time_t tv_sec;        /* Seconds. */
__suseconds_t tv_usec;  /* Microseconds. */
};


/* Route table entries */
//<目标地址，目标序列号，端口标号，下一跳地址，跳数>
struct rt_table {
    list_t l;
    struct in_addr dest_addr;	/* IP address of the destination */
    u_int32_t dest_seqno;
    unsigned int ifindex;	/* Network interface index... */
    struct in_addr next_hop;	/* IP address of the next hop to the dest */
    u_int8_t hcnt;		/* Distance (in hops) to the destination *///距离
    u_int16_t flags;		/* Routing flags *///标志符
    u_int8_t state;		/* The state of this entry *///状态
    struct timer rt_timer;	/* The timer associated with this entry */
    struct timer ack_timer;	/* RREP_ack timer for this destination */
    struct timer hello_timer;
    struct timeval last_hello_time;
    u_int8_t hello_cnt;
    hash_value hash;
    int nprec;			/* Number of precursors */
    list_t precursors;		/* List of neighbors using the route */
};


/* Route entry flags */
#define RT_UNIDIR        0x1
#define RT_REPAIR        0x2
#define RT_INV_SEQNO     0x4
#define RT_INET_DEST     0x8	/* Mark for Internet destinations (to be relayed
				 * through a Internet gateway. */
#define RT_GATEWAY       0x10

/* Route entry states */
#define INVALID   0  //路由无效
#define VALID     1  //路由有效

#define RT_TABLESIZE 64		/* Must be a power of 2 */
#define RT_TABLEMASK (RT_TABLESIZE - 1)

struct routing_table {
    unsigned int num_entries;//路由表加入项数
    unsigned int num_active;//活跃节点数
    list_t tbl[RT_TABLESIZE];
};

void precursor_list_destroy(rt_table_t * rt);//先驱链表销毁
#endif				/* NS_NO_GLOBALS */

#ifndef NS_NO_DECLARATIONS

struct routing_table rt_tbl;

void rt_table_init();//初始化
void rt_table_destroy();//销毁
rt_table_t *rt_table_insert(struct in_addr dest, struct in_addr next,//插入
			    u_int8_t hops, u_int32_t seqno, u_int32_t life,
			    u_int8_t state, u_int16_t flags,
			    unsigned int ifindex);
rt_table_t *rt_table_update(rt_table_t * rt, struct in_addr next, u_int8_t hops,//更新路由表
			    u_int32_t seqno, u_int32_t lifetime, u_int8_t state,
			    u_int16_t flags);
NS_INLINE rt_table_t *rt_table_update_timeout(rt_table_t * rt,//更新路由表定时器信息
					      u_int32_t lifetime);
void rt_table_update_route_timeouts(rt_table_t * fwd_rt, rt_table_t * rev_rt);//更新输入或者输出包路由的定时器信息
rt_table_t *rt_table_find(struct in_addr dest);//根据目的地址查找路由表项
rt_table_t *rt_table_find_gateway();//寻找本机的默认网关
int rt_table_update_inet_rt(rt_table_t * gw, u_int32_t life);//设置默认状态下所有包下一跳均转发给默认网关
int rt_table_invalidate(rt_table_t * rt);//路由表超时时将其无效化
void rt_table_delete(rt_table_t * rt);//删除一个路由表项
void precursor_add(rt_table_t * rt, struct in_addr addr);//在路由表项的先驱表中添加一个节点
void precursor_remove(rt_table_t * rt, struct in_addr addr);//在路由表项的先驱表中移除一个节点

#endif				/* NS_NO_DECLARATIONS */

#endif				/* ROUTING_TABLE_H */
