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
#ifndef _AODV_RREP_H
#define _AODV_RREP_H

#ifndef NS_NO_GLOBALS
#include <endian.h>

#include "defs.h"
#include "routing_table.h"

/* RREP Flags: */
// 路由回复
#define RREP_ACK       0x1
#define RREP_REPAIR    0x2
/*
 0					 1					 2					 3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|	  Type		|R|A|	 Reserved	  |Prefix Sz|	Hop Count	|
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|					  Destination IP address					|
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|				   Destination Sequence Number					|
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|					 Originator IP address						|
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|							Lifetime							|
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
typedef struct {
    u_int8_t type;         //定义类型 2
#if defined(__LITTLE_ENDIAN)
    u_int16_t res1:6;      //???忽略接收，发送0
    u_int16_t a:1;         //确认请求 当发送RREP消息的链接可能不可靠或单向时使用，
                           //当RREP消息包含'A'位集时，RREP的接收者将返回一条RREP-ack消息
    u_int16_t r:1;         //repair标记位，用于广播
    u_int16_t prefix:5;    //5位 若非0，可用于指定下一跳可用于具有与请求目的地相同的路由前缀
                           //当prefix大小为非0时，必须保留与子网路由有关的任何路由信息(和前驱数据)，
                           //而不是子网上的单个目标IP地址。
    u_int16_t res2:3;      //
#elif defined(__BIG_ENDIAN)
    u_int16_t r:1;
    u_int16_t a:1;
    u_int16_t res1:6;
    u_int16_t res2:3;
    u_int16_t prefix:5;
#else
#error "Adjust your <bits/endian.h> defines"
#endif
    u_int8_t hcnt;         //记录从发起者ip到目的地ip的跳数
    u_int32_t dest_addr;   //目的地地址
    u_int32_t dest_seqno;  //与路由关联的目的地序列号
    u_int32_t orig_addr;   //发送者地址
    u_int32_t lifetime;    //接收RREP的节点认为路由有效的毫秒时间
} RREP;
/*
* prefix允许子网路由器为由路由前缀定义的子网中的每个主机提供路由，
* 路由前缀由子网路由器的IP地址和前缀大小决定。
*/
#define RREP_SIZE sizeof(RREP)

typedef struct {
    u_int8_t type;  //rrep_ack
    u_int8_t reserved;
} RREP_ack;
//存在单向链接阻止路由发现周期完成的危险时 发送rrep_ack
#define RREP_ACK_SIZE sizeof(RREP_ack)
#endif				/* NS_NO_GLOBALS */

#ifndef NS_NO_DECLARATIONS
RREP *rrep_create(u_int8_t flags,
		  u_int8_t prefix,
		  u_int8_t hcnt,
		  struct in_addr dest_addr,
		  u_int32_t dest_seqno,
		  struct in_addr orig_addr, u_int32_t life);

RREP_ack *rrep_ack_create();
AODV_ext *rrep_add_ext(RREP * rrep, int type, unsigned int offset,
		       int len, char *data);
void rrep_send(RREP * rrep, rt_table_t * rev_rt, rt_table_t * fwd_rt, int size);
void rrep_forward(RREP * rrep, int size, rt_table_t * rev_rt,
		  rt_table_t * fwd_rt, int ttl);
void rrep_process(RREP * rrep, int rreplen, struct in_addr ip_src,
		  struct in_addr ip_dst, int ip_ttl, unsigned int ifindex);
void rrep_ack_process(RREP_ack * rrep_ack, int rreplen, struct in_addr ip_src,
		      struct in_addr ip_dst);
#endif				/* NS_NO_DECLARATIONS */

#endif				/* AODV_RREP_H */
