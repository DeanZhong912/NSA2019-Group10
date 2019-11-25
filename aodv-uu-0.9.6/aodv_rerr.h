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
#ifndef _AODV_RERR_H
#define _AODV_RERR_H

#ifndef NS_NO_GLOBALS
#include <endian.h>

#include "defs.h"
#include "routing_table.h"
//每当链接中断导致一个或多个目的地无法从节点的某些邻居处访问时，就会发送RERR消息。
/* RERR Flags: */
#define RERR_NODELETE 0x1

/*
 0					 1					 2					 3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|	  Type		|N| 		 Reserved			|	DestCount	|
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|			 Unreachable Destination IP Address (1) 			|
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|		  Unreachable Destination Sequence Number (1)			|
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-|
|  Additional Unreachable Destination IP Addresses (if needed)	|
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|Additional Unreachable Destination Sequence Numbers (if needed)|
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
typedef struct {
    u_int8_t type;//定义类型
#if defined(__LITTLE_ENDIAN)//支持小端
    u_int8_t res1:7;
    u_int8_t n:1;
#elif defined(__BIG_ENDIAN)//支持大端
    u_int8_t n:1;          // 没有删除标志;当一个节点执行了一个链接的本地修复，并且上游节点不应该删除路由时设置。
    u_int8_t res1:7;       // 发送0 忽略返回
#else
#error "Adjust your <bits/endian.h> defines"
#endif
    u_int8_t res2;
    u_int8_t dest_count;//不可到达的目的地数量，至少为1
    u_int32_t dest_addr;//由于链路问题不可到达的目的地的地址
    u_int32_t dest_seqno;//目的地序列号在之前不可到达的目的地IP地址字段中列出的目的地的路由表条目中的序列号
} RERR;

#define RERR_SIZE sizeof(RERR)

/* Extra unreachable destinations... */
typedef struct {    // 额外的不可到达节点的信息   ？会使用队列？
    u_int32_t dest_addr;
    u_int32_t dest_seqno;
} RERR_udest;

#define RERR_UDEST_SIZE sizeof(RERR_udest)

/* Given the total number of unreachable destination this macro
   returns the RERR size */
   //宏定义一些主要的参数，方便用到的
#define RERR_CALC_SIZE(rerr) (RERR_SIZE + (rerr->dest_count-1)*RERR_UDEST_SIZE)
#define RERR_UDEST_FIRST(rerr) ((RERR_udest *)&rerr->dest_addr)
#define RERR_UDEST_NEXT(udest) ((RERR_udest *)((char *)udest + RERR_UDEST_SIZE))
#endif				/* NS_NO_GLOBALS */

#ifndef NS_NO_DECLARATIONS
//rerr信息的建立，添加以及传输
RERR *rerr_create(u_int8_t flags, struct in_addr dest_addr,
		  u_int32_t dest_seqno);
void rerr_add_udest(RERR * rerr, struct in_addr udest, u_int32_t udest_seqno);
void rerr_process(RERR * rerr, int rerrlen, struct in_addr ip_src,
		  struct in_addr ip_dst);
#endif				/* NS_NO_DECLARATIONS */

#endif				/* AODV_RERR_H */
