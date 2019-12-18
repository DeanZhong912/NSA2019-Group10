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

#ifdef NS_PORT
#include "ns-2/aodv-uu.h"
#else
#include <netinet/in.h>
#include "aodv_rrep.h"
#include "aodv_neighbor.h"
#include "aodv_hello.h"
#include "routing_table.h"
#include "aodv_timeout.h"
#include "timer_queue.h"
#include "aodv_socket.h"
#include "defs.h"
#include "debug.h"
#include "params.h"

extern int unidir_hack, optimized_hellos, llfeedback;

#endif

RREP *NS_CLASS rrep_create(u_int8_t flags,						//创建一个RREP消息
			   u_int8_t prefix,
			   u_int8_t hcnt,
			   struct in_addr dest_addr,
			   u_int32_t dest_seqno,
			   struct in_addr orig_addr, u_int32_t life)
{
    RREP *rrep;

    rrep = (RREP *) aodv_socket_new_msg();
    rrep->type = AODV_RREP;
    rrep->res1 = 0;
    rrep->res2 = 0;
    rrep->prefix = prefix;
    rrep->hcnt = hcnt;
    rrep->dest_addr = dest_addr.s_addr;
    rrep->dest_seqno = htonl(dest_seqno);
    rrep->orig_addr = orig_addr.s_addr;
    rrep->lifetime = htonl(life);

    if (flags & RREP_REPAIR)
	rrep->r = 1;
    if (flags & RREP_ACK)
	rrep->a = 1;

    /* Don't print information about hello messages... */
#ifdef DEBUG_OUTPUT
    if (rrep->dest_addr != rrep->orig_addr) {
	DEBUG(LOG_DEBUG, 0, "Assembled RREP:");
	log_pkt_fields((AODV_msg *) rrep);
    }
#endif

    return rrep;
}

RREP_ack *NS_CLASS rrep_ack_create()								//创建一个RREP_ACK消息
{
    RREP_ack *rrep_ack;

    rrep_ack = (RREP_ack *) aodv_socket_new_msg();
    rrep_ack->type = AODV_RREP_ACK;

    DEBUG(LOG_DEBUG, 0, "Assembled RREP_ack");

    return rrep_ack;
}

void NS_CLASS rrep_ack_process(RREP_ack * rrep_ack, int rrep_acklen,			//RREP_ACK处理函数
			       struct in_addr ip_src, struct in_addr ip_dst)
{
    rt_table_t *rt;

    rt = rt_table_find(ip_src);													//寻找源IP地址的路由表项

    if (rt == NULL) {															//如果没有则返回
	DEBUG(LOG_WARNING, 0, "No RREP_ACK expected for %s", ip_to_str(ip_src));

	return;
    }
    DEBUG(LOG_DEBUG, 0, "Received RREP_ACK from %s", ip_to_str(ip_src));

    /* Remove unexpired timer for this RREP_ACK */
    timer_remove(&rt->ack_timer);												//移除ack_timer定时器
}

AODV_ext *NS_CLASS rrep_add_ext(RREP * rrep, int type, unsigned int offset,			//RREP添加扩展项
				int len, char *data)
{
    AODV_ext *ext = NULL;

    if (offset < RREP_SIZE)														//如果偏移小于RREP的大小 则返回
	return NULL;

    ext = (AODV_ext *) ((char *) rrep + offset);								//设置ext地址

    ext->type = type;															//设置类别
    ext->length = len;															//设置长度

    memcpy(AODV_EXT_DATA(ext), data, len);										//将数据复制到其中

    return ext;
}

void NS_CLASS rrep_send(RREP * rrep, rt_table_t * rev_rt,						//发送rrep
			rt_table_t * fwd_rt, int size)
{
    u_int8_t rrep_flags = 0;
    struct in_addr dest;

    if (!rev_rt) {																//接受路由表为空 返回
	DEBUG(LOG_WARNING, 0, "Can't send RREP, rev_rt = NULL!");		
	return;
    }

    dest.s_addr = rrep->dest_addr;												//目的IP地址为rrep中的目的地址

    /* Check if we should request a RREP-ACK */									//核实是否需要一个RREP_ACK
    if ((rev_rt->state == VALID && rev_rt->flags & RT_UNIDIR) ||				//路由表项的状态为有效且flags为1 
	(rev_rt->hcnt == 1 && unidir_hack)) {										//或者 距离目的地还有一跳且unidir_hack开启
	rt_table_t *neighbor = rt_table_find(rev_rt->next_hop);						//定义邻居节点为下一跳

	if (neighbor && neighbor->state == VALID && !neighbor->ack_timer.used) {	//邻居不为空而且状态为有效而且ack定时器未启用
	    /* If the node we received a RREQ for is a neighbor we are				如果我们收到RREQ的节点是邻居，则我们可能正面临单向链接...
	       probably facing a unidirectional link... Better request a			最好请求RREP-ack
	       RREP-ack */
	    rrep_flags |= RREP_ACK;													//RREP_flags置为RREP_ACK
	    neighbor->flags |= RT_UNIDIR;											//邻居的flags置为1

	    /* Must remove any pending hello timeouts when we set the				设置RT_UNIDIR标志时，必须删除所有待处理的hello超时，
	       RT_UNIDIR flag, else the route may expire after we begin to			否则路由可能会在我们开始忽略hello之后终止
	       ignore hellos... */
	    timer_remove(&neighbor->hello_timer);									//移除hello的定时器
	    neighbor_link_break(neighbor);											//邻居链路中断

	    DEBUG(LOG_DEBUG, 0, "Link to %s is unidirectional!",
		  ip_to_str(neighbor->dest_addr));

	    timer_set_timeout(&neighbor->ack_timer, NEXT_HOP_WAIT);					//设置ack定时器
	}
    }

    DEBUG(LOG_DEBUG, 0, "Sending RREP to next hop %s about %s->%s",
	  ip_to_str(rev_rt->next_hop), ip_to_str(rev_rt->dest_addr),
	  ip_to_str(dest));

    aodv_socket_send((AODV_msg *) rrep, rev_rt->next_hop, size, MAXTTL,			//给下一跳发送AODV socket
		     &DEV_IFINDEX(rev_rt->ifindex));

    /* Update precursor lists */
    if (fwd_rt) {																//如果转发路由表不为空
	precursor_add(fwd_rt, rev_rt->next_hop);									//rev_rt的下一跳加入fwd_rt
	precursor_add(rev_rt, fwd_rt->next_hop);									//fwd_rt的下一跳加入rev_rt
    }

    if (!llfeedback && optimized_hellos)										//未启用链路层反馈且当只有在转发数据的时候才发送hello消息
	hello_start();																//发送hello消息
}

void NS_CLASS rrep_forward(RREP * rrep, int size, rt_table_t * rev_rt,			//rrep转发
			   rt_table_t * fwd_rt, int ttl)
{
    /* Sanity checks... */
    if (!fwd_rt || !rev_rt) {													//路由表为空不能转发
	DEBUG(LOG_WARNING, 0, "Could not forward RREP because of NULL route!");			
	return;
    }

    if (!rrep) {																//rrep为空 不能转发
	DEBUG(LOG_WARNING, 0, "No RREP to forward!");
	return;
    }

    DEBUG(LOG_DEBUG, 0, "Forwarding RREP to %s", ip_to_str(rev_rt->next_hop));

    /* Here we should do a check if we should request a RREP_ACK,
       i.e we suspect a unidirectional link.. But how? */
    if (0) {
	rt_table_t *neighbor;

	/* If the source of the RREP is not a neighbor we must find the
	   neighbor (link) entry which is the next hop towards the RREP
	   source... */
	if (rev_rt->dest_addr.s_addr != rev_rt->next_hop.s_addr)
	    neighbor = rt_table_find(rev_rt->next_hop);
	else
	    neighbor = rev_rt;

	if (neighbor && !neighbor->ack_timer.used) {
	    /* If the node we received a RREQ for is a neighbor we are
	       probably facing a unidirectional link... Better request a
	       RREP-ack */
	    rrep->a = 1;
	    neighbor->flags |= RT_UNIDIR;

	    timer_set_timeout(&neighbor->ack_timer, NEXT_HOP_WAIT);
	}
    }

    rrep = (RREP *) aodv_socket_queue_msg((AODV_msg *) rrep, size);   	//得到rrep消息
    rrep->hcnt = fwd_rt->hcnt;	/* Update the hopcount */				//更新跳数

    aodv_socket_send((AODV_msg *) rrep, rev_rt->next_hop, size, ttl,	//发送aodv socket消息 ：rrep消息 给目的是源IP地址的表项的下一跳
		     &DEV_IFINDEX(rev_rt->ifindex));

    precursor_add(fwd_rt, rev_rt->next_hop);							//rev_rt的下一跳加入fwd_rt
    precursor_add(rev_rt, fwd_rt->next_hop);							//fwd_rt的下一跳加入rev_rt

    rt_table_update_timeout(rev_rt, ACTIVE_ROUTE_TIMEOUT);				//更新rev_rt的timeout
}


void NS_CLASS rrep_process(RREP * rrep, int rreplen, struct in_addr ip_src,		//rrep处理函数
			   struct in_addr ip_dst, int ip_ttl,
			   unsigned int ifindex)
{
    u_int32_t rrep_lifetime, rrep_seqno, rrep_new_hcnt;
    u_int8_t pre_repair_hcnt = 0, pre_repair_flags = 0;
    rt_table_t *fwd_rt, *rev_rt;
    AODV_ext *ext;
    unsigned int extlen = 0;
    int rt_flags = 0;
    struct in_addr rrep_dest, rrep_orig;
#ifdef CONFIG_GATEWAY
    struct in_addr inet_dest_addr;
    int inet_rrep = 0;
#endif

    /* Convert to correct byte order on affeected fields: */
    rrep_dest.s_addr = rrep->dest_addr;							//获得rrep中的各种信息
    rrep_orig.s_addr = rrep->orig_addr;
    rrep_seqno = ntohl(rrep->dest_seqno);
    rrep_lifetime = ntohl(rrep->lifetime);
    /* Increment RREP hop count to account for intermediate node... */
    rrep_new_hcnt = rrep->hcnt + 1;								//rrep跳数+1

    if (rreplen < (int) RREP_SIZE) {							//如果收到的rrep大小小于RREP大小 则返回
	alog(LOG_WARNING, 0, __FUNCTION__,
	     "IP data field too short (%u bytes)"
	     " from %s to %s", rreplen, ip_to_str(ip_src), ip_to_str(ip_dst));
	return;
    }

    /* Ignore messages which aim to a create a route to one self */
    if (rrep_dest.s_addr == DEV_IFINDEX(ifindex).ipaddr.s_addr)	//忽略目的地是本机的rrep
	return;

    DEBUG(LOG_DEBUG, 0, "from %s about %s->%s",
	  ip_to_str(ip_src), ip_to_str(rrep_orig), ip_to_str(rrep_dest));
#ifdef DEBUG_OUTPUT
    log_pkt_fields((AODV_msg *) rrep);
#endif

    /* Determine whether there are any extensions */
    ext = (AODV_ext *) ((char *) rrep + RREP_SIZE);				//获得ext的地址

    while ((rreplen - extlen) > RREP_SIZE) {					//当存在ext时
	switch (ext->type) {
	case RREP_EXT:												//扩展类型类型为RREP_EXT
	    DEBUG(LOG_INFO, 0, "RREP include EXTENSION");
	    /* Do something here */
	    break;
#ifdef CONFIG_GATEWAY
	case RREP_INET_DEST_EXT:									
	    if (ext->length == sizeof(u_int32_t)) {					//目的地是一个网关地址

		/* Destination address in RREP is the gateway address, while the
		 * extension holds the real destination */
		memcpy(&inet_dest_addr, AODV_EXT_DATA(ext), ext->length);//复制ext数据中的地址到inet_dest_addr中

		DEBUG(LOG_DEBUG, 0, "RREP_INET_DEST_EXT: <%s>",
		      ip_to_str(inet_dest_addr));
		/* This was a RREP from a gateway */
		rt_flags |= RT_GATEWAY;									//rt_flags置为网关
		inet_rrep = 1;											//inet_rrep置为1
		break;
	    }
#endif
	default:
	    alog(LOG_WARNING, 0, __FUNCTION__, "Unknown or bad extension %d",		//其余类型不接受
		 ext->type);
	    break;
	}
	extlen += AODV_EXT_SIZE(ext);							//增加扩展长度
	ext = AODV_EXT_NEXT(ext);								//选择下一个扩展
    }

    /* ---------- CHECK IF WE SHOULD MAKE A FORWARD ROUTE ------------ */

    fwd_rt = rt_table_find(rrep_dest);						//寻找转发路由  		目的地是rrep_dest的路由表项
    rev_rt = rt_table_find(rrep_orig);						//寻找接收路由		目的地是rrep_orig的路由表项

    if (!fwd_rt) {											//如果转发路由为空
	/* We didn't have an existing entry, so we insert a new one. */	//新建一个转发路由表
	fwd_rt = rt_table_insert(rrep_dest, ip_src, rrep_new_hcnt, rrep_seqno,
				 rrep_lifetime, VALID, rt_flags, ifindex);
    } else if (fwd_rt->dest_seqno == 0 ||							//如果转发的目的序列号为0
	       (int32_t) rrep_seqno > (int32_t) fwd_rt->dest_seqno ||	//或者rrep中的序列号大于转发路由中的序列号或者
	       (rrep_seqno == fwd_rt->dest_seqno &&						//（rrep的序列号等于转发路由中的序列号且
		(fwd_rt->state == INVALID || fwd_rt->flags & RT_UNIDIR ||	//（转发路由状态为无效 或者 标志为单向 
		 rrep_new_hcnt < fwd_rt->hcnt))) {							//或者rrep的跳数小于转发路由中的跳数））
	pre_repair_hcnt = fwd_rt->hcnt;									//待维修跳数更改为转发路由的跳数
	pre_repair_flags = fwd_rt->flags;								//待修复的标志更改为转发路由的标志

	fwd_rt = rt_table_update(fwd_rt, ip_src, rrep_new_hcnt, rrep_seqno,		//更新转发路由
				 rrep_lifetime, VALID,
				 rt_flags | fwd_rt->flags);
    } else {														//其他情况下
	if (fwd_rt->hcnt > 1) {											//如果转发路由跳数大于1	则丢弃
	    DEBUG(LOG_DEBUG, 0,
		  "Dropping RREP, fwd_rt->hcnt=%d fwd_rt->seqno=%ld",
		  fwd_rt->hcnt, fwd_rt->dest_seqno);
	}
	return;
    }


    /* If the RREP_ACK flag is set we must send a RREP
       acknowledgement to the destination that replied... */
    if (rrep->a) {													//rrep中的ack is set
	RREP_ack *rrep_ack;

	rrep_ack = rrep_ack_create();									//创建一个rrep_ack
	aodv_socket_send((AODV_msg *) rrep_ack, fwd_rt->next_hop,		//发送一个aodv socket消息：rrep_ack
			 NEXT_HOP_WAIT, MAXTTL, &DEV_IFINDEX(fwd_rt->ifindex));
	/* Remove RREP_ACK flag... */
	rrep->a = 0;													//移除rrep_ack的标志
    }

    /* Check if this RREP was for us (i.e. we previously made a RREQ
       for this host). */
    if (rrep_orig.s_addr == DEV_IFINDEX(ifindex).ipaddr.s_addr) {	//如果rrep的源IP地址为本机
#ifdef CONFIG_GATEWAY
	if (inet_rrep) {												//如果rrep来自网关
	    rt_table_t *inet_rt;										
	    inet_rt = rt_table_find(inet_dest_addr);					//寻找目的地址为inet_dest_addr网关的路由表项

	    /* Add a "fake" route indicating that this is an Internet
	     * destination, thus should be encapsulated and routed through a
	     * gateway... */
	    if (!inet_rt)												//如果没找到
		rt_table_insert(inet_dest_addr, rrep_dest, rrep_new_hcnt, 0,	//则新建一个目的地址是该网关 下一跳是rrep_dest的路由表项
				rrep_lifetime, VALID, RT_INET_DEST, ifindex);
	    else if (inet_rt->state == INVALID || rrep_new_hcnt < inet_rt->hcnt) {	//如果是一个无效的或者跳数比原来的小
		rt_table_update(inet_rt, rrep_dest, rrep_new_hcnt, 0,					//则进行更新
				rrep_lifetime, VALID, RT_INET_DEST |
				inet_rt->flags);
	    } else {
		DEBUG(LOG_DEBUG, 0, "INET Response, but no update %s",
		      ip_to_str(inet_dest_addr));
	    }
	}
#endif				/* CONFIG_GATEWAY */

	/* If the route was previously in repair, a NO DELETE RERR should be
	   sent to the source of the route, so that it may choose to reinitiate
	   route discovery for the destination. Fixed a bug here that caused the
	   repair flag to be unset and the RERR never being sent. Thanks to
	   McWood <hjw_5@hotmail.com> for discovering this. */
	if (pre_repair_flags & RT_REPAIR) {							//如果是一个待修复的
	    if (fwd_rt->hcnt > pre_repair_hcnt) {					//如果转发表项的跳数大于待修复的跳数
		RERR *rerr;												//发送一个rerr消息        广播该节点已被修复
		u_int8_t rerr_flags = 0;
		struct in_addr dest;

		dest.s_addr = AODV_BROADCAST;							//目的IP地址设为广播

		rerr_flags |= RERR_NODELETE;							//设置标志为rerr_nodelete
		rerr = rerr_create(rerr_flags, fwd_rt->dest_addr,		//创建一个rerr消息
				   fwd_rt->dest_seqno);

		if (fwd_rt->nprec)										//转发表项先驱表结点数量不为0
		    aodv_socket_send((AODV_msg *) rerr, dest,			//广播一个rerr消息
				     RERR_CALC_SIZE(rerr), 1,
				     &DEV_IFINDEX(fwd_rt->ifindex));
	    }
	}
    } else {
	/* --- Here we FORWARD the RREP on the REVERSE route --- */
	if (rev_rt && rev_rt->state == VALID) {						//目的地源IP地址的表项存在且有效
	    rrep_forward(rrep, rreplen, rev_rt, fwd_rt, --ip_ttl);	//转发rrep消息
	} else {
	    DEBUG(LOG_DEBUG, 0, "Could not forward RREP - NO ROUTE!!!");
	}
    }

    if (!llfeedback && optimized_hellos)						//未启用链路层反馈且当只有在转发数据的时候才发送hello消息
	hello_start();												//发送hello消息
}

/************************************************************************/

/* Include a Hello Interval Extension on the RREP and return new offset */

int rrep_add_hello_ext(RREP * rrep, int offset, u_int32_t interval)				//rrep后添加hello消息的扩展
{
    AODV_ext *ext;

    ext = (AODV_ext *) ((char *) rrep + RREP_SIZE + offset);
    ext->type = RREP_HELLO_INTERVAL_EXT;
    ext->length = sizeof(interval);
    memcpy(AODV_EXT_DATA(ext), &interval, sizeof(interval));

    return (offset + AODV_EXT_SIZE(ext));
}
