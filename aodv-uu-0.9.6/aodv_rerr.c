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
#include "aodv_rerr.h"
#include "routing_table.h"
#include "aodv_socket.h"
#include "aodv_timeout.h"
#include "defs.h"
#include "debug.h"
#include "params.h"

#endif
// 创建一个rerr数据，参数为目的地址，序列号，以及标记位
RERR *NS_CLASS rerr_create(u_int8_t flags, struct in_addr dest_addr,
			   u_int32_t dest_seqno)
{
    RERR *rerr;

    DEBUG(LOG_DEBUG, 0, "Assembling RERR about %s seqno=%d",
	  ip_to_str(dest_addr), dest_seqno);

    rerr = (RERR *) aodv_socket_new_msg();
    rerr->type = AODV_RERR;
    rerr->n = (flags & RERR_NODELETE ? 1 : 0);
    rerr->res1 = 0;
    rerr->res2 = 0;
    rerr->dest_addr = dest_addr.s_addr;
    rerr->dest_seqno = htonl(dest_seqno);
    rerr->dest_count = 1;

    return rerr;
}
// 给rerr添加到不可到达目的的队列，参数为当前rerr以及要添加的不可到达目的节点的信息
void NS_CLASS rerr_add_udest(RERR * rerr, struct in_addr udest,
			     u_int32_t udest_seqno)
{
    RERR_udest *ud;

    ud = (RERR_udest *) ((char *) rerr + RERR_CALC_SIZE(rerr)); 	//移到rerr最后的地址  添加不可达节点的IP地址和序列号
    ud->dest_addr = udest.s_addr;
    ud->dest_seqno = htonl(udest_seqno);
    rerr->dest_count++;
}

// 传输rerr消息的函数，参数为rerr，rerr长度，源ip，目的ip
void NS_CLASS rerr_process(RERR * rerr, int rerrlen, struct in_addr ip_src,
			   struct in_addr ip_dst)
{
    RERR *new_rerr = NULL;
    RERR_udest *udest;
    rt_table_t *rt;
    u_int32_t rerr_dest_seqno;
    struct in_addr udest_addr, rerr_unicast_dest;
    int i;

    rerr_unicast_dest.s_addr = 0;

    DEBUG(LOG_DEBUG, 0, "ip_src=%s", ip_to_str(ip_src));

    log_pkt_fields((AODV_msg *) rerr);

    if (rerrlen < ((int) RERR_CALC_SIZE(rerr))) {                    //如果rerr的长度小于原rerr大小   		错误 返回
	alog(LOG_WARNING, 0, __FUNCTION__,
	     "IP data too short (%u bytes) from %s to %s. Should be %d bytes.",
	     rerrlen, ip_to_str(ip_src), ip_to_str(ip_dst),
	     RERR_CALC_SIZE(rerr));

	return;
    }

    /* Check which destinations that are unreachable.  */			//核对目的地址是不可达的
    udest = RERR_UDEST_FIRST(rerr);									//得到rerr的第一个不可达结点

    while (rerr->dest_count) {										//不可达IP地址的数量

	udest_addr.s_addr = udest->dest_addr;							//记录目的IP地址 和 序列号
	rerr_dest_seqno = ntohl(udest->dest_seqno);
	DEBUG(LOG_DEBUG, 0, "unreachable dest=%s seqno=%lu",
	      ip_to_str(udest_addr), rerr_dest_seqno);

	rt = rt_table_find(udest_addr);									//寻找目的地是目的IP地址的路由表项

	if (rt && rt->state == VALID && rt->next_hop.s_addr == ip_src.s_addr) {	//如果存在且有效 而且下一跳为源IP地址

	    /* Checking sequence numbers here is an out of draft
	     * addition to AODV-UU. It is here because it makes a lot
	     * of sense... */
	    if (0 && (int32_t) rt->dest_seqno > (int32_t) rerr_dest_seqno) {	
	     // 检查序列号
		DEBUG(LOG_DEBUG, 0, "Udest ignored because of seqno");
		udest = RERR_UDEST_NEXT(udest);
		rerr->dest_count--;
		continue;
	    }
	    DEBUG(LOG_DEBUG, 0, "removing rte %s - WAS IN RERR!!",
		  ip_to_str(udest_addr));

#ifdef NS_PORT
	    interfaceQueue((nsaddr_t) udest_addr.s_addr, IFQ_DROP_BY_DEST);
#endif
	    /* Invalidate route: */
	    if (!rerr->n) {													//如果rerr->n为0
		rt_table_invalidate(rt);										//使路由rt无效
	    }
	    /* (a) updates the corresponding destination sequence number
	       with the Destination Sequence Number in the packet, and */
	    rt->dest_seqno = rerr_dest_seqno;								//更新序列号

	    /* (d) check precursor list for emptiness. If not empty, include
	       the destination as an unreachable destination in the
	       RERR... */
	    if (rt->nprec && !(rt->flags & RT_REPAIR)) {					//路由表中有先驱表且为待修复

		if (!new_rerr) {												//new_rerr为空
		    u_int8_t flags = 0;

		    if (rerr->n)												//如果rerr->n为1
			flags |= RERR_NODELETE;										//设置flag为nodelete

		    new_rerr = rerr_create(flags, rt->dest_addr,				//创建一个rerr消息 	将先驱表中的结点都变成不可达
					   rt->dest_seqno);									//留给其他节点去重新进行路由发现
		    DEBUG(LOG_DEBUG, 0, "Added %s as unreachable, seqno=%lu",
			  ip_to_str(rt->dest_addr), rt->dest_seqno);

		    if (rt->nprec == 1)											//如果先驱表中只有一个结点
			rerr_unicast_dest =
			    FIRST_PREC(rt->precursors)->neighbor;					//rerr的rerr_unicast_dest（单播）设置为先驱表的next的邻居结点IP地址

		} else {														//如果new_rerr不为空
		    /* Decide whether new precursors make this a non unicast RERR */
		    rerr_add_udest(new_rerr, rt->dest_addr, rt->dest_seqno);	//添加新的不可达结点

		    DEBUG(LOG_DEBUG, 0, "Added %s as unreachable, seqno=%lu",
			  ip_to_str(rt->dest_addr), rt->dest_seqno);

		    if (rerr_unicast_dest.s_addr) {								//如果rerr_unicast_dest的地址不为空
			list_t *pos2;
			list_foreach(pos2, &rt->precursors) {						//如果路由表rt的邻居结点IP地址不等于rerr_unicast_dest的IP地址，则清零
			    precursor_t *pr = (precursor_t *) pos2;
			    if (pr->neighbor.s_addr != rerr_unicast_dest.s_addr) {
				rerr_unicast_dest.s_addr = 0;
				break;
			    }
			}
		    }
		}
	    } else {						//没有先驱表 无需发送RERR
		DEBUG(LOG_DEBUG, 0,
		      "Not sending RERR, no precursors or route in RT_REPAIR");
	    }
	    /* We should delete the precursor list for all unreachable
	       destinations. */
	    if (rt->state == INVALID)											//如果路由表rt状态为无效
		precursor_list_destroy(rt);											//销毁rt的先驱表
	} else {
	    DEBUG(LOG_DEBUG, 0, "Ignoring UDEST %s", ip_to_str(udest_addr));	//有效则忽略
	}
	udest = RERR_UDEST_NEXT(udest);											//获得下一个不可达结点
	rerr->dest_count--;														//不可达节点数-1
    }				/* End while() */

    /* If a RERR was created, then send it now... */
    if (new_rerr) {															//如果有新的rerr被创建

	rt = rt_table_find(rerr_unicast_dest);									//在路由表中寻找目的为rerr_unicast_dest的路由表项

	if (rt && new_rerr->dest_count == 1 && rerr_unicast_dest.s_addr)		//如果存在且rerr只有一个不可达结点 而且存在单播地址
	    aodv_socket_send((AODV_msg *) new_rerr,								//发送一个给此单播地址的一个rerr消息
			     rerr_unicast_dest,
			     RERR_CALC_SIZE(new_rerr), 1,
			     &DEV_IFINDEX(rt->ifindex));

	else if (new_rerr->dest_count > 0) {									//如果新的rerr的不可达节点数大于0
	    /* FIXME: Should only transmit RERR on those interfaces
	     * which have precursor nodes for the broken route */				//只能在具有中断了的路由的先驱节点的那些接口上发送RERR
	    for (i = 0; i < MAX_NR_INTERFACES; i++) {							
		struct in_addr dest;

		if (!DEV_NR(i).enabled)												//在有效接口发送rerr
		    continue;
		dest.s_addr = AODV_BROADCAST;										//地址为广播
		aodv_socket_send((AODV_msg *) new_rerr, dest,
				 RERR_CALC_SIZE(new_rerr), 1, &DEV_NR(i));
	    }
	}
    }
}
