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

#ifdef NS_PORT                                                                          //如果定义了NS_PORT 则执行ns-2/aodv.uu.h 否则执行下边的else
#include "ns-2/aodv-uu.h"
#else
#include <netinet/in.h>
#include "aodv_hello.h"
#include "aodv_timeout.h"
#include "aodv_rrep.h"
#include "aodv_rreq.h"
#include "routing_table.h"
#include "timer_queue.h"
#include "params.h"
#include "aodv_socket.h"
#include "defs.h"
#include "debug.h"

extern int unidir_hack, receive_n_hellos, hello_jittering, optimized_hellos;
static struct timer hello_timer;

#endif

/* #define DEBUG_HELLO */


long NS_CLASS hello_jitter()
{
    if (hello_jittering) {													//开启不确定抖动时          默认为开启
#ifdef NS_PORT
	return (long) (((float) Random::integer(RAND_MAX + 1) / RAND_MAX - 0.5)
		       * JITTER_INTERVAL);
#else
	return (long) (((float) random() / RAND_MAX - 0.5) * JITTER_INTERVAL);	//返回计算结果   （随机数/最大随机数-0.5）*100
#endif
    } else
	return 0;
}

void NS_CLASS hello_start()
{
    if (hello_timer.used)				//如果hello定时器被使用则返回
	return;

    gettimeofday(&this_host.fwd_time, NULL);		//获取当前时间更新到最新转发时间

    DEBUG(LOG_DEBUG, 0, "Starting to send HELLOs!");
    timer_init(&hello_timer, &NS_CLASS hello_send, NULL);   //初始化hello定时器

    hello_send(NULL);
}

void NS_CLASS hello_stop()
{
    DEBUG(LOG_DEBUG, 0,
	  "No active forwarding routes - stopped sending HELLOs!");
    timer_remove(&hello_timer);									//移除hello定时器
}

void NS_CLASS hello_send(void *arg)
{
    RREP *rrep;									//hello消息为RREP消息 ttl为1 广播消息
    AODV_ext *ext = NULL;
    u_int8_t flags = 0;
    struct in_addr dest;
    long time_diff, jitter;
    struct timeval now;
    int msg_size = RREP_SIZE;
    int i;

    gettimeofday(&now, NULL);               	//获取当前时间

    if (optimized_hellos &&												//如果optimized_hellos为1，代表hello消息只能在转发数据时发送
	timeval_diff(&now, &this_host.fwd_time) > ACTIVE_ROUTE_TIMEOUT) {   //且当前时间与上一次转发数据的时间之差大于
	hello_stop();														//ACTIVE_ROUTE_TIMEOUT=3000 即3s  则停止发送hello消息
	return;
    }

    time_diff = timeval_diff(&now, &this_host.bcast_time);  			//获取当前时间与上一次广播时间的差
    jitter = hello_jitter();

    /* This check will ensure we don't send unnecessary hello msgs, in case
       we have sent other bcast msgs within HELLO_INTERVAL */
    if (time_diff >= HELLO_INTERVAL) {									//如果时间间隔大于等于1s

	for (i = 0; i < MAX_NR_INTERFACES; i++) {							//对于任何有效的接口
	    if (!DEV_NR(i).enabled)
		continue;
#ifdef DEBUG_HELLO
	    DEBUG(LOG_DEBUG, 0, "sending Hello to 255.255.255.255");		//DEBUG状态下 记录发送信息
#endif
	    rrep = rrep_create(flags, 0, 0, DEV_NR(i).ipaddr,				//创建一个RREP消息
			       this_host.seqno,
			       DEV_NR(i).ipaddr,
			       ALLOWED_HELLO_LOSS * HELLO_INTERVAL);

	    /* Assemble a RREP extension which contain our neighbor set... */
	    if (unidir_hack) {  											//开启unidir_hack后 检查并避免单向链接
		int i;

		if (ext)
		    ext = AODV_EXT_NEXT(ext);                 					//不为NULL 则寻找下一个ext
		else
		    ext = (AODV_ext *) ((char *) rrep + RREP_SIZE);				//为空 则在rrep后开辟一块空间

		ext->type = RREP_HELLO_NEIGHBOR_SET_EXT;						//设置类型
		ext->length = 0;

		for (i = 0; i < RT_TABLESIZE; i++) {
		    list_t *pos;
		    list_foreach(pos, &rt_tbl.tbl[i]) {							//查找路由表
			rt_table_t *rt = (rt_table_t *) pos;
			/* If an entry has an active hello timer, we assume
			   that we are receiving hello messages from that
			   node... */
			if (rt->hello_timer.used) {									//如果当前路由正在发送hello消息 默认给我们发，说明与我们有连接
#ifdef DEBUG_HELLO						
			    DEBUG(LOG_INFO, 0,
				  "Adding %s to hello neighbor set ext",
				  ip_to_str(rt->dest_addr));
#endif
			    memcpy(AODV_EXT_DATA(ext), &rt->dest_addr,				//把目的IP地址放到ext中
				   sizeof(struct in_addr));
			    ext->length += sizeof(struct in_addr);					//增加ext长度
			}
		    }
		}
		if (ext->length)
		    msg_size = RREP_SIZE + AODV_EXT_SIZE(ext);					//如果长度不为零 则记录消息的总长度
	    }
	    dest.s_addr = AODV_BROADCAST;									//目的IP地址设置为广播
	    aodv_socket_send((AODV_msg *) rrep, dest, msg_size, 1, &DEV_NR(i)); 	//调用发送函数 其中ttl为1
	}

	timer_set_timeout(&hello_timer, HELLO_INTERVAL + jitter);			//设置hello_timer的timeout	   为1s加上不确定抖动
    } else {						//如果时间差小于1s，不用发送hello消息 设置定时器时间即可
	if (HELLO_INTERVAL - time_diff + jitter < 0)						//如果1s减去时间间隔再加上不确定抖动小于0
	    timer_set_timeout(&hello_timer,
			      HELLO_INTERVAL - time_diff - jitter);					//设置timeout为 1s减去时间间隔减去不确定抖动             		这时jitter为负
	else
	    timer_set_timeout(&hello_timer,									//否则设置timeout为1s减去时间间隔在上不确定抖动	这时jitter为正
			      HELLO_INTERVAL - time_diff + jitter);
    }
}


/* Process a hello message */
void NS_CLASS hello_process(RREP * hello, int rreplen, unsigned int ifindex)		//hello消息处理
{
    u_int32_t hello_seqno, timeout, hello_interval = HELLO_INTERVAL;			
    u_int8_t state, flags = 0;
    struct in_addr ext_neighbor, hello_dest;
    rt_table_t *rt;
    AODV_ext *ext = NULL;
    int i;
    struct timeval now;

    gettimeofday(&now, NULL);										//获取当前时间

    hello_dest.s_addr = hello->dest_addr;							//得到目的IP地址
    hello_seqno = ntohl(hello->dest_seqno);							//得到目的序列号

    rt = rt_table_find(hello_dest);									//路由表中寻找目的IP地址

    if (rt)															//如果存在
	flags = rt->flags;												//设置routing flag

    if (unidir_hack)												//如果开启unidir_hack
	flags |= RT_UNIDIR;												//flag置为1

    /* Check for hello interval extension: */
    ext = (AODV_ext *) ((char *) hello + RREP_SIZE);				//得到ext的地址

    while (rreplen > (int) RREP_SIZE) {								//如果收到的长度大于RREP的长度
	switch (ext->type) {											
	case RREP_HELLO_INTERVAL_EXT:									//当ext的类型是RREP_HELLO_INTERVAL_EXT
	    if (ext->length == 4) {  									
		memcpy(&hello_interval, AODV_EXT_DATA(ext), 4);				//将ext的数据放入hello_interval中  		即时间间隔
		hello_interval = ntohl(hello_interval);						//转换为主机字节序
#ifdef DEBUG_HELLO
		DEBUG(LOG_INFO, 0, "Hello extension interval=%lu!",
		      hello_interval);
#endif

	    } else														//如果长度不为4 则扩展出错
		alog(LOG_WARNING, 0,
		     __FUNCTION__, "Bad hello interval extension!");
	    break;
	case RREP_HELLO_NEIGHBOR_SET_EXT:							 	//当ext的类型是RREP_HELLO_NEIGHBOR_SET_EXT

#ifdef DEBUG_HELLO
	    DEBUG(LOG_INFO, 0, "RREP_HELLO_NEIGHBOR_SET_EXT");
#endif
	    for (i = 0; i < ext->length; i = i + 4) {					
		ext_neighbor.s_addr =
		    *(in_addr_t *) ((char *) AODV_EXT_DATA(ext) + i);		//获得ext中的邻居的IP地址

		if (ext_neighbor.s_addr == DEV_IFINDEX(ifindex).ipaddr.s_addr)	//如果是本机地址
		    flags &= ~RT_UNIDIR;									//flag设为0
	    }
	    break;
	default:
	    alog(LOG_WARNING, 0, __FUNCTION__,
		 "Bad extension!! type=%d, length=%d", ext->type, ext->length);
	    ext = NULL;
	    break;
	}
	if (ext == NULL)
	    break;

	rreplen -= AODV_EXT_SIZE(ext);				//rreplen长度减小一个ext
	ext = AODV_EXT_NEXT(ext);					//ext更变为下一个
    }

#ifdef DEBUG_HELLO
    DEBUG(LOG_DEBUG, 0, "rcvd HELLO from %s, seqno %lu",
	  ip_to_str(hello_dest), hello_seqno);
#endif
    /* This neighbor should only be valid after receiving 3
       consecutive hello messages... */	  
    if (receive_n_hellos)					//当设置了receive_n_hellos      则收到n（n>2）个连续的hello消息才有效
	state = INVALID;						//receive_n_hellos被设置后     state设置为0 无效
    else
	state = VALID;							//否则 state为1	  有效

    timeout = ALLOWED_HELLO_LOSS * hello_interval + ROUTE_TIMEOUT_SLACK;   	//计算timeout   允许的hello丢失数*两个之间的间隔+100ms

    if (!rt) {
	/* No active or expired route in the routing table. So we add a     	路由表中没有活动或过期的路由。 因此，我们添加了一个新条目
	   new entry... */

	rt = rt_table_insert(hello_dest, hello_dest, 1,							//添加一条新路由
			     hello_seqno, timeout, state, flags, ifindex);

	if (flags & RT_UNIDIR) {											
	    DEBUG(LOG_INFO, 0, "%s new NEIGHBOR, link UNI-DIR",					//如果flags为1 则是新邻居 且为单向连接
		  ip_to_str(rt->dest_addr));
	} else {
	    DEBUG(LOG_INFO, 0, "%s new NEIGHBOR!", ip_to_str(rt->dest_addr));	//如果flags为0 则是一个新邻居
	}
	rt->hello_cnt = 1;														//路由表项的目前收到的hello数设为1

    } else {																//路由表中有路由

	if ((flags & RT_UNIDIR) && rt->state == VALID && rt->hcnt > 1) {     	//如果flags为1 表项为一个hello有效 距离目的地的跳数大于1
	    goto hello_update;													//跳转到hello_update
	}

	if (receive_n_hellos && rt->hello_cnt < (receive_n_hellos - 1)) {		//如果receive_n_hellos开启 而且收到的hello数小于目标数-1
	    if (timeval_diff(&now, &rt->last_hello_time) <						//计算当前时间与上一次发送hello的时间差
		(long) (hello_interval + hello_interval / 2))						//当其小于设置的间隔的2/3  
		rt->hello_cnt++;													//表项收到的hello数+1
	    else		
		rt->hello_cnt = 1;													//否则重置为1

	    memcpy(&rt->last_hello_time, &now, sizeof(struct timeval));			//将当前时间更新为最新一次发送的hello时间
	    return;
	}
	rt_table_update(rt, hello_dest, 1, hello_seqno, timeout, VALID, flags);		//路由表更新
    }

  hello_update:										

    hello_update_timeout(rt, &now, ALLOWED_HELLO_LOSS * hello_interval);		//调用下边的函数
    return;
}


#define HELLO_DELAY 50		/* The extra time we should allow an hello
				   message to take (due to processing) before
				   assuming lost . */

NS_INLINE void NS_CLASS hello_update_timeout(rt_table_t * rt,
					     struct timeval *now, long time)
{
    timer_set_timeout(&rt->hello_timer, time + HELLO_DELAY);				//将hello_timer的timeout设置为time+延迟
    memcpy(&rt->last_hello_time, now, sizeof(struct timeval));				//将当前时间更新为最新一次发送的hello时间
}
