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
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <asm/types.h>
#include <linux/netlink.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/rtnetlink.h>

#include "defs.h"
#include "lnx/kaodv-netlink.h"
#include "debug.h"
#include "aodv_rreq.h"
#include "aodv_timeout.h"
#include "routing_table.h"
#include "aodv_hello.h"
#include "params.h"
#include "aodv_socket.h"
#include "aodv_rerr.h"
//补充的 一些必要的结构 sockaddr_nl nlmsghdr
struct sockaddr_nl
{
sa_family_t    nl_family;
unsigned short nl_pad;
__u32          nl_pid;   //进程pid
__u32          nl_groups;//多播组掩码
};
struct nlmsghdr
{
__u32 nlmsg_len;   // Length of message 
__u16 nlmsg_type;  // Message type
__u16 nlmsg_flags; // Additional flags 
__u32 nlmsg_seq;   // Sequence number 
__u32 nlmsg_pid;   // Sending process PID 
};

struct in_addr
{
    union
    {
        struct
        {
            u_char s_b1,s_b2,s_b3,s_b4;
        } S_un_b; //An IPv4 address formatted as four u_chars.
        struct
        {
            u_short s_w1,s_w2;
        } S_un_w; //An IPv4 address formatted as two u_shorts
       u_long S_addr;//An IPv4 address formatted as a u_long
    } S_un;
//#define s_addr S_un.S_addr
};
struct msghdr {
    void         *msg_name;
    socklen_t    msg_namelen;
    struct iovec *msg_iov;
    size_t       msg_iovlen;
    void         *msg_control;
    size_t       msg_controllen;
    int          msg_flags;
};



/* Implements a Netlink socket communication channel to the kernel. Route
 * information and refresh messages are passed. */

struct nlsock {
	int sock;
	int seq;
	struct sockaddr_nl local;//sockaddr_nl结构 AF_NETLINK nl_pad 进程pid 多播组掩码
};

struct sockaddr_nl peer = { AF_NETLINK, 0, 0, 0 };

struct nlsock aodvnl;//aodvnl 协议套接字
struct nlsock rtnl;// rtnl 路由表套接字

static void nl_kaodv_callback(int sock);
static void nl_rt_callback(int sock);

extern int llfeedback, active_route_timeout, qual_threshold, internet_gw_mode,
    wait_on_reboot;
extern struct timer worb_timer;//获取main函数中的全局变量，这些变量都在main函数中已经赋值

#define BUFLEN 256

/* #define DEBUG_NETLINK */

void nl_init(void)//对用户层nl模块进行初始化
{
	int status;
	unsigned int addrlen;

	memset(&peer, 0, sizeof(struct sockaddr_nl));//为peer申请空间
	peer.nl_family = AF_NETLINK;
	peer.nl_pid = 0;
	peer.nl_groups = 0;

	memset(&aodvnl, 0, sizeof(struct nlsock));//为aodvnl申请空间并赋值
	aodvnl.seq = 0;
	aodvnl.local.nl_family = AF_NETLINK;
	aodvnl.local.nl_groups = AODVGRP_NOTIFY;
	aodvnl.local.nl_pid = getpid();

	/* This is the AODV specific socket to communicate with the
	   AODV kernel module */
	aodvnl.sock = socket(PF_NETLINK, SOCK_RAW, NETLINK_AODV);//adodvnl是与内核aodv通信的套接字

	if (aodvnl.sock < 0) {//获取失败
		perror("Unable to create AODV netlink socket");
		exit(-1);
	}


	status = bind(aodvnl.sock, (struct sockaddr *) &aodvnl.local,
		      sizeof(aodvnl.local));//绑定套接字

	if (status == -1) {//bind失败
		perror("Bind for AODV netlink socket failed");
		exit(-1);
	}

	addrlen = sizeof(aodvnl.local);

	if (getsockname//获取aodv套接字名字
	    (aodvnl.sock, (struct sockaddr *) &aodvnl.local, &addrlen) < 0) {
		perror("Getsockname failed ");
		exit(-1);
	}

	if (attach_callback_func(aodvnl.sock, nl_kaodv_callback) < 0) {//检查回调函数连接，连接成功返回0否则为-1
		alog(LOG_ERR, 0, __FUNCTION__, "Could not attach callback.");
	}
	/* This socket is the generic routing socket for adding and
	   removing kernel routing table entries */
// rtnl 套接字是用于添加和删除内核路由表项的通用路由套接字
	memset(&rtnl, 0, sizeof(struct nlsock));//申请空间并赋值
	rtnl.seq = 0;
	rtnl.local.nl_family = AF_NETLINK;
	rtnl.local.nl_groups =
	    RTMGRP_NOTIFY | RTMGRP_IPV4_IFADDR | RTMGRP_IPV4_ROUTE;
	rtnl.local.nl_pid = getpid();

	rtnl.sock = socket(PF_NETLINK, SOCK_RAW, NETLINK_ROUTE);

	if (rtnl.sock < 0) {
		perror("Unable to create RT netlink socket");
		exit(-1);
	}

	addrlen = sizeof(rtnl.local);

	status = bind(rtnl.sock, (struct sockaddr *) &rtnl.local, addrlen);

	if (status == -1) {
		perror("Bind for RT netlink socket failed");
		exit(-1);
	}

	if (getsockname(rtnl.sock, (struct sockaddr *) &rtnl.local, &addrlen) <
	    0) {
		perror("Getsockname failed ");
		exit(-1);
	}

	if (attach_callback_func(rtnl.sock, nl_rt_callback) < 0) {
		alog(LOG_ERR, 0, __FUNCTION__, "Could not attach callback.");
	}
}

void nl_cleanup(void)
{
	close(aodvnl.sock);//关闭aodvnl以及rtnl的套接字
	close(rtnl.sock);
}


static void nl_kaodv_callback(int sock)
{
	int len;
	socklen_t addrlen;
	struct nlmsghdr *nlm;
	struct nlmsgerr *nlmerr;
	char buf[BUFLEN];
	struct in_addr dest_addr, src_addr;
	kaodv_rt_msg_t *m;
	rt_table_t *rt, *fwd_rt, *rev_rt = NULL;

	addrlen = sizeof(struct sockaddr_nl);


	len =
	    recvfrom(sock, buf, BUFLEN, 0, (struct sockaddr *) &peer, &addrlen);

	if (len <= 0)
		return;

	nlm = (struct nlmsghdr *) buf;

	switch (nlm->nlmsg_type) {
	case NLMSG_ERROR://类型为错误
		nlmerr = NLMSG_DATA(nlm);
		if (nlmerr->error == 0) {
		/* 	DEBUG(LOG_DEBUG, 0, "NLMSG_ACK"); */
		} else {
			DEBUG(LOG_DEBUG, 0, "NLMSG_ERROR, error=%d type=%s",
			      nlmerr->error, 
			      kaodv_msg_type_to_str(nlmerr->msg.nlmsg_type));
		}
		break;

	case KAODVM_DEBUG://类型为内核aodv-debug信息
		DEBUG(LOG_DEBUG, 0, "kaodv: %s", NLMSG_DATA(nlm));
		break;
       	case KAODVM_TIMEOUT://内核aodv超时信息
		m = NLMSG_DATA(nlm);
		dest_addr.s_addr = m->dst;

		DEBUG(LOG_DEBUG, 0,
		      "Got TIMEOUT msg from kernel for %s",
		      ip_to_str(dest_addr));

		rt = rt_table_find(dest_addr);//按目的地址查找路由表

		if (rt && rt->state == VALID)
			route_expire_timeout(rt);//设置路由到期
		else
			DEBUG(LOG_DEBUG, 0,
			      "Got rt timeoute event but there is no route");
		break;
	case KAODVM_ROUTE_REQ://类型为内核aodv路由的rreq
		m = NLMSG_DATA(nlm);
		dest_addr.s_addr = m->dst;

		DEBUG(LOG_DEBUG, 0, "Got ROUTE_REQ: %s from kernel",
		      ip_to_str(dest_addr));

		rreq_route_discovery(dest_addr, 0, NULL);//执行路由发现操作
		break;
	case KAODVM_REPAIR://类型为路由修复
		m = NLMSG_DATA(nlm);
		dest_addr.s_addr = m->dst;
		src_addr.s_addr = m->src;

		DEBUG(LOG_DEBUG, 0, "Got REPAIR from kernel for %s",
		      ip_to_str(dest_addr));

		fwd_rt = rt_table_find(dest_addr);//按目的地址在路由表中查找要修复的表项

		if (fwd_rt)//找到了
			rreq_local_repair(fwd_rt, src_addr, NULL);//发送rreq路由请求用于路由修复

		break;
	case KAODVM_ROUTE_UPDATE://类型为路由更新
		m = NLMSG_DATA(nlm);

		
		dest_addr.s_addr = m->dst;
		src_addr.s_addr = m->src;

		//	DEBUG(LOG_DEBUG, 0, "ROute update s=%s d=%s", ip_to_str(src_addr), ip_to_str(dest_addr));
		if (dest_addr.s_addr == AODV_BROADCAST ||
		    dest_addr.s_addr ==
		    DEV_IFINDEX(m->ifindex).broadcast.s_addr)
			return;//如果是自己发送出去的广播数据包，不做处理

		fwd_rt = rt_table_find(dest_addr);//在路由表中查找目的地址
		rev_rt = rt_table_find(src_addr);//在路由表中查找源地址

		rt_table_update_route_timeouts(fwd_rt, rev_rt);//进行路由更新操作

		break;
	case KAODVM_SEND_RERR://类型为发送的路由错误信息
		m = NLMSG_DATA(nlm);
		dest_addr.s_addr = m->dst;
		src_addr.s_addr = m->src;

		if (dest_addr.s_addr == AODV_BROADCAST ||
		    dest_addr.s_addr ==
		    DEV_IFINDEX(m->ifindex).broadcast.s_addr)
			return;//是自己发送出去的广播数据包

		fwd_rt = rt_table_find(dest_addr);//查找RERR中目的地址是否存在自己的路由表中
		rev_rt = rt_table_find(src_addr);//查找源地址是否在自己路由表中

		do {
			struct in_addr rerr_dest;
			RERR *rerr;

			DEBUG(LOG_DEBUG, 0,
			      "Sending RERR for unsolicited message from %s to dest %s",
			      ip_to_str(src_addr), ip_to_str(dest_addr));

			if (fwd_rt) {//在路由表中找到不可达的目的地址
				rerr = rerr_create(0, fwd_rt->dest_addr,
						   fwd_rt->dest_seqno);//找到了，创建rerr

				rt_table_update_timeout(fwd_rt, DELETE_PERIOD);//把路由表中该项设置超时
			} else
				rerr = rerr_create(0, dest_addr, 0);//没找到创建rerr消息

			/* Unicast the RERR to the source of the data transmission
			 * if possible, otherwise we broadcast it. */

			if (rev_rt && rev_rt->state == VALID)//下一跳有效的表项实现单播
				rerr_dest = rev_rt->next_hop;
			else
				rerr_dest.s_addr = AODV_BROADCAST;//否则广播

			aodv_socket_send((AODV_msg *) rerr, rerr_dest,
					 RERR_CALC_SIZE(rerr), 1,
					 &DEV_IFINDEX(m->ifindex));//发送创建的rerr

			if (wait_on_reboot) {
				DEBUG(LOG_DEBUG, 0,
				      "Wait on reboot timer reset.");
				timer_set_timeout(&worb_timer, DELETE_PERIOD);
			}
		} while (0);
		break;
	default:
		DEBUG(LOG_DEBUG, 0, "Got mesg type=%d\n", nlm->nlmsg_type);
	}

}
static void nl_rt_callback(int sock)//用于初始化中测试路由回调函数是否正常
{
	int len, attrlen;
	socklen_t addrlen;
	struct nlmsghdr *nlm;
	struct nlmsgerr *nlmerr;
	char buf[BUFLEN];
	struct ifaddrmsg *ifm;
	struct rtattr *rta;

	addrlen = sizeof(struct sockaddr_nl);

	len =
	    recvfrom(sock, buf, BUFLEN, 0, (struct sockaddr *) &peer, &addrlen);

	if (len <= 0)
		return;

	nlm = (struct nlmsghdr *) buf;

	switch (nlm->nlmsg_type) {
	case NLMSG_ERROR:
		nlmerr = NLMSG_DATA(nlm);
		if (nlmerr->error == 0) {
		/* 	DEBUG(LOG_DEBUG, 0, "NLMSG_ACK"); */
		} else {
			DEBUG(LOG_DEBUG, 0, "NLMSG_ERROR, error=%d type=%d",
			      nlmerr->error, nlmerr->msg.nlmsg_type);
		}
		break;
	case RTM_NEWLINK:
		DEBUG(LOG_DEBUG, 0, "RTM_NEWADDR");
		break;
	case RTM_NEWADDR:
		ifm = NLMSG_DATA(nlm);

		rta = (struct rtattr *) ((char *) ifm + sizeof(ifm));

		attrlen = nlm->nlmsg_len -
		    sizeof(struct nlmsghdr) - sizeof(struct ifaddrmsg);

		for (; RTA_OK(rta, attrlen); rta = RTA_NEXT(rta, attrlen)) {

			if (rta->rta_type == IFA_ADDRESS) {
				struct in_addr ifaddr;

				memcpy(&ifaddr, RTA_DATA(rta),
				       RTA_PAYLOAD(rta));

				DEBUG(LOG_DEBUG, 0,
				      "Interface index %d changed address to %s",
				      ifm->ifa_index, ip_to_str(ifaddr));
			}
		}
		break;
	case RTM_NEWROUTE:
		/* DEBUG(LOG_DEBUG, 0, "RTM_NEWROUTE"); */
		break;
	}
	return;
}

int prefix_length(int family, void *nm)//计算路由表项中前驱的长度
{
	int prefix = 0;

	if (family == AF_INET) {
		unsigned int tmp;
		memcpy(&tmp, nm, sizeof(unsigned int));

		while (tmp) {
			tmp = tmp << 1;
			prefix++;
		}
		return prefix;

	} else {
		DEBUG(LOG_DEBUG, 0, "Unsupported address family");
	}

	return 0;
}

/* Utility function  comes from iproute2. 
   Authors:	Alexey Kuznetsov, <kuznet@ms2.inr.ac.ru> */
int addattr(struct nlmsghdr *n, int type, void *data, int alen)
{
	struct rtattr *attr;
	int len = RTA_LENGTH(alen);

	attr = (struct rtattr *) (((char *) n) + NLMSG_ALIGN(n->nlmsg_len));
	attr->rta_type = type;
	attr->rta_len = len;
	memcpy(RTA_DATA(attr), data, alen);
	n->nlmsg_len = NLMSG_ALIGN(n->nlmsg_len) + len;

	return 0;
}


#define ATTR_BUFLEN 512

int nl_send(struct nlsock *nl, struct nlmsghdr *n)
{
	int res;
	struct iovec iov = { (void *) n, n->nlmsg_len };
	struct msghdr msg =
	    { (void *) &peer, sizeof(peer), &iov, 1, NULL, 0, 0 };
	// int flags = 0;

	if (!nl)
		return -1;

	n->nlmsg_seq = ++nl->seq;
	n->nlmsg_pid = nl->local.nl_pid;

	/* Request an acknowledgement by setting NLM_F_ACK */
	n->nlmsg_flags |= NLM_F_ACK;

	/* Send message to netlink interface. */
	res = sendmsg(nl->sock, &msg, 0);//把msg发送到netlink接口

	if (res < 0) {
		fprintf(stderr, "error: %s\n", strerror(errno));
		return -1;
	}
	return 0;
}

/* Function to add, remove and update entries in the kernel routing
 * table */
 //用于在内核路由表中添加 删除 更新表项
int nl_kern_route(int action, int flags, int family,
		  int index, struct in_addr *dst, struct in_addr *gw,
		  struct in_addr *nm, int metric)
{
	struct {
		struct nlmsghdr nlh;
		struct rtmsg rtm;
		char attrbuf[1024];
	} req;

	if (!dst || !gw)
		return -1;

	req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
	req.nlh.nlmsg_type = action;
	req.nlh.nlmsg_flags = NLM_F_REQUEST | flags;
	req.nlh.nlmsg_pid = 0;

	req.rtm.rtm_family = family;

	if (!nm)
		req.rtm.rtm_dst_len = sizeof(struct in_addr) * 8;
	else
		req.rtm.rtm_dst_len = prefix_length(AF_INET, nm);

	req.rtm.rtm_src_len = 0;
	req.rtm.rtm_tos = 0;
	req.rtm.rtm_table = RT_TABLE_MAIN;
	req.rtm.rtm_protocol = 100;
	req.rtm.rtm_scope = RT_SCOPE_LINK;
	req.rtm.rtm_type = RTN_UNICAST;
	req.rtm.rtm_flags = 0;

	addattr(&req.nlh, RTA_DST, dst, sizeof(struct in_addr));

	if (memcmp(dst, gw, sizeof(struct in_addr)) != 0) {
		req.rtm.rtm_scope = RT_SCOPE_UNIVERSE;
		addattr(&req.nlh, RTA_GATEWAY, gw, sizeof(struct in_addr));
	}

	if (index > 0)
		addattr(&req.nlh, RTA_OIF, &index, sizeof(index));

	addattr(&req.nlh, RTA_PRIORITY, &metric, sizeof(metric));//实际上也是定义结构，申请空间，并赋值，并没有具体操作，具体操作在内核层实现，这里调用rtnl套接字交给了内核处理

	return nl_send(&rtnl, &req.nlh);//调用rtnl套接字修改内核中的路由表
}

int nl_send_add_route_msg(struct in_addr dest, struct in_addr next_hop,
			  int metric, u_int32_t lifetime, int rt_flags,
			  int ifindex)
{
	struct {
		struct nlmsghdr n;
		struct kaodv_rt_msg m;
	} areq;

	DEBUG(LOG_DEBUG, 0, "ADD/UPDATE: %s:%s ifindex=%d",
	      ip_to_str(dest), ip_to_str(next_hop), ifindex);

	memset(&areq, 0, sizeof(areq));

	areq.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct kaodv_rt_msg));
	areq.n.nlmsg_type = KAODVM_ADDROUTE;//类型为添加路由条目
	areq.n.nlmsg_flags = NLM_F_REQUEST;

	areq.m.dst = dest.s_addr;
	areq.m.nhop = next_hop.s_addr;
	areq.m.time = lifetime;
	areq.m.ifindex = ifindex;

	if (rt_flags & RT_INET_DEST) {
		areq.m.flags |= KAODV_RT_GW_ENCAP;
	}

	if (rt_flags & RT_REPAIR)
		areq.m.flags |= KAODV_RT_REPAIR;

	if (nl_send(&aodvnl, &areq.n) < 0) {
		DEBUG(LOG_DEBUG, 0, "Failed to send netlink message");
		return -1;
	}
#ifdef DEBUG_NETLINK
	DEBUG(LOG_DEBUG, 0, "Sending add route");
#endif
	return nl_kern_route(RTM_NEWROUTE, NLM_F_CREATE,
			     AF_INET, ifindex, &dest, &next_hop, NULL, metric);//调用nl_kern_route在内核中创建新表项
}

int nl_send_no_route_found_msg(struct in_addr dest)
{
	struct {
		struct nlmsghdr n;
		kaodv_rt_msg_t m;
	} areq;

	memset(&areq, 0, sizeof(areq));

	areq.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct kaodv_rt_msg));
	areq.n.nlmsg_type = KAODVM_NOROUTE_FOUND;//类型为无路径发现
	areq.n.nlmsg_flags = NLM_F_REQUEST;

	areq.m.dst = dest.s_addr;

	DEBUG(LOG_DEBUG, 0, "Send NOROUTE_FOUND to kernel: %s",
	      ip_to_str(dest));

	return nl_send(&aodvnl, &areq.n);
}

int nl_send_del_route_msg(struct in_addr dest, struct in_addr next_hop, int metric)
{
	int index = -1;
	struct {
		struct nlmsghdr n;
		struct kaodv_rt_msg m;//内核路由信息
	} areq;

	DEBUG(LOG_DEBUG, 0, "Send DEL_ROUTE to kernel: %s", ip_to_str(dest));

	memset(&areq, 0, sizeof(areq));

	areq.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct kaodv_rt_msg));
	areq.n.nlmsg_type = KAODVM_DELROUTE;//类型为删除路由表项
	areq.n.nlmsg_flags = NLM_F_REQUEST;

	areq.m.dst = dest.s_addr;
	areq.m.nhop = next_hop.s_addr;
	areq.m.time = 0;
	areq.m.flags = 0;

	if (nl_send(&aodvnl, &areq.n) < 0) {//调用套接字失败
		DEBUG(LOG_DEBUG, 0, "Failed to send netlink message");
		return -1;
	}
#ifdef DEBUG_NETLINK
	DEBUG(LOG_DEBUG, 0, "Sending del route");
#endif
	return nl_kern_route(RTM_DELROUTE, 0, AF_INET, index, &dest, &next_hop,
			     NULL, metric);//调用nl_kern_route进行删除路由表项操作
}

int nl_send_conf_msg(void)//nl模块发送配置信息到内核
{
	struct {
		struct nlmsghdr n;
		kaodv_conf_msg_t cm;
	} areq;//定义结构 申请空间 并赋值

	memset(&areq, 0, sizeof(areq));

	areq.n.nlmsg_len = NLMSG_LENGTH(sizeof(kaodv_conf_msg_t));
	areq.n.nlmsg_type = KAODVM_CONFIG;
	areq.n.nlmsg_flags = NLM_F_REQUEST;

	areq.cm.qual_th = qual_threshold;
	areq.cm.active_route_timeout = active_route_timeout;
	areq.cm.is_gateway = internet_gw_mode;

#ifdef DEBUG_NETLINK
	DEBUG(LOG_DEBUG, 0, "Sending aodv conf msg");
#endif
	return nl_send(&aodvnl, &areq.n);//调用套接字发送配置信息
}
