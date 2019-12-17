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
#include <linux/version.h>
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,19))
#include <linux/config.h>
#endif
#include <linux/if.h>
#include <linux/skbuff.h>
#include <linux/spinlock.h>
#include <linux/netlink.h>
#include <linux/version.h>

#ifdef KERNEL26
#include <linux/security.h>
#endif
#include <net/sock.h>

#include "kaodv-netlink.h"
#include "kaodv-expl.h"
#include "kaodv-queue.h"
#include "kaodv-debug.h"
#include "kaodv.h"

static int peer_pid;
static struct sock *kaodvnl;
static DECLARE_MUTEX(kaodvnl_sem);

/* For 2.4 backwards compatibility */
#ifndef KERNEL26
#define sk_receive_queue receive_queue
#define sk_socket socket
#endif

extern int active_route_timeout, qual_th, is_gateway;

static struct sk_buff *kaodv_netlink_build_msg(int type, void *data, int len)//创建路由信息
{
	unsigned char *old_tail;
	size_t size = 0;
	struct sk_buff *skb;
	struct nlmsghdr *nlh;// nlmsghdr结构 Length of message  / Message type /  Additional flags / Sequence number /  Sending process PID
	void *m;

	size = NLMSG_SPACE(len);//LMSG_SPACE返回不小于NLMSG_LENGTH(len)且字节对齐的最小数值，它也用于分配消息缓存。

	skb = alloc_skb(size, GFP_ATOMIC);//为skbuff申请内核空间,GFP_ATOMIC用来从中断处理和进程上下文之外的其他代码中分配内存. 从不睡眠.

	if (!skb)
		goto nlmsg_failure;

	old_tail = SKB_TAIL_PTR(skb);//old_tail指向skbuff的末尾
	nlh = NLMSG_PUT(skb, 0, 0, type, size - sizeof(*nlh));//nlmsg_put把nlh填入skb

	m = NLMSG_DATA(nlh);//nlmsg_data用于取得消息的数据部分的首地址，设置和读取消息数据部分时需要使用该宏。

	memcpy(m, data, len);
	
	nlh->nlmsg_len = SKB_TAIL_PTR(skb) - old_tail;
	NETLINK_CB(skb).pid = 0;  /* from kernel */
	
	return skb;

      nlmsg_failure:
	if (skb)
		kfree_skb(skb);

	printk(KERN_ERR "kaodv: error creating rt timeout message\n");

	return NULL;
}

void kaodv_netlink_send_debug_msg(char *buf, int len)
{
	struct sk_buff *skb = NULL;

	skb = kaodv_netlink_build_msg(KAODVM_DEBUG, buf, len);//创建DEBUG信息

	if (skb == NULL) {
		printk("kaodv_netlink: skb=NULL\n");
		return;
	}

	netlink_broadcast(kaodvnl, skb, peer_pid, AODVGRP_NOTIFY, GFP_USER);//发送广播消息
}

void kaodv_netlink_send_rt_msg(int type, __u32 src, __u32 dest)
{
	struct sk_buff *skb = NULL;
	struct kaodv_rt_msg m;

	memset(&m, 0, sizeof(m));

	m.src = src;
	m.dst = dest;

	skb = kaodv_netlink_build_msg(type, &m, sizeof(struct kaodv_rt_msg));//创建路由信息

	if (skb == NULL) {
		printk("kaodv_netlink: skb=NULL\n");
		return;
	}

/* 	netlink_unicast(kaodvnl, skb, peer_pid, MSG_DONTWAIT); */
	netlink_broadcast(kaodvnl, skb, 0, AODVGRP_NOTIFY, GFP_USER);//广播发送
}

void kaodv_netlink_send_rt_update_msg(int type, __u32 src, __u32 dest,
				      int ifindex)
{
	struct sk_buff *skb = NULL;
	struct kaodv_rt_msg m;

	memset(&m, 0, sizeof(m));

	m.type = type;
	m.src = src;
	m.dst = dest;
	m.ifindex = ifindex;

	skb = kaodv_netlink_build_msg(KAODVM_ROUTE_UPDATE, &m,
				      sizeof(struct kaodv_rt_msg));//创建路由更新信息

	if (skb == NULL) {
		printk("kaodv_netlink: skb=NULL\n");
		return;
	}
	/* netlink_unicast(kaodvnl, skb, peer_pid, MSG_DONTWAIT); */
	netlink_broadcast(kaodvnl, skb, 0, AODVGRP_NOTIFY, GFP_USER);//广播发送
}

void kaodv_netlink_send_rerr_msg(int type, __u32 src, __u32 dest, int ifindex)
{
	struct sk_buff *skb = NULL;
	struct kaodv_rt_msg m;

	memset(&m, 0, sizeof(m));

	m.type = type;
	m.src = src;
	m.dst = dest;
	m.ifindex = ifindex;

	skb = kaodv_netlink_build_msg(KAODVM_SEND_RERR, &m,
				      sizeof(struct kaodv_rt_msg));//创建路由错误信息

	if (skb == NULL) {
		printk("kaodv_netlink: skb=NULL\n");
		return;
	}
	/* netlink_unicast(kaodvnl, skb, peer_pid, MSG_DONTWAIT); */
	netlink_broadcast(kaodvnl, skb, 0, AODVGRP_NOTIFY, GFP_USER);//广播发送
}

static int kaodv_netlink_receive_peer(unsigned char type, void *msg,
				      unsigned int len)
{
	int ret = 0;
	struct kaodv_rt_msg *m;
	struct kaodv_conf_msg *cm;
	struct expl_entry e;

	KAODV_DEBUG("Received msg: %s", kaodv_msg_type_to_str(type));

	switch (type) {
	case KAODVM_ADDROUTE:  //路由添加
		if (len < sizeof(struct kaodv_rt_msg))//如果大小不符
			return -EINVAL;

		m = (struct kaodv_rt_msg *)msg;

		ret = kaodv_expl_get(m->dst, &e);//按目的地地址在超时列表中查找

		if (ret < 0) {					//找到了
			ret = kaodv_expl_update(m->dst, m->nhop, m->time,
						m->flags, m->ifindex);//更新expl表
		} else {                        //没找到
			ret = kaodv_expl_add(m->dst, m->nhop, m->time,
					     m->flags, m->ifindex);//把m添加到expl表中
		}
		kaodv_queue_set_verdict(KAODV_QUEUE_SEND, m->dst);//执行发送指令
		break;
	case KAODVM_DELROUTE:    //路由删除
		if (len < sizeof(struct kaodv_rt_msg))//大小不符合
			return -EINVAL;

		m = (struct kaodv_rt_msg *)msg;
		kaodv_expl_del(m->dst);//按目的节点删除expl中的表项
		kaodv_queue_set_verdict(KAODV_QUEUE_DROP, m->dst);//执行丢弃指令
		break;
	case KAODVM_NOROUTE_FOUND:  //没有路由发现
		if (len < sizeof(struct kaodv_rt_msg))//大小不符
			return -EINVAL;

		m = (struct kaodv_rt_msg *)msg;
		KAODV_DEBUG("No route found for %s", print_ip(m->dst));
		kaodv_queue_set_verdict(KAODV_QUEUE_DROP, m->dst);   //执行丢弃
		break;
	case KAODVM_CONFIG:          //配置
		if (len < sizeof(struct kaodv_conf_msg))//大小不符
			return -EINVAL;

		cm = (struct kaodv_conf_msg *)msg;
		active_route_timeout = cm->active_route_timeout;
		qual_th = cm->qual_th;
		is_gateway = cm->is_gateway;//进行配置操作
		break;
	default:
		printk("kaodv-netlink: Unknown message type\n");
		ret = -EINVAL;
	}
	return ret;
}

static int kaodv_netlink_rcv_nl_event(struct notifier_block *this,
				      unsigned long event, void *ptr)//接收到nl时间处理
{
	struct netlink_notify *n = ptr;


	if (event == NETLINK_URELEASE && n->protocol == NETLINK_AODV && n->pid) {//判断协议是否为aodv，且为当前进程
		if (n->pid == peer_pid) {
			peer_pid = 0;
			kaodv_expl_flush();//清空expl
			kaodv_queue_flush();//清空队列
		}
		return NOTIFY_DONE;
	}
	return NOTIFY_DONE;
}

static struct notifier_block kaodv_nl_notifier = {
	.notifier_call = kaodv_netlink_rcv_nl_event,
};

#define RCV_SKB_FAIL(err) do { netlink_ack(skb, nlh, (err)); return; } while (0)

static inline void kaodv_netlink_rcv_skb(struct sk_buff *skb)//处理skb部分
{
	int status, type, pid, flags, nlmsglen, skblen;
	struct nlmsghdr *nlh;

	skblen = skb->len;
	if (skblen < sizeof(struct nlmsghdr)) {
		printk("skblen to small\n");
		return;
	}

	nlh = (struct nlmsghdr *)skb->data;
	nlmsglen = nlh->nlmsg_len;
	
	if (nlmsglen < sizeof(struct nlmsghdr) || skblen < nlmsglen) {
		printk("nlsmsg=%d skblen=%d to small\n", nlmsglen, skblen);
		return;
	}

	pid = nlh->nlmsg_pid;
	flags = nlh->nlmsg_flags;

	if (pid <= 0 || !(flags & NLM_F_REQUEST) || flags & NLM_F_MULTI)
		RCV_SKB_FAIL(-EINVAL);


	if (flags & MSG_TRUNC)
		RCV_SKB_FAIL(-ECOMM);

	type = nlh->nlmsg_type;

/* 	printk("kaodv_netlink: type=%d\n", type); */
	/* if (type < NLMSG_NOOP || type >= IPQM_MAX) */
/* 		RCV_SKB_FAIL(-EINVAL); */
#ifdef KERNEL26
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,18))
	if (security_netlink_recv(skb))
		RCV_SKB_FAIL(-EPERM);
#else
	if (security_netlink_recv(skb, CAP_NET_ADMIN))
		RCV_SKB_FAIL(-EPERM);
#endif
#endif
	//write_lock_bh(&queue_lock);
	
	if (peer_pid) {
		if (peer_pid != pid) {  //内核中别的进展在执行
			//write_unlock_bh(&queue_lock);
			RCV_SKB_FAIL(-EBUSY);//繁忙
		}
	} else
		peer_pid = pid;

	//write_unlock_bh(&queue_lock);

	status = kaodv_netlink_receive_peer(type, NLMSG_DATA(nlh),
					    skblen - NLMSG_LENGTH(0));//调用netlink处理函数
	if (status < 0)
		RCV_SKB_FAIL(status);

	if (flags & NLM_F_ACK)
		netlink_ack(skb, nlh, 0);
	return;
}

#if 0
static void kaodv_netlink_rcv_sk(struct sock *sk, int len)
{
	do {
		struct sk_buff *skb;

		if (down_trylock(&kaodvnl_sem))
			return;

		while ((skb = skb_dequeue(&sk->sk_receive_queue)) != NULL) {
			kaodv_netlink_rcv_skb(skb);
			kfree_skb(skb);
		}

		up(&kaodvnl_sem);

	} while (kaodvnl && kaodvnl->sk_receive_queue.qlen);

	return;
}
#endif

int kaodv_netlink_init(void)
{
	netlink_register_notifier(&kaodv_nl_notifier);//在netlink_register链上注册一个回调函数kaodv_nl_notifier
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,14))
	kaodvnl = netlink_kernel_create(NETLINK_AODV, kaodv_netlink_rcv_sk);
#elif (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,22))
	kaodvnl = netlink_kernel_create(NETLINK_AODV, AODVGRP_MAX, kaodv_netlink_rcv_sk, THIS_MODULE);
#elif (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24))
	kaodvnl = netlink_kernel_create(NETLINK_AODV, AODVGRP_MAX, kaodv_netlink_rcv_sk, NULL, THIS_MODULE);
#else
	kaodvnl = netlink_kernel_create(&init_net, NETLINK_AODV, AODVGRP_MAX,
                    kaodv_netlink_rcv_skb, NULL, THIS_MODULE);
#endif
   //创建kaodvnl
	if (kaodvnl == NULL) {
		printk(KERN_ERR "kaodv_netlink: failed to create netlink socket\n");
		netlink_unregister_notifier(&kaodv_nl_notifier);
		return -1;
	}
	return 0;
}

void kaodv_netlink_fini(void)
{
	sock_release(kaodvnl->sk_socket);//释放套接字
	down(&kaodvnl_sem);
	up(&kaodvnl_sem);

	netlink_unregister_notifier(&kaodv_nl_notifier);//在netlink_unregister链上注册一个回调函数kaodv_nl_notifier
}
