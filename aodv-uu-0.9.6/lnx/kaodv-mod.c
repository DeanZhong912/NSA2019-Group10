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
 * Author: Erik Nordstr�m, <erik.nordstrom@it.uu.se>
 * 
 *****************************************************************************/
#include <linux/version.h>
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,19))
#include <linux/config.h>
#endif
#ifdef KERNEL26
#include <linux/moduleparam.h>
#endif
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/if.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/inetdevice.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <net/tcp.h>
#include <net/route.h>

#include "kaodv-mod.h"
#include "kaodv-expl.h"
#include "kaodv-netlink.h"
#include "kaodv-queue.h"
#include "kaodv-ipenc.h"
#include "kaodv-debug.h"
#include "kaodv.h"

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,25))//在内核中注册的五个hook
#define NF_INET_PRE_ROUTING NF_IP_PRE_ROUTING  //进入路由代码之前
#define NF_INET_LOCAL_IN NF_IP_LOCAL_IN //发往本机的数据报，经过该宏的处理传入上层
#define NF_INET_FORWARD NF_IP_FORWARD   //应该被转发的数据报，由该宏进行处理
#define NF_INET_LOCAL_OUT NF_IP_LOCAL_OUT//本地产生的数据报，由该宏进行处理
#define NF_INET_POST_ROUTING NF_IP_POST_ROUTING//应该转发的数据报经过该宏处理后发往网络
#define NF_INET_NUMHOOKS NF_IP_NUMHOOKS
#endif

#define ACTIVE_ROUTE_TIMEOUT active_route_timeout
#define MAX_INTERFACES 10

static int qual = 0;
static unsigned long pkts_dropped = 0;//丢弃包的数量？
int qual_th = 0;//qual阈值
int is_gateway = 1;//是否为网关
int active_route_timeout = 3000;
//static unsigned int loindex = 0;
//无关紧要
MODULE_DESCRIPTION
    ("AODV-UU kernel support. � Uppsala University & Ericsson AB");
MODULE_AUTHOR("Erik Nordstr�m");
#ifdef MODULE_LICENSE
MODULE_LICENSE("GPL");
#endif

#define ADDR_HOST 1
#define ADDR_BROADCAST 2

void kaodv_update_route_timeouts(int hooknum, const struct net_device *dev,
				 struct iphdr *iph)
{
	struct expl_entry e;
	struct in_addr bcaddr;
	int res;

	bcaddr.s_addr = 0; /* Stop compiler from complaining about
			    * uninitialized bcaddr */

	res = if_info_from_ifindex(NULL, &bcaddr, dev->ifindex);//读取接口设备号为dev->ifindex的广播信息到bcaddr

	if (res < 0)
		return;//没获取到

	if (hooknum == NF_INET_PRE_ROUTING)//进入内核路由之前
		kaodv_netlink_send_rt_update_msg(PKT_INBOUND, iph->saddr,
						 iph->daddr, dev->ifindex);//netlink发送路由更新信息,进到路由中
	else if (iph->daddr != INADDR_BROADCAST && iph->daddr != bcaddr.s_addr)//数据包的目的地址不是广播地址并且自己发送的广播数据包
		kaodv_netlink_send_rt_update_msg(PKT_OUTBOUND, iph->saddr,
						 iph->daddr, dev->ifindex);//发送出去的

	/* First update forward route and next hop */
	if (kaodv_expl_get(iph->daddr, &e)) {//按数据包的目的地址查找expl表项

		kaodv_expl_update(e.daddr, e.nhop, ACTIVE_ROUTE_TIMEOUT,
				  e.flags, dev->ifindex);//找到了，更新该表项的超时时间

		if (e.nhop != e.daddr && kaodv_expl_get(e.nhop, &e))//该表项的下一跳不是该表项的目的地址，把下一跳赋值给e
			kaodv_expl_update(e.daddr, e.nhop, ACTIVE_ROUTE_TIMEOUT,
					  e.flags, dev->ifindex);//更新下一跳的expl
	}
	/* Update reverse route */
	if (kaodv_expl_get(iph->saddr, &e)) {//按照原地址查找，并更新相关表项

		kaodv_expl_update(e.daddr, e.nhop, ACTIVE_ROUTE_TIMEOUT,
				  e.flags, dev->ifindex);

		if (e.nhop != e.daddr && kaodv_expl_get(e.nhop, &e))//同上，如果该表项的下一跳不是目的地址，便更新下一跳相关表项
			kaodv_expl_update(e.daddr, e.nhop, ACTIVE_ROUTE_TIMEOUT,
					  e.flags, dev->ifindex);
	}
}

static unsigned int kaodv_hook(unsigned int hooknum,
			       struct sk_buff *skb,
			       const struct net_device *in,
			       const struct net_device *out,
			       int (*okfn) (struct sk_buff *))//*最重要函数
{
	struct iphdr *iph = SKB_NETWORK_HDR_IPH(skb);
	struct expl_entry e;
	struct in_addr ifaddr, bcaddr;
	int res = 0;

	memset(&ifaddr, 0, sizeof(struct in_addr));
	memset(&bcaddr, 0, sizeof(struct in_addr));//给ifaddr和bcaddr申请空间

	/* We are only interested in IP packets */
	if (iph == NULL)
		return NF_ACCEPT;//如果类型不是ip则接收但不处理，说明不是aodv进程的数据
	
	/* We want AODV control messages to go through directly to the
	 * AODV socket.... */
	if (iph && iph->protocol == IPPROTO_UDP) {//ip报文头的上层协议是udp
		struct udphdr *udph;//udp报文头

		udph = (struct udphdr *)((char *)iph + (iph->ihl << 2));

		if (ntohs(udph->dest) == AODV_PORT ||  //udp的目的或者源地址为654端口
		    ntohs(udph->source) == AODV_PORT) {

#ifdef CONFIG_QUAL_THRESHOLD
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0))
			qual = (int)(skb)->__unused;
#elif (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0))
			qual = (skb)->iwq.qual;
#endif
			if (qual_th && hooknum == NF_INET_PRE_ROUTING) {

				if (qual && qual < qual_th) {//不符合要求，丢弃
					pkts_dropped++;
					return NF_DROP;
				}
			}
#endif /* CONFIG_QUAL_THRESHOLD */
			if (hooknum == NF_INET_PRE_ROUTING && in)
				kaodv_update_route_timeouts(hooknum, in, iph);//进入内核路由之前

			return NF_ACCEPT;//用udp发过来，我接收了，可能是hello消息？使用udp作为报文头区分hello？
		}
	}
	
	if (hooknum == NF_INET_PRE_ROUTING)//判断是否是要进路由
		res = if_info_from_ifindex(&ifaddr, &bcaddr, in->ifindex);//是的话读取接口地址
	else 
		res = if_info_from_ifindex(&ifaddr, &bcaddr, out->ifindex);//不是则获取接口信息中的广播地址
	
	if (res < 0)//读取成功
		return NF_ACCEPT;//正常处理
	

	/* Ignore broadcast and multicast packets */
	if (iph->daddr == INADDR_BROADCAST ||
	    IN_MULTICAST(ntohl(iph->daddr)) || 
	    iph->daddr == bcaddr.s_addr)//忽略广播和多播
		return NF_ACCEPT;

       
	/* Check which hook the packet is on... */
	switch (hooknum) {//检验hooknum
	case NF_INET_PRE_ROUTING:
		kaodv_update_route_timeouts(hooknum, in, iph);
		
		/* If we are a gateway maybe we need to decapsulate? */
		if (is_gateway && iph->protocol == IPPROTO_MIPE &&
		    iph->daddr == ifaddr.s_addr) {//如果是网关且ip协议为55，并且数据包的目的地址是自己
			ip_pkt_decapsulate(skb);//解分装
			iph = SKB_NETWORK_HDR_IPH(skb);//获取skb到iph里
			return NF_ACCEPT;
		}
		/* Ignore packets generated locally or that are for this
		 * node. */
		if (iph->saddr == ifaddr.s_addr ||
		    iph->daddr == ifaddr.s_addr) {//如果是自身产生的数据包则忽略
			return NF_ACCEPT;
		}
		/* Check for unsolicited data packets */
		else if (!kaodv_expl_get(iph->daddr, &e)) {//检查是否是未请求的，expl表中没有的
			kaodv_netlink_send_rerr_msg(PKT_INBOUND, iph->saddr,
						    iph->daddr, in->ifindex);//发送路由错误信息，并丢弃该数据包
			return NF_DROP;

		}
		/* Check if we should repair the route */
		else if (e.flags & KAODV_RT_REPAIR) {//检查是否可修复

			kaodv_netlink_send_rt_msg(KAODVM_REPAIR, iph->saddr,
						  iph->daddr);//发送路由修复的消息

			kaodv_queue_enqueue_packet(skb, okfn);//把skb进入队列中

			return NF_STOLEN;//由Hook函数处理了该数据包，不要再继续传送
		}
		break;
	case NF_INET_LOCAL_OUT://本地产生的数据包

		if (!kaodv_expl_get(iph->daddr, &e) ||
		    (e.flags & KAODV_RT_REPAIR)) {//如果未找到且该表项可修复

			if (!kaodv_queue_find(iph->daddr))//如果该表项在待处理队列中没有
				kaodv_netlink_send_rt_msg(KAODVM_ROUTE_REQ,
							  0,
							  iph->daddr);//控制netlink模块发送一遍路由请求
			
			kaodv_queue_enqueue_packet(skb, okfn);//将它加入队列  
			
			return NF_STOLEN;//由Hook函数处理了该数据包，不要再继续传送

		} else if (e.flags & KAODV_RT_GW_ENCAP) {
#ifdef ENABLE_DISABLED
			/* Make sure the maximum segment size (MSM) is
			   reduced to account for the
			   encapsulation. This is probably not the
			   nicest way to do it. It works sometimes,
			   but may freeze due to some locking issue
			   that needs to be fix... */
			if (iph->protocol == IPPROTO_TCP) {
				
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24))
				if ((*skb)->sk) {
					struct tcp_sock *tp = tcp_sk((*skb)->sk);
					if (tp->mss_cache > 1452) {
						tp->rx_opt.user_mss = 1452;
						tp->rx_opt.mss_clamp = 1452;
						tcp_sync_mss((*skb)->sk, 1452);
					}
				}
#else
				if (skb->sk) {
					struct tcp_sock *tp = tcp_sk(skb->sk);
					if (tp->mss_cache > 1452) {
						tp->rx_opt.user_mss = 1452;
						tp->rx_opt.mss_clamp = 1452;
						tcp_sync_mss(skb->sk, 1452);
					}
				}
#endif
			}
#endif /* ENABLE_DISABLED */
			/* Make sure that also the virtual Internet
			 * dest entry is refreshed */
			kaodv_update_route_timeouts(hooknum, out, iph);//更新路由信息
			
			skb = ip_pkt_encapsulate(skb, e.nhop);//数据包封装
			
			if (!skb)
				return NF_STOLEN;

			ip_route_me_harder(skb, RTN_LOCAL);//重新进行路由操作
		}
		break;
	case NF_INET_POST_ROUTING://应该是转发出去的
		kaodv_update_route_timeouts(hooknum, out, iph);//转发出去
	}
	return NF_ACCEPT;
}

int kaodv_proc_info(char *buffer, char **start, off_t offset, int length)
{//类似kaodv_proc_read函数
	int len;

	len =
	    sprintf(buffer,
		    "qual threshold=%d\npkts dropped=%lu\nlast qual=%d\ngateway_mode=%d\n",
		    qual_th, pkts_dropped, qual, is_gateway);

	*start = buffer + offset;
	len -= offset;
	if (len > length)
		len = length;
	else if (len < 0)
		len = 0;
	return len;
}

/*
 * Called when the module is inserted in the kernel.
 */
static char *ifname[MAX_INTERFACES] = { "eth0" };

#ifdef KERNEL26
static int num_parms = 0;
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,10))
module_param_array(ifname, charp, num_parms, 0444);
#else
module_param_array(ifname, charp, &num_parms, 0444);
#endif
module_param(qual_th, int, 0);//在kernel态，无法通过这样的方式传递参数，一般使用module_param的方式
#else
MODULE_PARM(ifname, "1-" __MODULE_STRING(MAX_INTERFACES) "s");
MODULE_PARM(qual_th, "i");//传参数
#endif

static struct nf_hook_ops kaodv_ops[] = {
	{
	 .hook = kaodv_hook,//kaodv_ops[1]
#ifdef KERNEL26
	 .owner = THIS_MODULE,
#endif
	 .pf = PF_INET,
	 .hooknum = NF_INET_PRE_ROUTING,
	 .priority = NF_IP_PRI_FIRST,
	 },
	{
	 .hook = kaodv_hook,
#ifdef KERNEL26
	 .owner = THIS_MODULE,
#endif
	 .pf = PF_INET,
	 .hooknum = NF_INET_LOCAL_OUT,
	 .priority = NF_IP_PRI_FILTER,
	 },
	{
	 .hook = kaodv_hook,
#ifdef KERNEL26
	 .owner = THIS_MODULE,
#endif
	 .pf = PF_INET,
	 .hooknum = NF_INET_POST_ROUTING,
	 .priority = NF_IP_PRI_FILTER,
	 },
};

static int kaodv_read_proc(char *page, char **start, off_t off, int count,
                    int *eof, void *data)//读取进程信息？
{
    int len;

    len = sprintf(page,
        "qual threshold=%d\npkts dropped=%lu\nlast qual=%d\ngateway_mode=%d\n",
        qual_th, pkts_dropped, qual, is_gateway);

    *start = page + off;
    len -= off;
    if (len > count)
        len = count;
    else if (len < 0)
        len = 0;
    return len;
}


static int __init kaodv_init(void)//初始化内核的aodv进程
{
	struct net_device *dev = NULL;
	int i, ret = -ENOMEM;

#ifndef KERNEL26
	EXPORT_NO_SYMBOLS;
#endif

	kaodv_expl_init();//对内核的expl表进行初始化

	ret = kaodv_queue_init();//对内核的queue进行初始化

	if (ret < 0)
		return ret;//队列初始化失败,退出

	ret = kaodv_netlink_init();//对内核的netlink进行初始化

	if (ret < 0)
		goto cleanup_queue;//netlink初始化失败，解除之前对queue的初始化

	ret = nf_register_hook(&kaodv_ops[0]);//将自己定义的、包含了hook函数，hook点的nf_hook_ops结构体注册到系统中后，一旦有符合条件的包出现，系统都会打印出相应的语句

	if (ret < 0)//
		goto cleanup_netlink;//调用hook,注册ops[0]失败

	ret = nf_register_hook(&kaodv_ops[1]);

	if (ret < 0)
		goto cleanup_hook0;//注册ops[1]失败

	ret = nf_register_hook(&kaodv_ops[2]);

	if (ret < 0)
		goto cleanup_hook1;//注册ops[2]失败



	/* Prefetch network device info (ip, broadcast address, ifindex). */
	//获取网络设备信息
	for (i = 0; i < MAX_INTERFACES; i++) {
		if (!ifname[i])
			break;

		dev = dev_get_by_name(&init_net, ifname[i]);

		if (!dev) {
			printk("No device %s available, ignoring!\n",
			       ifname[i]);
			continue;
		}
		if_info_add(dev);

		dev_put(dev);
	}
	
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24))
	proc_net_create("kaodv", 0, kaodv_proc_info);
#else
    if (!create_proc_read_entry("kaodv", 0, init_net.proc_net, kaodv_read_proc,
                            NULL))
        KAODV_DEBUG("Could not create kaodv proc entry");
#endif
	KAODV_DEBUG("Module init OK");

	return ret;

cleanup_hook1:
	nf_unregister_hook(&kaodv_ops[1]);
cleanup_hook0:
	nf_unregister_hook(&kaodv_ops[0]);
cleanup_netlink:
	kaodv_netlink_fini();
cleanup_queue:
	kaodv_queue_fini();

	return ret;
}

/*
 * Called when removing the module from memory... 
 */
static void __exit kaodv_exit(void)//当把内核的aodv模块移除的时候用到该函数
{
	unsigned int i;
	
	if_info_purge();//清除并释放网络设备信息的空间

	for (i = 0; i < sizeof(kaodv_ops) / sizeof(struct nf_hook_ops); i++)
		nf_unregister_hook(&kaodv_ops[i]);//从hook中释放kaodv_ops的三个选项
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24))
	proc_net_remove("kaodv");
#else
	proc_net_remove(&init_net, "kaodv");
#endif
	kaodv_queue_fini();//清除内核中的队列
	kaodv_expl_fini();//清除内核的expl表
	kaodv_netlink_fini();//清除内核中的netlink
}

module_init(kaodv_init);
module_exit(kaodv_exit);
