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
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/init.h>
#include <linux/ip.h>
#include <linux/notifier.h>
#include <linux/netdevice.h>
#include <linux/netfilter_ipv4.h>
#include <linux/spinlock.h>
#include <linux/sysctl.h>
#include <linux/proc_fs.h>
#include <net/sock.h>
#include <net/route.h>
#include <net/icmp.h>

#include "kaodv-queue.h"
#include "kaodv-expl.h"
#include "kaodv-netlink.h"
#include "kaodv-ipenc.h"
#include "kaodv.h"
/*
 * This is basically a shameless rippoff of the linux kernel's ip_queue module.
 */

#define KAODV_QUEUE_QMAX_DEFAULT 1024
#define KAODV_QUEUE_PROC_FS_NAME "kaodv_queue"
#define NET_KAODV_QUEUE_QMAX 2088
#define NET_KAODV_QUEUE_QMAX_NAME "kaodv_queue_maxlen"

struct kaodv_rt_info {
	__u8 tos;    //两字节，服务类型 typeofservice
	__u32 daddr; //目的地址
	__u32 saddr; //原地址
};

struct kaodv_queue_entry {  //队列表          ,本质上就是一个列表
	struct list_head list;
	struct sk_buff *skb;      //缓冲区buff结构 sk_buff
	int (*okfn) (struct sk_buff *);
	struct kaodv_rt_info rt_info;//内存中的路由信息
};

typedef int (*kaodv_queue_cmpfn) (struct kaodv_queue_entry *, unsigned long);

static unsigned int queue_maxlen = KAODV_QUEUE_QMAX_DEFAULT;
static rwlock_t queue_lock = RW_LOCK_UNLOCKED;//队列的读写锁
static unsigned int queue_total;//队列元素总数
static LIST_HEAD(queue_list);

static inline int __kaodv_queue_enqueue_entry(struct kaodv_queue_entry *entry)
{
	if (queue_total >= queue_maxlen) {
		if (net_ratelimit())
			printk(KERN_WARNING "kaodv-queue: full at %d entries, "
			       "dropping packet(s).\n", queue_total);
		return -ENOSPC;
	}
	list_add(&entry->list, &queue_list);//添加表项
	queue_total++;//表项++
	return 0;
}

/*
 * Find and return a queued entry matched by cmpfn, or return the last
 * entry if cmpfn is NULL.
 */
static inline struct kaodv_queue_entry
*__kaodv_queue_find_entry(kaodv_queue_cmpfn cmpfn, unsigned long data)
{
	struct list_head *p;

	list_for_each_prev(p, &queue_list) {    //遍历并查找
		struct kaodv_queue_entry *entry = (struct kaodv_queue_entry *)p;

		if (!cmpfn || cmpfn(entry, data))
			return entry;
	}
	return NULL;
}

static inline struct kaodv_queue_entry
*__kaodv_queue_find_dequeue_entry(kaodv_queue_cmpfn cmpfn, unsigned long data)
{
	struct kaodv_queue_entry *entry;

	entry = __kaodv_queue_find_entry(cmpfn, data);//查找表项
	if (entry == NULL)
		return NULL;

	list_del(&entry->list);//删除该表项
	queue_total--;

	return entry;
}

static inline void __kaodv_queue_flush(void)
{
	struct kaodv_queue_entry *entry;

	while ((entry = __kaodv_queue_find_dequeue_entry(NULL, 0))) {//删除整个队列中的表项
		kfree_skb(entry->skb);
		kfree(entry);
	}
}

static inline void __kaodv_queue_reset(void)
{
	__kaodv_queue_flush();
}

static struct kaodv_queue_entry
*kaodv_queue_find_dequeue_entry(kaodv_queue_cmpfn cmpfn, unsigned long data)
{
	struct kaodv_queue_entry *entry;

	write_lock_bh(&queue_lock);//写锁
	entry = __kaodv_queue_find_dequeue_entry(cmpfn, data);//出队操作
	write_unlock_bh(&queue_lock);//解开写锁
	return entry;
}

void kaodv_queue_flush(void)
{
	write_lock_bh(&queue_lock);
	__kaodv_queue_flush();
	write_unlock_bh(&queue_lock);
}

int
kaodv_queue_enqueue_packet(struct sk_buff *skb, int (*okfn) (struct sk_buff *))
{
	int status = -EINVAL;//宏定义的一个取值，表示错误 加上一个负号表示无错
	struct kaodv_queue_entry *entry;
	struct iphdr *iph = SKB_NETWORK_HDR_IPH(skb);

	entry = kmalloc(sizeof(*entry), GFP_ATOMIC);

	if (entry == NULL) {//entry没有获取到空间
		printk(KERN_ERR
		       "kaodv_queue: OOM in kaodv_queue_enqueue_packet()\n");
		return -ENOMEM;
	}

	/* printk("enquing packet queue_len=%d\n", queue_total); */
	entry->okfn = okfn;//对entry赋值
	entry->skb = skb;
	entry->rt_info.tos = iph->tos;
	entry->rt_info.daddr = iph->daddr;
	entry->rt_info.saddr = iph->saddr;

	write_lock_bh(&queue_lock);//获得写锁

	status = __kaodv_queue_enqueue_entry(entry);//entry加到队列中

	if (status < 0)//出错，不错status为0
		goto err_out_unlock;

	write_unlock_bh(&queue_lock);//释放写锁
	return status;

      err_out_unlock:
	write_unlock_bh(&queue_lock);
	kfree(entry);

	return status;
}

static inline int dest_cmp(struct kaodv_queue_entry *e, unsigned long daddr)//把比较操作函数化对应__kaodv_queue_find_entry中的cmpfn
{
	return (daddr == e->rt_info.daddr);
}

int kaodv_queue_find(__u32 daddr)
{
	struct kaodv_queue_entry *entry;
	int res = 0;

	read_lock_bh(&queue_lock);
	entry = __kaodv_queue_find_entry(dest_cmp, daddr);//从路由队列中找到表项
	if (entry != NULL)
		res = 1;

	read_unlock_bh(&queue_lock);
	return res;//表示找到
}

int kaodv_queue_set_verdict(int verdict, __u32 daddr)
{
	struct kaodv_queue_entry *entry;
	int pkts = 0;

	if (verdict == KAODV_QUEUE_DROP) {//如果命令是丢弃

		while (1) {
			entry = kaodv_queue_find_dequeue_entry(dest_cmp, daddr);//按目的地址找到该表项，并取出

			if (entry == NULL)
				return pkts;//若找不到，返回0。发送icmp报文通知上层，该目的地址不可用

			/* Send an ICMP message informing the application that the
			 * destination was unreachable. */
			if (pkts == 0)
				icmp_send(entry->skb, ICMP_DEST_UNREACH,
					  ICMP_HOST_UNREACH, 0);

			kfree_skb(entry->skb);//删除skbuff
			kfree(entry);//删除该表项
			pkts++;
		}
	} else if (verdict == KAODV_QUEUE_SEND) {//如果命令是发送
		struct expl_entry e;

		while (1) {
			entry = kaodv_queue_find_dequeue_entry(dest_cmp, daddr);//从队列中取出

			if (entry == NULL)
				return pkts;//找不到，返回0

			if (!kaodv_expl_get(daddr, &e)) {//如果该表项超时了
				kfree_skb(entry->skb);//释放skbuff
				goto next;
			}
			if (e.flags & KAODV_RT_GW_ENCAP) {

				entry->skb = ip_pkt_encapsulate(entry->skb, e.nhop);
				if (!entry->skb)//如果skbuff为空，释放该表项
					goto next;
			}
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,18))
			ip_route_me_harder(&entry->skb);
#elif (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24))
			ip_route_me_harder(&entry->skb, RTN_LOCAL);
#else
			ip_route_me_harder(entry->skb, RTN_LOCAL);//把skbuff内容发送出去
#endif
			pkts++;

			/* Inject packet */
			entry->okfn(entry->skb);
		next:
			kfree(entry);//释放该表项
		}
	}
	return 0;
}

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24))
static int kaodv_queue_get_info(char *buffer, char **start, off_t offset, int length)
{
	int len;

	read_lock_bh(&queue_lock);

	len = sprintf(buffer,
		      "Queue length      : %u\n"
		      "Queue max. length : %u\n", queue_total, queue_maxlen);

	read_unlock_bh(&queue_lock);

	*start = buffer + offset;
	len -= offset;
	if (len > length)
		len = length;
	else if (len < 0)
		len = 0;
	return len;
}
#else
static int kaodv_queue_get_info(char *page, char **start, off_t off, int count,
                    int *eof, void *data)
{
	int len;

	read_lock_bh(&queue_lock);

	len = sprintf(page,
		      "Queue length      : %u\n"
		      "Queue max. length : %u\n", queue_total, queue_maxlen);

	read_unlock_bh(&queue_lock);

	*start = page + off;
	len -= off;
	if (len > count)
		len = count;
	else if (len < 0)
		len = 0;
	return len;
}
#endif

static int init_or_cleanup(int init)
{
	int status = -ENOMEM;
	struct proc_dir_entry *proc;

	if (!init)
		goto cleanup;

	queue_total = 0;

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24))
	proc = proc_net_create(KAODV_QUEUE_PROC_FS_NAME, 0, kaodv_queue_get_info);
#else
	proc = create_proc_read_entry(KAODV_QUEUE_PROC_FS_NAME, 0, init_net.proc_net, kaodv_queue_get_info, NULL);
#endif
	if (!proc) {
	  printk(KERN_ERR "kaodv_queue: failed to create proc entry\n");
	  return -1;
	}

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,30))
	proc->owner = THIS_MODULE;
#endif

	return 1;
	
 cleanup:
#ifdef KERNEL26
	synchronize_net();
#endif
	kaodv_queue_flush();

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24))
	proc_net_remove(KAODV_QUEUE_PROC_FS_NAME);
#else
	proc_net_remove(&init_net, KAODV_QUEUE_PROC_FS_NAME);
#endif
	return status;
}

int kaodv_queue_init(void)
{

	return init_or_cleanup(1);//进行初始化
}

void kaodv_queue_fini(void)
{
	init_or_cleanup(0);//进行清除
}
