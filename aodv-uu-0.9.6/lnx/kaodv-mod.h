#ifndef _KAODV_MOD_H
#define _KAODV_MOD_H

#include <linux/netdevice.h>
#include <linux/inetdevice.h>
#include <linux/list.h>
#include <linux/spinlock.h>
//sk_buff
struct sk_buff {
	/* These two members must be first. */
	struct sk_buff		*next;  //  因为sk_buff结构体是双链表，所以有前驱后继。这是个指向后面的sk_buff结构体指针
	struct sk_buff		*prev;  //  这是指向前一个sk_buff结构体指针
	//老版本（2.6以前）应该还有个字段： sk_buff_head *list  //即每个sk_buff结构都有个指针指向头节点
	struct sock		    *sk;  // 指向拥有此缓冲的套接字sock结构体，即：宿主传输控制模块
	ktime_t			tstamp;  // 时间戳，表示这个skb的接收到的时间，一般是在包从驱动中往二层发送的接口函数中设置
	struct net_device	*dev;  // 表示一个网络设备，当skb为输出/输入时，dev表示要输出/输入到的设备
	unsigned long	_skb_dst;  // 主要用于路由子系统，保存路由有关的东西
	char			cb[48];  // 保存每层的控制信息,每一层的私有信息
	unsigned int		len,  // 表示数据区的长度(tail - data)与分片结构体数据区的长度之和。其实这个len中数据区长度是个有效长度，
                                      // 因为不删除协议头，所以只计算有效协议头和包内容。如：当在L3时，不会计算L2的协议头长度。
				data_len;  // 只表示分片结构体数据区的长度，所以len = (tail - data) + data_len；
	__u16			mac_len,  // mac报头的长度
				hdr_len;  // 用于clone时，表示clone的skb的头长度
	// 接下来是校验相关域，这里就不详细讲了。
	__u32			priority;  // 优先级，主要用于QOS
	kmemcheck_bitfield_begin(flags1);
	__u8			local_df:1,  // 是否可以本地切片的标志
				cloned:1,  // 为1表示该结构被克隆，或者自己是个克隆的结构体；同理被克隆时，自身skb和克隆skb的cloned都要置1
				ip_summed:2, 
				nohdr:1,  // nohdr标识payload是否被单独引用，不存在协议首部。                                                                                                       // 如果被引用，则决不能再修改协议首部，也不能通过skb->data来访问协议首部。</span></span>
				nfctinfo:3;
	__u8			pkt_type:3,  // 标记帧的类型
				fclone:2,   // 这个成员字段是克隆时使用，表示克隆状态
				ipvs_property:1,
				peeked:1,
				nf_trace:1;
	__be16			protocol:16;  // 这是包的协议类型，标识是IP包还是ARP包或者其他数据包。
	kmemcheck_bitfield_end(flags1);
	void	(*destructor)(struct sk_buff *skb);  // 这是析构函数，后期在skb内存销毁时会用到
#if defined(CONFIG_NF_CONNTRACK) || defined(CONFIG_NF_CONNTRACK_MODULE)
	struct nf_conntrack	*nfct;
	struct sk_buff		*nfct_reasm;
#endif
#ifdef CONFIG_BRIDGE_NETFILTER
	struct nf_bridge_info	*nf_bridge;
#endif
	int			iif;  // 接受设备的index
#ifdef CONFIG_NET_SCHED
	__u16			tc_index;	/* traffic control index */
#ifdef CONFIG_NET_CLS_ACT
	__u16			tc_verd;	/* traffic control verdict */
#endif
#endif
	kmemcheck_bitfield_begin(flags2);
	__u16			queue_mapping:16;
#ifdef CONFIG_IPV6_NDISC_NODETYPE
	__u8			ndisc_nodetype:2;
#endif
	kmemcheck_bitfield_end(flags2);
	/* 0/14 bit hole */
#ifdef CONFIG_NET_DMA
	dma_cookie_t		dma_cookie;
#endif
#ifdef CONFIG_NETWORK_SECMARK
	__u32			secmark;
#endif
	__u32			mark;
	__u16			vlan_tci;
	sk_buff_data_t		transport_header;      // 指向四层帧头结构体指针
	sk_buff_data_t		network_header;	       // 指向三层IP头结构体指针
	sk_buff_data_t		mac_header;	       // 指向二层mac头的头
	/* These elements must be at the end, see alloc_skb() for details.  */
	sk_buff_data_t		tail;			  // 指向数据区中实际数据结束的位置
	sk_buff_data_t		end;			  // 指向数据区中结束的位置（非实际数据区域结束位置）
	unsigned char		*head,			  // 指向数据区中开始的位置（非实际数据区域开始位置）
				*data;			  // 指向数据区中实际数据开始的位置			
	unsigned int		truesize;		  // 表示总长度，包括sk_buff自身长度和数据区以及分片结构体的数据区长度
	atomic_t		users;                    // skb被克隆引用的次数，在内存申请和克隆时会用到
};   //end sk_buff

/* Interface information */
struct if_info {
	struct list_head l;//填表首部
	struct in_addr if_addr;//接口地址
	struct in_addr bc_addr;//广播地址
	struct net_device *dev;//接口连接上的设备
};

static LIST_HEAD(ifihead);
static rwlock_t ifilock = RW_LOCK_UNLOCKED;
/* extern struct list_head ifihead; */
/* extern rwlock_t ifilock; */

static inline int if_info_add(struct net_device *dev)
{
	struct if_info *ifi;
	struct in_device *indev;

	ifi = (struct if_info *)kmalloc(sizeof(struct if_info), GFP_ATOMIC);

	if (!ifi)
		return -1;

	ifi->dev = dev;

	dev_hold(dev);

	indev = in_dev_get(dev);

	if (indev) {
		struct in_ifaddr **ifap;
		struct in_ifaddr *ifa;

		for (ifap = &indev->ifa_list; (ifa = *ifap) != NULL;
		     ifap = &ifa->ifa_next)
			if (!strcmp(dev->name, ifa->ifa_label))
				break;

		if (ifa) {
			ifi->if_addr.s_addr = ifa->ifa_address;
			ifi->bc_addr.s_addr = ifa->ifa_broadcast;
		}
		in_dev_put(indev);
	}

	write_lock(&ifilock);
	list_add(&ifi->l, &ifihead);
	write_unlock(&ifilock);

	return 0;
}

static inline void if_info_purge(void)
{
	struct list_head *pos, *n;

	write_lock(&ifilock);
	list_for_each_safe(pos, n, &ifihead) {
		struct if_info *ifi = (struct if_info *)pos;
		list_del(&ifi->l);
		dev_put(ifi->dev);
		kfree(ifi);
	}
	write_unlock(&ifilock);
}

static inline int if_info_from_ifindex(struct in_addr *ifa, struct in_addr *bc,
				   int ifindex)//读取设备号是ifindex的接口的ifaddr和bcaddr
{
	struct list_head *pos;
	int res = -1;

	read_lock(&ifilock);
	list_for_each(pos, &ifihead) {//if_addr，bc_addr读取到ifa和bc
		struct if_info *ifi = (struct if_info *)pos;
		if (ifi->dev->ifindex == ifindex) {
			if (ifa)
				*ifa = ifi->if_addr;

			if (bc)
				*bc = ifi->bc_addr;
			res = 0;
			break;
		}
	}
	read_unlock(&ifilock);

	return res;
}

void kaodv_update_route_timeouts(int hooknum, const struct net_device *dev,
				 struct iphdr *iph);//根据hooknum的类型对内核路由进行更新
#endif
