#ifndef _KAODV_MOD_H
#define _KAODV_MOD_H

#include <linux/netdevice.h>
#include <linux/inetdevice.h>
#include <linux/list.h>
#include <linux/spinlock.h>
  //sk_buff 结构用来封装网络数据
  //网络栈代码对数据的处理都是以sk_buff 结构为单元进行的
struct sk_buff {
  struct sk_buff		* volatile next;
  struct sk_buff		* volatile prev;//构成队列
#if CONFIG_SKB_CHECK
  int				magic_debug_cookie; //调试用
#endif
  struct sk_buff		* volatile link3; //构成数据包重发队列
  struct sock			*sk; //数据包所属的套接字
  volatile unsigned long	when;	 //数据包的发送时间，用于计算往返时间RTT/* used to compute rtt's	*/
  struct timeval		stamp; //记录时间
  struct device			*dev; //接收该数据包的接口设备
  struct sk_buff		*mem_addr; //该sk_buff在内存中的基地址，用于释放该sk_buff结构
  //联合类型，表示数据报在不同处理层次上所到达的处理位置
  union {
	struct tcphdr	*th; //传输层tcp，指向首部第一个字节位置
	struct ethhdr	*eth; //链路层上，指向以太网首部第一个字节位置
	struct iphdr	*iph; //网络层上，指向ip首部第一个字节位置
	struct udphdr	*uh; //传输层udp协议，
	unsigned char	*raw; //随层次变化而变化，链路层=eth，网络层=iph
	unsigned long	seq; //针对tcp协议的待发送数据包而言，表示该数据包的ACK值
  } h;
  struct iphdr		*ip_hdr; //指向ip首部的指针		/* For IPPROTO_RAW */
  unsigned long			mem_len; //表示sk_buff结构大小加上数据部分的总长度
  unsigned long 		len; //只表示数据部分长度，len = mem_len - sizeof(sk_buff)
  unsigned long			fraglen; //分片数据包个数
  struct sk_buff		*fraglist;	/* Fragment list */
  unsigned long			truesize; //同men_len
  unsigned long 		saddr; //源端ip地址
  unsigned long 		daddr; //目的端ip地址
  unsigned long			raddr; //数据包下一站ip地址		/* next hop addr */
   //标识字段
  volatile char 		acked, //=1，表示数据报已得到确认，可以从重发队列中删除
				used, //=1，表示该数据包的数据已被应用程序读完，可以进行释放
				free, //用于数据包发送，=1表示再进行发送操作后立即释放，无需缓存
				arp; //用于待发送数据包，=1表示已完成MAC首部的建立，=0表示还不知道目的端MAC地址
  //已进行tries试发送，该数据包正在被其余部分使用，路由类型，数据包类型
  unsigned char			tries,lock,localroute,pkt_type;
   //下面是数据包的类型，即pkt_type的取值
#define PACKET_HOST		0	  //发往本机	/* To us */
#define PACKET_BROADCAST	1 //广播
#define PACKET_MULTICAST	2 //多播
#define PACKET_OTHERHOST	3 //其他机器		/* Unmatched promiscuous */
  unsigned short		users; //使用该数据包的模块数		/* User count - see datagram.c (and soon seqpacket.c/stream.c) */
  unsigned short		pkt_class;	/* For drivers that need to cache the packet type with the skbuff (new PPP) */
#ifdef CONFIG_SLAVE_BALANCING
  unsigned short		in_dev_queue; //该字段是否正在缓存于设备缓存队列中
#endif  
  unsigned long			padding[0]; //填充字节
  unsigned char			data[0]; //指向该层数据部分
  //data指向的数据负载首地址，在各个层对应不同的数据部分
//从侧面看出sk_buff结构基本上是贯穿整个网络栈的非常重要的一个数据结构
};


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
