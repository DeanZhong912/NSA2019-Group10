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
 *****************************************************************************/

#include <sys/types.h>

#ifdef NS_PORT
#include "ns-2/aodv-uu.h"
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>
#include <netinet/udp.h>
#include "aodv_socket.h"
#include "timer_queue.h"
#include "aodv_rreq.h"
#include "aodv_rerr.h"
#include "aodv_rrep.h"
#include "params.h"
#include "aodv_hello.h"
#include "aodv_neighbor.h"
#include "debug.h"
#include "defs.h"

#endif				/* NS_PORT */

#ifndef NS_PORT
#define SO_RECVBUF_SIZE 256*1024

static char recv_buf[RECV_BUF_SIZE];
static char send_buf[SEND_BUF_SIZE];

extern int wait_on_reboot, hello_qual_threshold, ratelimit;

static void aodv_socket_read(int fd);

/* Seems that some libc (for example ulibc) has a bug in the provided
 * CMSG_NXTHDR() routine... redefining it here */

static struct cmsghdr *__cmsg_nxthdr_fix(void *__ctl, size_t __size,
					 struct cmsghdr *__cmsg)
{
    struct cmsghdr *__ptr;

    __ptr = (struct cmsghdr *) (((unsigned char *) __cmsg) +
				CMSG_ALIGN(__cmsg->cmsg_len));
    if ((unsigned long) ((char *) (__ptr + 1) - (char *) __ctl) > __size)
	return NULL;

    return __ptr;
}

struct cmsghdr *cmsg_nxthdr_fix(struct msghdr *__msg, struct cmsghdr *__cmsg)
{
    return __cmsg_nxthdr_fix(__msg->msg_control, __msg->msg_controllen, __cmsg);
}

#endif				/* NS_PORT */


void NS_CLASS aodv_socket_init()     			/*socket初始化*/
{
#ifndef NS_PORT
    struct sockaddr_in aodv_addr;        //sockaddr_in 地址族，16位tcp/udp端口号，32位ip地址 
    struct ifreq ifr;                   
    int i, retval = 0;
    int on = 1;
    int tos = IPTOS_LOWDELAY;        	 //IPTOS_LOWDELAY用来为交互式通信最小化延迟时间
    int bufsize = SO_RECVBUF_SIZE;   	 //SO_RECVBUF_SIZE 缓冲区大小256*1024
    socklen_t optlen = sizeof(bufsize);  //socklen_t 与int 大小保持一致

    /* Create a UDP socket */

    if (this_host.nif == 0) {          //如果可广播的端口数为零则报错
	fprintf(stderr, "No interfaces configured\n");
	exit(-1);
    }

    /* Open a socket for every AODV enabled interface */
    for (i = 0; i < MAX_NR_INTERFACES; i++) {   
	if (!DEV_NR(i).enabled)    //寻找每个设备是否有效，有效则继续下一条，无效跳回
	    continue;

	/* AODV socket */
	DEV_NR(i).sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);  //关联socket
	if (DEV_NR(i).sock < 0) {     //关联出错 则退出
	    perror("");
	    exit(-1);
	}
#ifdef CONFIG_GATEWAY 
	/* Data packet send socket */
	DEV_NR(i).psock = socket(PF_INET, SOCK_RAW, IPPROTO_RAW);    //关联发送数据包的socket

	if (DEV_NR(i).psock < 0) {  //出错则退出
	    perror("");
	    exit(-1);
	}
#endif
	/* Bind the socket to the AODV port number */
	memset(&aodv_addr, 0, sizeof(aodv_addr));    	//清空aodv_addr
	aodv_addr.sin_family = AF_INET;             	//绑定地址族       tcp/ip簇              
	aodv_addr.sin_port = htons(AODV_PORT);      	//绑定aodv端口号654
	aodv_addr.sin_addr.s_addr = htonl(INADDR_ANY);  //绑定IP地址 0.0.0.0 表示不确定地址 

	retval = bind(DEV_NR(i).sock, (struct sockaddr *) &aodv_addr,
		      sizeof(struct sockaddr));    //bind绑定

	if (retval < 0) {           //出错则退出
	    perror("Bind failed ");
	    exit(-1);
	}
	if (setsockopt(DEV_NR(i).sock, SOL_SOCKET, SO_BROADCAST,    //setsockopt 设置套接口选项 SOL_SOCKET表示选项定义的层次为通用套接字选项
		       &on, sizeof(int)) < 0) {                         //SO_BROADCAST 表示允许发送广播数据
	    perror("SO_BROADCAST failed ");                        	//出错则退出
	    exit(-1);
	}

	memset(&ifr, 0, sizeof(struct ifreq));                      //清空ifr
	strcpy(ifr.ifr_name, DEV_NR(i).ifname);                     //复制设备名给ifr的设备名

	if (setsockopt(DEV_NR(i).sock, SOL_SOCKET, SO_BINDTODEVICE, //设置套接字层  SO_BINDTODEVICE创建套接字时绑定设备
		       &ifr, sizeof(ifr)) < 0) {                        //出错则退出
	    fprintf(stderr, "SO_BINDTODEVICE failed for %s", DEV_NR(i).ifname);
	    perror(" ");
	    exit(-1);
	}

	if (setsockopt(DEV_NR(i).sock, SOL_SOCKET, SO_PRIORITY,    //以下全为套接字选项  
		       &tos, sizeof(int)) < 0) {
	    perror("Setsockopt SO_PRIORITY failed ");
	    exit(-1);
	}

	if (setsockopt(DEV_NR(i).sock, SOL_IP, IP_RECVTTL,
		       &on, sizeof(int)) < 0) {
	    perror("Setsockopt IP_RECVTTL failed ");
	    exit(-1);
	}

	if (setsockopt(DEV_NR(i).sock, SOL_IP, IP_PKTINFO,
		       &on, sizeof(int)) < 0) {
	    perror("Setsockopt IP_PKTINFO failed ");
	    exit(-1);
	}
#ifdef CONFIG_GATEWAY
	if (setsockopt(DEV_NR(i).psock, SOL_SOCKET, SO_BINDTODEVICE,    //以下为发送数据包的套接字选项
		       &ifr, sizeof(ifr)) < 0) {
	    fprintf(stderr, "SO_BINDTODEVICE failed for %s", DEV_NR(i).ifname);
	    perror(" ");
	    exit(-1);
	}

	bufsize = 4 * 65535;

	if (setsockopt(DEV_NR(i).psock, SOL_SOCKET, SO_SNDBUF,
		       (char *) &bufsize, optlen) < 0) {
	    DEBUG(LOG_NOTICE, 0, "Could not set send socket buffer size");
	}
	if (getsockopt(DEV_NR(i).psock, SOL_SOCKET, SO_SNDBUF,
		       (char *) &bufsize, &optlen) == 0) {
	    alog(LOG_NOTICE, 0, __FUNCTION__,
		 "RAW send socket buffer size set to %d", bufsize);
	}
#endif
	/* Set max allowable receive buffer size... */      
	for (;; bufsize -= 1024) {
	    if (setsockopt(DEV_NR(i).sock, SOL_SOCKET, SO_RCVBUF,    //设置 SO_RCVBUF 接收缓冲区大小
			   (char *) &bufsize, optlen) == 0) {            //==0  成功  则跳出 否则减小1024 再设置
		alog(LOG_NOTICE, 0, __FUNCTION__,
		     "Receive buffer size set to %d", bufsize);
		break;
	    }
	    if (bufsize < RECV_BUF_SIZE) {             //如果小于接收RERR的大小 出错退出
		alog(LOG_ERR, 0, __FUNCTION__,
		     "Could not set receive buffer size");
		exit(-1);
	    }
	}

	retval = attach_callback_func(DEV_NR(i).sock, aodv_socket_read);   //将其注册在回调函数中

	if (retval < 0) {
	    perror("register input handler failed ");
	    exit(-1);
	}
    }
#endif				/* NS_PORT */

    num_rreq = 0;
    num_rerr = 0;
}

void NS_CLASS aodv_socket_process_packet(AODV_msg * aodv_msg, int len,
					 struct in_addr src,
					 struct in_addr dst,
					 int ttl, unsigned int ifindex)
{

    /* If this was a HELLO message... Process as HELLO. */
    if ((aodv_msg->type == AODV_RREP && ttl == 1 &&
	 dst.s_addr == AODV_BROADCAST)) {                    //判断是否为hello消息
	hello_process((RREP *) aodv_msg, len, ifindex);      //将其转交给hello函数处理
	return;
    }

    /* Make sure we add/update neighbors */
    neighbor_add(aodv_msg, src, ifindex);              //如果不是hello函数 添加/更新到邻居

    /* Check what type of msg we received and call the corresponding
       function to handle the msg... */
    switch (aodv_msg->type) {

    case AODV_RREQ:
	rreq_process((RREQ *) aodv_msg, len, src, dst, ttl, ifindex);   //如果是RREQ消息 则转交给RREQ函数处理
	break;
    case AODV_RREP:
	DEBUG(LOG_DEBUG, 0, "Received RREP");
	rrep_process((RREP *) aodv_msg, len, src, dst, ttl, ifindex);   //如果是RREP消息 则转交给RREP函数处理
	break;
    case AODV_RERR:
	DEBUG(LOG_DEBUG, 0, "Received RERR");
	rerr_process((RERR *) aodv_msg, len, src, dst);    //如果是RRER消息 则转交给RRER函数处理
	break;
    case AODV_RREP_ACK:
	DEBUG(LOG_DEBUG, 0, "Received RREP_ACK");
	rrep_ack_process((RREP_ack *) aodv_msg, len, src, dst);  //如果是RREP_ACK消息 则转交给RREP_ACK函数处理
	break;
    default:
	alog(LOG_WARNING, 0, __FUNCTION__,
	     "Unknown msg type %u rcvd from %s to %s", aodv_msg->type,
	     ip_to_str(src), ip_to_str(dst));          		//如果都不是则为未知消息类型
    }
}

#ifdef NS_PORT
void NS_CLASS recvAODVUUPacket(Packet * p)  
{
    int len, i, ttl = 0;
    struct in_addr src, dst;           
    struct hdr_cmn *ch = HDR_CMN(p);      //取出包头数据的一部分
    struct hdr_ip *ih = HDR_IP(p);        //取出包头中的IP地址
    hdr_aodvuu *ah = HDR_AODVUU(p);

    src.s_addr = ih->saddr();		//源IP地址
    dst.s_addr = ih->daddr();		//目的IP地址
    len = ch->size() - IP_HDR_LEN;  //
    ttl = ih->ttl();                //获取ttl

    AODV_msg *aodv_msg = (AODV_msg *) recv_buf;  //定义aodv消息的缓冲区

    /* Only handle AODVUU packets */
    assert(ch->ptype() == PT_AODVUU);

    /* Only process incoming packets */
    assert(ch->direction() == hdr_cmn::UP);

    /* Copy message to receive buffer */
    memcpy(recv_buf, ah, RECV_BUF_SIZE);   //将消息复制到recv_buf中

    /* Deallocate packet, we have the information we need... */
    Packet::free(p);                       //释放掉数据包p

    /* Ignore messages generated locally */
    for (i = 0; i < MAX_NR_INTERFACES; i++)       //忽略本地消息
	if (this_host.devs[i].enabled &&
	    memcmp(&src, &this_host.devs[i].ipaddr,
		   sizeof(struct in_addr)) == 0)
	    return;

    aodv_socket_process_packet(aodv_msg, len, src, dst, ttl, NS_IFINDEX);    //交给上面的函数去处理
}
#else
static void aodv_socket_read(int fd)
{
    struct in_addr src, dst;
    int i, len, ttl = -1;
    AODV_msg *aodv_msg;
    struct dev_info *dev;
    struct msghdr msgh;               //存放为应用层的消息
    struct cmsghdr *cmsg;
    struct iovec iov;                  //一个缓冲区
    char ctrlbuf[CMSG_SPACE(sizeof(int)) +
		 CMSG_SPACE(sizeof(struct in_pktinfo))];
    struct sockaddr_in src_addr;

    dst.s_addr = -1;

    iov.iov_base = recv_buf;     		//指向一个缓冲区，用来存放readv所接收到的数据
    iov.iov_len = RECV_BUF_SIZE; 
    msgh.msg_name = &src_addr;    		//消息的协议地址，源sockaddr的地址
    msgh.msg_namelen = sizeof(src_addr);
    msgh.msg_iov = &iov;         		//将iov存放在其中
    msgh.msg_iovlen = 1;				//缓冲区个数 只存放了iov一个
    msgh.msg_control = ctrlbuf;  		//辅助数据的地址
    msgh.msg_controllen = sizeof(ctrlbuf);

    len = recvmsg(fd, &msgh, 0);       //将接收到的消息存放在msgh中 返回数据报长度

    if (len < 0) {
	alog(LOG_WARNING, 0, __FUNCTION__, "receive ERROR len=%d!", len);  //长度为0则报错 返回
	return;
    }

    src.s_addr = src_addr.sin_addr.s_addr;   //将源IP地址放入src.s_addr中 

    /* Get the ttl and destination address from the control message */
    for (cmsg = CMSG_FIRSTHDR(&msgh); cmsg != NULL;
	 cmsg = CMSG_NXTHDR_FIX(&msgh, cmsg)) {
	if (cmsg->cmsg_level == SOL_IP) {     
	    switch (cmsg->cmsg_type) {
	    case IP_TTL:
		ttl = *(CMSG_DATA(cmsg));    //获取ttl
		break;
	    case IP_PKTINFO:
	      {
		struct in_pktinfo *pi = (struct in_pktinfo *)CMSG_DATA(cmsg);
		dst.s_addr = pi->ipi_addr.s_addr;   //获取目的IP地址
	      }
	    }
	}
    }

    if (ttl < 0) {
	DEBUG(LOG_DEBUG, 0, "No TTL, packet ignored!");
	return;
    }

    /* Ignore messages generated locally */
    for (i = 0; i < MAX_NR_INTERFACES; i++)    //忽略来自本地的消息
	if (this_host.devs[i].enabled &&
	    memcmp(&src, &this_host.devs[i].ipaddr,
		   sizeof(struct in_addr)) == 0)
	    return;

    aodv_msg = (AODV_msg *) recv_buf;   	//得到缓冲区

    dev = devfromsock(fd);  				//返回设备即接口 

    if (!dev) {
	DEBUG(LOG_ERR, 0, "Could not get device info!\n");
	return;
    }

    aodv_socket_process_packet(aodv_msg, len, src, dst, ttl, dev->ifindex);   //交给上面的函数处理
}
#endif				/* NS_PORT */

void NS_CLASS aodv_socket_send(AODV_msg * aodv_msg, struct in_addr dst,
			       int len, u_int8_t ttl, struct dev_info *dev)
{
    int retval = 0;
    struct timeval now;         //时间
    /* Rate limit stuff: */

#ifndef NS_PORT

    struct sockaddr_in dst_addr;    //定义目的IP地址

    if (wait_on_reboot && aodv_msg->type == AODV_RREP)  //wait_on_root为1 代表我们处于重启后的等待状态 且消息类型为RREP回复消息 则不发送
	return;

    memset(&dst_addr, 0, sizeof(dst_addr));   			//清空dst_addr
    dst_addr.sin_family = AF_INET;						//设置dst_addr
    dst_addr.sin_addr = dst;
    dst_addr.sin_port = htons(AODV_PORT);

    /* Set ttl */
    if (setsockopt(dev->sock, SOL_IP, IP_TTL, &ttl, sizeof(ttl)) < 0) {   //设置ttl
	alog(LOG_WARNING, 0, __FUNCTION__, "ERROR setting ttl!");
	return;
    }
#else

    /*
       NS_PORT: Sending of AODV_msg messages to other AODV-UU routing agents
       by encapsulating them in a Packet.

	   通过将AODV_msg消息封装在Packet中，将其发送到其他AODV-UU路由代理。

       Note: This method is _only_ for sending AODV packets to other routing
       agents, _not_ for forwarding "regular" IP packets!
     */

    /* If we are in waiting phase after reboot, don't send any RREPs */
    if (wait_on_reboot && aodv_msg->type == AODV_RREP)
	return;

    /*
       NS_PORT: Don't allocate packet until now. Otherwise packet uid
       (unique ID) space is unnecessarily exhausted at the beginning of
       the simulation, resulting in uid:s starting at values greater than 0.
       直到现在才分配数据包。 否则，在模拟开始时会不必要地耗尽数据包uid（唯一ID）空间，
       导致uid：s从大于0的值开始。
     */
    Packet *p = allocpkt();
    struct hdr_cmn *ch = HDR_CMN(p);
    struct hdr_ip *ih = HDR_IP(p);
    hdr_aodvuu *ah = HDR_AODVUU(p);

    // Clear AODVUU part of packet
    memset(ah, '\0', ah->size());     	//清空ah 

    // Copy message contents into packet
    memcpy(ah, aodv_msg, len);       	//将aodv_msg复制到ah中

    // Set common header fields
    ch->ptype() = PT_AODVUU;			//设置数据包头
    ch->direction() = hdr_cmn::DOWN;    //数据向物理层传输
    ch->size() += len + IP_HDR_LEN;
    ch->iface() = -2;                   //接口
    ch->error() = 0;
    ch->prev_hop_ = (nsaddr_t) dev->ipaddr.s_addr;  //转发的接口的IP地址 

    // Set IP header fields
    ih->saddr() = (nsaddr_t) dev->ipaddr.s_addr; //设置IP包头
    ih->daddr() = (nsaddr_t) dst.s_addr;
    ih->ttl() = ttl;

    // Note: Port number for routing agents, not AODV port number!   //路由代理的端口号不是AODV的端口号
    ih->sport() = RT_PORT;
    ih->dport() = RT_PORT;

    // Fake success
    retval = len;
#endif				/* NS_PORT */

    /* If rate limiting is enabled, check if we are sending either a
       RREQ or a RERR. In that case, drop the outgoing control packet
       if the time since last transmit of that type of packet is less
       than the allowed RATE LIMIT time... */

    if (ratelimit) {          										//当速率限制开启时          判断为RREQ还是RRER

	gettimeofday(&now, NULL);  										//获取当前时间

	switch (aodv_msg->type) {
	case AODV_RREQ:            										//如果为RREQ消息
	    if (num_rreq == (RREQ_RATELIMIT - 1)) {						//如果发送的RREQ数量达到最大值
		if (timeval_diff(&now, &rreq_ratel[0]) < 1000) {			//如果距离第一个RREQ发送时间小于1s
		    DEBUG(LOG_DEBUG, 0, "RATELIMIT: Dropping RREQ %ld ms",
			  timeval_diff(&now, &rreq_ratel[0]));
#ifdef NS_PORT													
		  	Packet::free(p);										//释放要传出去的控制数据包
#endif
		    return;													//返回
		} else {
		    memmove(rreq_ratel, &rreq_ratel[1],
			    sizeof(struct timeval) * (num_rreq - 1));			//如果大于1s 则从下标为1的开始向前挪一位
		    memcpy(&rreq_ratel[num_rreq - 1], &now,					//将当前时间放在最后一位
			   sizeof(struct timeval));
		}
	    } else {													//如果没有满，则将当前时间放在下一位
		memcpy(&rreq_ratel[num_rreq], &now, sizeof(struct timeval));
		num_rreq++;
	    }
	    break;
	case AODV_RERR:
	    if (num_rerr == (RERR_RATELIMIT - 1)) {                   //同上
		if (timeval_diff(&now, &rerr_ratel[0]) < 1000) {
		    DEBUG(LOG_DEBUG, 0, "RATELIMIT: Dropping RERR %ld ms",
			  timeval_diff(&now, &rerr_ratel[0]));
#ifdef NS_PORT
		  	Packet::free(p);
#endif
		    return;
		} else {
		    memmove(rerr_ratel, &rerr_ratel[1],
			    sizeof(struct timeval) * (num_rerr - 1));
		    memcpy(&rerr_ratel[num_rerr - 1], &now,
			   sizeof(struct timeval));
		}
	    } else {
		memcpy(&rerr_ratel[num_rerr], &now, sizeof(struct timeval));
		num_rerr++;
	    }
	    break;
	}
    }

    /* If we broadcast this message we update the time of last broadcast
       to prevent unnecessary broadcasts of HELLO msg's 
       如果我们广播此消息，则会更新上次广播的时间，以防止不必要的HELLO消息广播*/
    if (dst.s_addr == AODV_BROADCAST) {

	gettimeofday(&this_host.bcast_time, NULL);   	//更新广播时间

#ifdef NS_PORT
	ch->addr_type() = NS_AF_NONE;   		//设置为广播报文

	sendPacket(p, dst, 0.0);				//发送数据包给dst
#else

	retval = sendto(dev->sock, send_buf, len, 0,
			(struct sockaddr *) &dst_addr, sizeof(dst_addr));      //通过套接字发送send_buf中的内容

	if (retval < 0) {

	    alog(LOG_WARNING, errno, __FUNCTION__, "Failed send to bc %s",
		 ip_to_str(dst));
	    return;
	}
#endif

    } else {

#ifdef NS_PORT
	ch->addr_type() = NS_AF_INET;       						//分组需要经过单播路由到达目的地，使用arp
	/* We trust the decision of next hop for all AODV messages... 
		我们相信所有AODV消息的下一跳决定*/
	
	if (dst.s_addr == AODV_BROADCAST)							//如果目的IP地址是广播		
	    sendPacket(p, dst, 0.001 * Random::uniform());			//发送
	else
	    sendPacket(p, dst, 0.0);
#else
	retval = sendto(dev->sock, send_buf, len, 0,				//通过套接字发送send_buf中的内容
			(struct sockaddr *) &dst_addr, sizeof(dst_addr));   

	if (retval < 0) {
	    alog(LOG_WARNING, errno, __FUNCTION__, "Failed send to %s",
		 ip_to_str(dst));
	    return;
	}
#endif
    }

    /* Do not print hello msgs... */
    if (!(aodv_msg->type == AODV_RREP && (dst.s_addr == AODV_BROADCAST)))  //如果不是hello消息 则打印在DEBUG中
	DEBUG(LOG_INFO, 0, "AODV msg to %s ttl=%d size=%u",
	      ip_to_str(dst), ttl, retval, len);

    return;
}

AODV_msg *NS_CLASS aodv_socket_new_msg(void)
{
    memset(send_buf, '\0', SEND_BUF_SIZE);				//清空send_buf
    return (AODV_msg *) (send_buf);						//返回AODV_msg类型的send_buf
}

/* Copy an existing AODV message to the send buffer */  
AODV_msg *NS_CLASS aodv_socket_queue_msg(AODV_msg * aodv_msg, int size)
{
    memcpy((char *) send_buf, aodv_msg, size);     //复制一个已经存在的AODV消息到send_buf中
    return (AODV_msg *) send_buf;
}

void aodv_socket_cleanup(void)
{
#ifndef NS_PORT
    int i;

    for (i = 0; i < MAX_NR_INTERFACES; i++) {
	if (!DEV_NR(i).enabled)
	    continue;
	close(DEV_NR(i).sock);           //关闭任何有效接口的socket
    }
#endif				/* NS_PORT */
}
