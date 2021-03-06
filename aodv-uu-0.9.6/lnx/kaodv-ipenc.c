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
 *****************************************************************************/
#include <net/ip.h>
#include <linux/skbuff.h>
#include <linux/version.h>

#include "kaodv-ipenc.h"
#include "kaodv-expl.h" /* For print_ip() */
#include "kaodv.h"

/* Simple function (based on R. Stevens) to calculate IP header checksum */
static u_int16_t ip_csum(unsigned short *buf, int nshorts)//计算ip首部校验和
{
    u_int32_t sum;
    
    for (sum = 0; nshorts > 0; nshorts--) {
        sum += *buf++;
    }
    
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    
    return ~sum;
}

struct sk_buff *ip_pkt_encapsulate(struct sk_buff *skb, __u32 dest)//对IP数据包进行封装
{


    struct min_ipenc_hdr *ipe;//IP首部
    struct sk_buff *nskb;     //skbuff
    struct iphdr *iph;
    
    /* Allocate new data space at head */
    nskb = skb_copy_expand(skb, skb_headroom(skb),
			   skb_tailroom(skb) +
			   sizeof(struct min_ipenc_hdr), 
			   GFP_ATOMIC);//拷贝skbfuff并且扩展成nskb

    if (nskb == NULL) {//操作失败
	printk("Could not allocate new skb\n");
	kfree_skb(skb);
	return NULL;	
    }

    /* Set old owner */
    if (skb->sk != NULL)
	skb_set_owner_w(nskb, skb->sk);//把skb的sock赋给nskb

    iph = SKB_NETWORK_HDR_IPH(skb);//强制的类型转换skb类型转换成iph的类型

    skb_put(nskb, sizeof(struct min_ipenc_hdr));//在nskb尾部加上大小为min_ipenc_hdr大小
    
    /* Move the IP header */
    memcpy(nskb->data, skb->data, (iph->ihl << 2));//把skb的IP首部复制到nskb
    /* Move the data */
    memcpy(nskb->data + (iph->ihl << 2) + sizeof(struct min_ipenc_hdr), 
	   skb->data + (iph->ihl << 2), skb->len - (iph->ihl << 2));//把skb的数据复制发到nskb
    
    kfree_skb(skb);//释放skb空间
    skb = nskb;//skb指向nskb
    
    /* Update pointers */
    
    SKB_SET_NETWORK_HDR(skb, 0);
    iph = SKB_NETWORK_HDR_IPH(skb);

    ipe = (struct min_ipenc_hdr *)(SKB_NETWORK_HDR_RAW(skb) + (iph->ihl << 2));
    
    /* Save the old ip header information in the encapsulation header */
    ipe->protocol = iph->protocol;
    ipe->s = 0; /* No source address field in the encapsulation header */
    ipe->res = 0;
    ipe->check = 0;
    ipe->daddr = iph->daddr;

    /* Update the IP header */
    iph->daddr = dest;
    iph->protocol = IPPROTO_MIPE;
    iph->tot_len = htons(ntohs(iph->tot_len) + sizeof(struct min_ipenc_hdr));
    
    /* Recalculate checksums */
    ipe->check = ip_csum((unsigned short *)ipe, 4);

    ip_send_check(iph);//发送

    if (iph->id == 0)
	    ip_select_ident(iph, skb_dst(skb), NULL);//ip包的id选择
        
    return skb;
}

struct sk_buff *ip_pkt_decapsulate(struct sk_buff *skb)//ip解封装
{
    struct min_ipenc_hdr *ipe; 
    /* skb->nh.iph is probably not set yet */
    struct iphdr *iph = SKB_NETWORK_HDR_IPH(skb);//把skb类型转换一下

    ipe = (struct min_ipenc_hdr *)((char *)iph + (iph->ihl << 2));//获取ip首部赋值给ipe

    iph->protocol = ipe->protocol;
    iph->daddr = ipe->daddr;
    
    /* Shift the data to the left, overwriting the encap header */
    memmove(skb->data + (iph->ihl << 2), 
	    skb->data + (iph->ihl << 2) + sizeof(struct min_ipenc_hdr), 
	    skb->len - (iph->ihl << 2) - sizeof(struct min_ipenc_hdr));//获取数据
    
    skb_trim(skb, skb->len - sizeof(struct min_ipenc_hdr));//skb_trim()根据指定长度删除SKB的数据缓存区尾部的数据，如果新长度大于当前长度，则不作处理
    
    SKB_SET_NETWORK_HDR(skb, 0);
    iph = SKB_NETWORK_HDR_IPH(skb);

    iph->tot_len = htons((ntohs(iph->tot_len) - sizeof(struct min_ipenc_hdr))); 
    ip_send_check(iph);
   
    return skb;
}
