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
#ifndef _TIMER_QUEUE_H
#define _TIMER_QUEUE_H

#ifndef NS_NO_GLOBALS
#include <sys/time.h>

#include "defs.h"
#include "list.h"

#ifdef NS_PORT//表示在定义了NS_PORT时执行如下程序
typedef void (AODVUU::*timeout_func_t) (void *);
#else
typedef void (*timeout_func_t) (void *);
#endif

struct timer {//定义timer结构体，参数有列表，标识位used，timeval结构体实例化的timeout，timeout_func_t指针类型的handler,和空类型的指针data
    list_t l;
    int used;
    struct timeval timeout;//时间同步 时间计算获得时间延迟，所以会用到timeval ，struct timeval {long tv_sec; long tv_usec;};
    timeout_func_t handler;
    void *data;
};

static inline long timeval_diff(struct timeval *t1, struct timeval *t2)//用于计算t1和t2的时间差，并处理单位
{
    long long res;		/* We need this to avoid overflows while calculating... */

    if (!t1 || !t2)//t1或者t2为0时返回-1
	return -1;
    else {

	res = t1->tv_sec;//首先将res赋值为t1的时间，单位是秒
	res = ((res - t2->tv_sec) * 1000000 + t1->tv_usec - t2->tv_usec) / 1000;//tv_sec 代表多少秒 tv_usec 代表多少微秒 1000000 微秒 = 1秒
	return (long) res;//返回时间差，单位毫秒
    }
}

static inline int timeval_add_msec(struct timeval *t, unsigned long msec)//以毫秒单位向t中加入时间并处理单位
{
    unsigned long long add;	/* Protect against overflows */

    if (!t)
	return -1;//返回值为-1

    add = t->tv_usec + (msec * 1000);//先将毫秒转化为微秒
    t->tv_sec += add / 1000000;//满1秒向tv_sec中加1
    t->tv_usec = add % 1000000;//将剩下的加入到微秒级tv_usec中

    return 0;
}
#endif				/* NS_NO_GLOBALS */

#ifndef NS_NO_DECLARATIONS
void timer_queue_init();//定时器队列初始化
int timer_remove(struct timer *t);//定时器移除
void timer_set_timeout(struct timer *t, long msec);//设置定时器超时时间
int timer_timeout_now(struct timer *t);//获取定时器当前的超时时间
struct timeval *timer_age_queue();//定时器的时间队列
/* timer_init should be called for every newly allocated timer */
int timer_init(struct timer *t, timeout_func_t f, void *data);//定时器初始化

#ifdef NS_PORT
void timer_add(struct timer *t);//添加定时器
void timer_timeout(struct timeval *now);//定时器超时

#ifdef DEBUG_TIMER_QUEUE
void NS_CLASS printTQ();//打印定时器队列
#endif				/* DEBUG_TIMER_QUEUE */

#endif				/* NS_PORT */

#endif				/* NS_NO_DECLARATIONS */

#endif				/* TIMER_QUEUE_H */
