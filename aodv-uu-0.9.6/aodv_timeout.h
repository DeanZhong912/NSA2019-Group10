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
 *
 *****************************************************************************/
#ifndef _AODV_TIMEOUT_H
#define _AODV_TIMEOUT_H

#ifndef NS_NO_GLOBALS
#include "defs.h"
#endif				/* NS_NO_GLOBALS */

#ifndef NS_NO_DECLARATIONS
void route_delete_timeout(void *arg);//路由删除超时
void local_repair_timeout(void *arg);//本地修复超时
void route_discovery_timeout(void *arg);//路由发现超时
void route_expire_timeout(void *arg);//路由到期超时
void hello_timeout(void *arg);//hello消息超时
void rrep_ack_timeout(void *arg);//回复确认超时
void wait_on_reboot_timeout(void *arg);//重启等待超时
void packet_queue_timeout(void *arg);//数据包排队超时
#endif				/* NS_NO_DECLARATIONS */

#endif				/* AODV_TIMEOUT_H */
