# NSA2019-Group10
---
## aodv-uu-0.9.6

12.2
添加RREQ，RREP，RREE消息的格式，对相关函数进行学习，记录在对应.c及.h文件中

对aodv过程进行学习

每个节点上的每个路由表条目必须包含关于维护路由表条目的目标节点的IP地址的序列号的最新可用信息。

这个序列号称为“目的序列号”。每当一个节点接收到新信息(例如，有关序列号的信息来自可能接收到的与该目的地相关的RREQ、RREP或RERR消息。AODV依赖于网络中的每个节点来拥有和维护其目标序列号，以保证所有路由到该节点的环自由。目标节点在两种情况下增加自己的序列号:
1. 在节点发起路由发现之前，必须增加自己的路由序列号，以免和之前的反向路径发生冲突，反向路径指向之前rreq的发起者
2. 在一个目标节点发送rrep回复rreq时 它必须将自己的序列号更新到RREQ包中当前序列号和目标序列号的最大值。

A->C->D->E

REEQ <A,1,1,E, ,0> <OAddr,OSeq,BroadcastID,DAddr,DSeq>
REEP <E,A,120,0> <DAddr,OAddr,Seq,hop>

路由表 routingtable.h routingtable.c