#ifndef __NETPACK_H
#define __NETPACK_H

// struct so_event {
// 	u32 src_addr;
// 	u32 dst_addr;
// 	// u32 ip_proto;
// 	// u32 pkt_type;
// 	// u32 ifindex;
// };

struct so_event {
	__be32 src_addr;
	__be32 dst_addr;
	union {
		__be32 ports;
		__be16 port16[2];
	};
	__u32 ip_proto;
	__u32 pkt_type;
	__u32 ifindex;
};

#endif /* __SOCKFILTER_H */