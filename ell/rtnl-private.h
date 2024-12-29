/*
 * Embedded Linux library
 * Copyright (C) 2022  Intel Corporation
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

struct l_rtnl_address {
	uint8_t family;
	uint8_t prefix_len;
	uint8_t scope;
	union {
		struct in6_addr in6_addr;
		struct in_addr in_addr;
	};
	struct in_addr broadcast;
	char label[IFNAMSIZ];
	uint32_t preferred_lifetime;
	uint32_t valid_lifetime;
	uint64_t preferred_expiry_time;
	uint64_t valid_expiry_time;
	uint32_t flags;
};

struct l_rtnl_route {
	uint8_t family;
	uint8_t scope;
	uint8_t protocol;
	union {
		struct in6_addr in6_addr;
		struct in_addr in_addr;
	} gw;
	union {
		struct in6_addr in6_addr;
		struct in_addr in_addr;
	} dst;
	uint8_t dst_prefix_len;
	union {
		struct in6_addr in6_addr;
		struct in_addr in_addr;
	} prefsrc;
	uint32_t lifetime;
	uint64_t expiry_time;
	uint32_t mtu;
	uint32_t priority;
	uint8_t preference;
};

struct l_netlink_message *rtnl_message_from_route(uint16_t type, uint16_t flags,
						int ifindex,
						const struct l_rtnl_route *rt);
struct l_netlink_message *rtnl_message_from_address(uint16_t type,
					uint16_t flags, int ifindex,
					const struct l_rtnl_address *addr);
