/*
 * Embedded Linux library
 * Copyright (C) 2019  Intel Corporation
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#define _GNU_SOURCE
#include <asm/types.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/icmpv6.h>
#include <linux/neighbour.h>
#include <linux/if_ether.h>
#include <net/if_arp.h>
#include <arpa/inet.h>
#include <errno.h>

#include "useful.h"
#include "netlink.h"
#include "log.h"
#include "util.h"
#include "time.h"
#include "netlink-private.h"
#include "rtnl-private.h"
#include "rtnl.h"
#include "private.h"

static struct l_netlink *rtnl;

static inline int address_to_string(int family, const struct in_addr *v4,
					const struct in6_addr *v6,
					char *out_address)
{
	switch (family) {
	case AF_INET:
		if (!inet_ntop(family, v4, out_address, INET_ADDRSTRLEN))
			return -errno;
		break;
	case AF_INET6:
		if (!inet_ntop(family, v6, out_address, INET6_ADDRSTRLEN))
			return -errno;
		break;
	default:
		return -EAFNOSUPPORT;
	}

	return 0;
}

static int address_get(const char *ip, struct in_addr *out_v4,
				struct in6_addr *out_v6)
{
	if (inet_pton(AF_INET, ip, out_v4) == 1)
		return AF_INET;

	if (inet_pton(AF_INET6, ip, out_v6) == 1)
		return AF_INET6;

	return -EINVAL;
}

static int address_is_null(int family, const struct in_addr *v4,
						const struct in6_addr *v6)
{
	switch (family) {
	case AF_INET:
		return v4->s_addr == 0;
	case AF_INET6:
		return IN6_IS_ADDR_UNSPECIFIED(v6);
	}

	return -EAFNOSUPPORT;
}

static inline void _rtnl_address_init(struct l_rtnl_address *addr,
					uint8_t prefix_len)
{
	addr->prefix_len = prefix_len;
	addr->scope = RT_SCOPE_UNIVERSE;
	addr->flags = IFA_F_PERMANENT;
	memset(addr->label, 0, sizeof(addr->label));
	addr->preferred_lifetime = 0;
	addr->valid_lifetime = 0;
	addr->preferred_expiry_time = 0;
	addr->valid_expiry_time = 0;

	l_rtnl_address_set_broadcast(addr, NULL);
}

static bool rtnl_address_init(struct l_rtnl_address *addr,
				const char *ip, uint8_t prefix_len)
{
	int family;

	if ((family = address_get(ip, &addr->in_addr, &addr->in6_addr)) < 0)
		return false;

	addr->family = family;
	_rtnl_address_init(addr, prefix_len);
	return true;
}

LIB_EXPORT struct l_rtnl_address *l_rtnl_address_new(const char *ip,
							uint8_t prefix_len)
{
	struct in_addr in_addr;
	struct in6_addr in6_addr;
	int family;
	struct l_rtnl_address *addr;

	if ((family = address_get(ip, &in_addr, &in6_addr)) < 0)
		return NULL;

	addr = l_new(struct l_rtnl_address, 1);
	_rtnl_address_init(addr, prefix_len);
	addr->family = family;

	if (family == AF_INET6)
		memcpy(&addr->in6_addr, &in6_addr, sizeof(in6_addr));
	else
		memcpy(&addr->in_addr, &in_addr, sizeof(in_addr));

	return addr;
}

LIB_EXPORT struct l_rtnl_address *l_rtnl_address_clone(
					const struct l_rtnl_address *orig)
{
	return l_memdup(orig, sizeof(struct l_rtnl_address));
}

LIB_EXPORT void l_rtnl_address_free(struct l_rtnl_address *addr)
{
	l_free(addr);
}

LIB_EXPORT bool l_rtnl_address_get_address(const struct l_rtnl_address *addr,
						char *out_buf)
{
	if (unlikely(!addr))
		return false;

	return !address_to_string(addr->family, &addr->in_addr,
						&addr->in6_addr,
						out_buf);
}

LIB_EXPORT const void *l_rtnl_address_get_in_addr(
					const struct l_rtnl_address *addr)
{
	if (unlikely(!addr))
		return NULL;

	return addr->family == AF_INET ? (void *) &addr->in_addr : &addr->in6_addr;
}

LIB_EXPORT uint8_t l_rtnl_address_get_family(const struct l_rtnl_address *addr)
{
	if (unlikely(!addr))
		return 0;

	return addr->family;
}

LIB_EXPORT uint8_t l_rtnl_address_get_prefix_length(
					const struct l_rtnl_address *addr)
{
	if (unlikely(!addr))
		return 0;

	return addr->prefix_len;
}

LIB_EXPORT bool l_rtnl_address_get_broadcast(const struct l_rtnl_address *addr,
						char *out_buf)
{
	if (unlikely(!addr))
		return false;

	inet_ntop(AF_INET, &addr->broadcast, out_buf, INET_ADDRSTRLEN);
	return true;
}

LIB_EXPORT bool l_rtnl_address_set_broadcast(struct l_rtnl_address *addr,
						const char *broadcast)
{
	if (unlikely(!addr))
		return false;

	if (unlikely(addr->family != AF_INET))
		return false;

	if (broadcast) {
		if (inet_pton(AF_INET, broadcast, &addr->broadcast) != 1)
			return false;
	} else
		addr->broadcast.s_addr = addr->in_addr.s_addr |
					htonl(0xFFFFFFFFLU >> addr->prefix_len);

	return true;
}

LIB_EXPORT const char *l_rtnl_address_get_label(
					const struct l_rtnl_address *addr)
{
	if (unlikely(!addr))
		return NULL;

	return addr->label;
}

LIB_EXPORT bool l_rtnl_address_set_label(struct l_rtnl_address *addr,
						const char *label)
{
	if (unlikely(!addr))
		return false;

	if (strlen(label) > IFNAMSIZ - 1)
		return false;

	l_strlcpy(addr->label, label, IFNAMSIZ);
	return true;
}

LIB_EXPORT bool l_rtnl_address_set_noprefixroute(struct l_rtnl_address *addr,
							bool noprefixroute)
{
	if (unlikely(!addr))
		return false;

	if (noprefixroute)
		addr->flags |= IFA_F_NOPREFIXROUTE;
	else
		addr->flags &= ~IFA_F_NOPREFIXROUTE;

	return true;
}

LIB_EXPORT uint32_t l_rtnl_address_get_valid_lifetime(
					const struct l_rtnl_address *addr)
{
	if (unlikely(!addr))
		return false;

	return addr->valid_lifetime;
}

LIB_EXPORT uint32_t l_rtnl_address_get_preferred_lifetime(
					const struct l_rtnl_address *addr)
{
	if (unlikely(!addr))
		return false;

	return addr->preferred_lifetime;
}

LIB_EXPORT bool l_rtnl_address_set_lifetimes(struct l_rtnl_address *addr,
						uint32_t preferred_lifetime,
						uint32_t valid_lifetime)
{
	uint64_t now = l_time_now();

	if (unlikely(!addr))
		return false;

	addr->preferred_lifetime = preferred_lifetime;
	addr->valid_lifetime = valid_lifetime;
	addr->preferred_expiry_time = preferred_lifetime ?
		now + preferred_lifetime * L_USEC_PER_SEC : 0;
	addr->valid_expiry_time = valid_lifetime ?
		now + valid_lifetime * L_USEC_PER_SEC : 0;
	return true;
}

LIB_EXPORT bool l_rtnl_address_get_expiry(const struct l_rtnl_address *addr,
						uint64_t *preferred_expiry_time,
						uint64_t *valid_expiry_time)
{
	if (unlikely(!addr))
		return false;

	if (preferred_expiry_time)
		*preferred_expiry_time = addr->preferred_expiry_time;

	if (valid_expiry_time)
		*valid_expiry_time = addr->valid_expiry_time;

	return true;
}

LIB_EXPORT bool l_rtnl_address_set_expiry(struct l_rtnl_address *addr,
						uint64_t preferred_expiry_time,
						uint64_t valid_expiry_time)
{
	if (unlikely(!addr))
		return false;

	addr->preferred_expiry_time = preferred_expiry_time;
	addr->valid_expiry_time = valid_expiry_time;
	return true;
}

LIB_EXPORT bool l_rtnl_address_set_scope(struct l_rtnl_address *addr,
								uint8_t scope)
{
	if (unlikely(!addr))
		return false;

	addr->scope = scope;
	return true;
}

LIB_EXPORT struct l_rtnl_route *l_rtnl_route_new_gateway(const char *gw)
{
	struct in_addr in_addr;
	struct in6_addr in6_addr;
	int family;
	struct l_rtnl_route *rt;

	if ((family = address_get(gw, &in_addr, &in6_addr)) < 0)
		return NULL;

	rt = l_new(struct l_rtnl_route, 1);
	rt->family = family;
	rt->scope = RT_SCOPE_UNIVERSE;
	rt->protocol = RTPROT_UNSPEC;
	rt->lifetime = 0xffffffff;

	if (family == AF_INET6)
		memcpy(&rt->gw.in6_addr, &in6_addr, sizeof(in6_addr));
	else
		memcpy(&rt->gw.in_addr, &in_addr, sizeof(in_addr));

	return rt;
}

LIB_EXPORT struct l_rtnl_route *l_rtnl_route_new_prefix(const char *ip,
							uint8_t prefix_len)
{
	struct in_addr in_addr;
	struct in6_addr in6_addr;
	int family;
	struct l_rtnl_route *rt;

	if ((family = address_get(ip, &in_addr, &in6_addr)) < 0)
		return NULL;

	if (!prefix_len)
		return NULL;

	if (family == AF_INET && prefix_len > 32)
		return NULL;

	if (family == AF_INET6 && prefix_len > 128)
		return NULL;

	rt = l_new(struct l_rtnl_route, 1);
	rt->family = family;
	rt->protocol = RTPROT_UNSPEC;
	rt->lifetime = 0xffffffff;
	rt->dst_prefix_len = prefix_len;

	/* IPV6 prefix routes are usually global, IPV4 are link-local */
	if (family == AF_INET6) {
		memcpy(&rt->dst.in6_addr, &in6_addr, sizeof(in6_addr));
		rt->scope = RT_SCOPE_UNIVERSE;
	} else {
		memcpy(&rt->dst.in_addr, &in_addr, sizeof(in_addr));
		rt->scope = RT_SCOPE_LINK;
	}

	return rt;
}

LIB_EXPORT struct l_rtnl_route *l_rtnl_route_new_static(const char *gw,
							const char *ip,
							uint8_t prefix_len)
{
	struct in_addr gw_addr4;
	struct in6_addr gw_addr6;
	struct in_addr dst_addr4;
	struct in6_addr dst_addr6;
	int family;
	struct l_rtnl_route *rt;

	if ((family = address_get(gw, &gw_addr4, &gw_addr6)) < 0)
		return NULL;

	if (address_get(ip, &dst_addr4, &dst_addr6) != family)
		return NULL;

	if (prefix_len == 0 || prefix_len > (family == AF_INET ? 32 : 128))
		return NULL;

	rt = l_rtnl_route_new_gateway(gw);
	if (!rt)
		return rt;

	rt->dst_prefix_len = prefix_len;

	if (family == AF_INET6)
		memcpy(&rt->dst.in6_addr, &dst_addr6, sizeof(dst_addr6));
	else
		memcpy(&rt->dst.in_addr, &dst_addr4, sizeof(dst_addr4));

	return rt;
}

LIB_EXPORT void l_rtnl_route_free(struct l_rtnl_route *rt)
{
	l_free(rt);
}

LIB_EXPORT uint8_t l_rtnl_route_get_family(const struct l_rtnl_route *rt)
{
	if (unlikely(!rt))
		return 0;

	return rt->family;
}

LIB_EXPORT bool l_rtnl_route_get_gateway(const struct l_rtnl_route *rt,
						char *out_buf)
{
	if (unlikely(!rt))
		return false;

	if (address_is_null(rt->family, &rt->gw.in_addr, &rt->gw.in6_addr))
		return false;

	return !address_to_string(rt->family, &rt->gw.in_addr, &rt->gw.in6_addr,
					out_buf);
}

LIB_EXPORT const void *l_rtnl_route_get_gateway_in_addr(
						const struct l_rtnl_route *rt)
{
	if (unlikely(!rt))
		return NULL;

	if (address_is_null(rt->family, &rt->gw.in_addr, &rt->gw.in6_addr))
		return NULL;

	if (rt->family == AF_INET)
		return &rt->gw.in_addr;
	else
		return &rt->gw.in6_addr;
}

LIB_EXPORT bool l_rtnl_route_get_dst(const struct l_rtnl_route *rt,
						char *out_buf,
						uint8_t *out_prefix_len)
{
	if (unlikely(!rt))
		return false;

	if (address_to_string(rt->family, &rt->dst.in_addr, &rt->dst.in6_addr,
					out_buf) != 0)
		return false;

	*out_prefix_len = rt->dst_prefix_len;
	return true;
}

LIB_EXPORT const void *l_rtnl_route_get_dst_in_addr(
						const struct l_rtnl_route *rt,
						uint8_t *out_prefix_len)
{
	if (unlikely(!rt))
		return NULL;

	*out_prefix_len = rt->dst_prefix_len;

	if (rt->family == AF_INET)
		return &rt->dst.in_addr;
	else
		return &rt->dst.in6_addr;
}

LIB_EXPORT uint32_t l_rtnl_route_get_lifetime(const struct l_rtnl_route *rt)
{
	if (unlikely(!rt))
		return 0;

	return rt->lifetime;
}

LIB_EXPORT bool l_rtnl_route_set_lifetime(struct l_rtnl_route *rt, uint32_t lt)
{
	if (unlikely(!rt))
		return false;

	rt->lifetime = lt;
	rt->expiry_time = lt ? l_time_now() + lt * L_USEC_PER_SEC : 0;

	return true;
}

LIB_EXPORT uint64_t l_rtnl_route_get_expiry(const struct l_rtnl_route *rt)
{
	return rt->expiry_time;
}

LIB_EXPORT bool l_rtnl_route_set_expiry(struct l_rtnl_route *rt,
					uint64_t expiry_time)
{
	if (unlikely(!rt))
		return false;

	rt->expiry_time = expiry_time;
	return true;
}

LIB_EXPORT uint32_t l_rtnl_route_get_mtu(const struct l_rtnl_route *rt)
{
	if (unlikely(!rt))
		return 0;

	return rt->mtu;
}

LIB_EXPORT bool l_rtnl_route_set_mtu(struct l_rtnl_route *rt, uint32_t mtu)
{
	if (unlikely(!rt))
		return false;

	rt->mtu = mtu;
	return true;
}

LIB_EXPORT uint8_t l_rtnl_route_get_preference(const struct l_rtnl_route *rt)
{
	if (unlikely(!rt))
		return ICMPV6_ROUTER_PREF_INVALID;

	return rt->preference;
}

LIB_EXPORT bool l_rtnl_route_set_preference(struct l_rtnl_route *rt,
							uint8_t preference)
{
	if (unlikely(!rt))
		return false;

	if (!L_IN_SET(preference, ICMPV6_ROUTER_PREF_LOW,
			ICMPV6_ROUTER_PREF_HIGH, ICMPV6_ROUTER_PREF_MEDIUM))
		return false;

	rt->preference = preference;
	return true;
}

LIB_EXPORT bool l_rtnl_route_get_prefsrc(const struct l_rtnl_route *rt,
						char *out_address)
{
	if (unlikely(!rt))
		return false;

	if (address_is_null(rt->family, &rt->prefsrc.in_addr,
					&rt->prefsrc.in6_addr))
		return false;

	return !address_to_string(rt->family, &rt->prefsrc.in_addr,
						&rt->prefsrc.in6_addr,
						out_address);
}

LIB_EXPORT bool l_rtnl_route_set_prefsrc(struct l_rtnl_route *rt,
							const char *address)
{
	if (unlikely(!rt))
		return false;

	switch(rt->family) {
	case AF_INET:
		return inet_pton(AF_INET, address, &rt->prefsrc.in_addr) == 1;
	case AF_INET6:
		return inet_pton(AF_INET6, address, &rt->prefsrc.in6_addr) == 1;
	default:
		return  false;
	}
}

LIB_EXPORT uint32_t l_rtnl_route_get_priority(const struct l_rtnl_route *rt)
{
	if (unlikely(!rt))
		return 0;

	return rt->priority;
}

LIB_EXPORT bool l_rtnl_route_set_priority(struct l_rtnl_route *rt,
							uint32_t priority)
{
	if (unlikely(!rt))
		return false;

	rt->priority = priority;
	return true;
}

LIB_EXPORT uint8_t l_rtnl_route_get_protocol(const struct l_rtnl_route *rt)
{
	if (unlikely(!rt))
		return RTPROT_UNSPEC;

	return rt->protocol;
}

LIB_EXPORT bool l_rtnl_route_set_protocol(struct l_rtnl_route *rt,
							uint8_t protocol)
{
	if (unlikely(!rt))
		return false;

	rt->protocol = protocol;
	return true;
}

LIB_EXPORT uint8_t l_rtnl_route_get_scope(const struct l_rtnl_route *rt)
{
	if (unlikely(!rt))
		return RT_SCOPE_NOWHERE;

	return rt->scope;
}

LIB_EXPORT bool l_rtnl_route_set_scope(struct l_rtnl_route *rt, uint8_t scope)
{
	if (unlikely(!rt))
		return false;

	rt->scope = scope;
	return true;
}

static int append_address(struct l_netlink_message *nlm, uint16_t type,
				uint8_t family,
				const struct in6_addr *v6,
				const struct in_addr *v4)
{
	switch (family) {
	case AF_INET6:
		l_netlink_message_append(nlm, type, v6, sizeof(struct in6_addr));
		return 0;
	case AF_INET:
		l_netlink_message_append(nlm, type, v4, sizeof(struct in_addr));
		return 0;
	}

	return -EAFNOSUPPORT;
}

static void l_rtnl_route_extract(const struct rtmsg *rtmsg, uint32_t len,
				int family, uint32_t *table, uint32_t *ifindex,
				uint32_t *priority, uint8_t *pref,
				char **dst, char **gateway, char **src)
{
	struct rtattr *attr;
	char buf[INET6_ADDRSTRLEN];

	/* Not extracted at the moment: RTA_CACHEINFO for IPv6 */
	for (attr = RTM_RTA(rtmsg); RTA_OK(attr, len);
						attr = RTA_NEXT(attr, len)) {
		switch (attr->rta_type) {
		case RTA_DST:
			if (!dst)
				break;

			inet_ntop(family, RTA_DATA(attr), buf, sizeof(buf));
			*dst = l_strdup(buf);

			break;
		case RTA_GATEWAY:
			if (!gateway)
				break;

			inet_ntop(family, RTA_DATA(attr), buf, sizeof(buf));
			*gateway = l_strdup(buf);

			break;
		case RTA_PREFSRC:
			if (!src)
				break;

			inet_ntop(family, RTA_DATA(attr), buf, sizeof(buf));
			*src = l_strdup(buf);

			break;
		case RTA_TABLE:
			if (!table)
				break;

			*table = *((uint32_t *) RTA_DATA(attr));
			break;
		case RTA_PRIORITY:
			if (!priority)
				break;

			*priority = *((uint32_t *) RTA_DATA(attr));
			break;
		case RTA_PREF:
			if (!pref)
				break;

			*pref = *((uint8_t *) RTA_DATA(attr));
			break;
		case RTA_OIF:
			if (!ifindex)
				break;

			*ifindex = *((uint32_t *) RTA_DATA(attr));
			break;
		}
	}
}

LIB_EXPORT uint32_t l_rtnl_set_linkmode_and_operstate(struct l_netlink *rtnl,
					int ifindex,
					uint8_t linkmode, uint8_t operstate,
					l_netlink_command_func_t cb,
					void *user_data,
					l_netlink_destroy_func_t destroy)
{
	struct l_netlink_message *nlm = l_netlink_message_new(RTM_SETLINK, 0);
	struct ifinfomsg ifi;

	memset(&ifi, 0, sizeof(ifi));
	ifi.ifi_family = AF_UNSPEC;
	ifi.ifi_index = ifindex;

	l_netlink_message_add_header(nlm, &ifi, sizeof(ifi));
	l_netlink_message_append_u8(nlm, IFLA_LINKMODE, linkmode);
	l_netlink_message_append_u8(nlm, IFLA_OPERSTATE, operstate);

	return l_netlink_send(rtnl, nlm, cb, user_data, destroy);
}

LIB_EXPORT uint32_t l_rtnl_set_mac(struct l_netlink *rtnl, int ifindex,
					const uint8_t addr[static 6],
					bool power_up,
					l_netlink_command_func_t cb,
					void *user_data,
					l_netlink_destroy_func_t destroy)
{
	struct l_netlink_message *nlm = l_netlink_message_new(RTM_SETLINK, 0);
	struct ifinfomsg ifi;

	memset(&ifi, 0, sizeof(ifi));
	ifi.ifi_family = AF_UNSPEC;
	ifi.ifi_index = ifindex;

	if (power_up) {
		ifi.ifi_change = IFF_UP;
		ifi.ifi_flags = IFF_UP;
	}

	l_netlink_message_add_header(nlm, &ifi, sizeof(ifi));
	l_netlink_message_append_mac(nlm, IFLA_ADDRESS, addr);

	return l_netlink_send(rtnl, nlm, cb, user_data, destroy);
}

LIB_EXPORT uint32_t l_rtnl_set_powered(struct l_netlink *rtnl, int ifindex,
				bool powered,
				l_netlink_command_func_t cb, void *user_data,
				l_netlink_destroy_func_t destroy)
{
	struct l_netlink_message *nlm = l_netlink_message_new(RTM_SETLINK, 0);
	struct ifinfomsg ifi;

	memset(&ifi, 0, sizeof(ifi));
	ifi.ifi_family = AF_UNSPEC;
	ifi.ifi_index = ifindex;
	ifi.ifi_change = IFF_UP;
	ifi.ifi_flags = powered ? IFF_UP : 0;

	l_netlink_message_add_header(nlm, &ifi, sizeof(ifi));

	return l_netlink_send(rtnl, nlm, cb, user_data, destroy);
}

LIB_EXPORT uint32_t l_rtnl_link_set_mtu(struct l_netlink *rtnl, int ifindex,
				uint32_t mtu,
				l_netlink_command_func_t cb, void *user_data,
				l_netlink_destroy_func_t destroy)
{
	struct l_netlink_message *nlm = l_netlink_message_new(RTM_SETLINK, 0);
	struct ifinfomsg ifi;

	memset(&ifi, 0, sizeof(ifi));
	ifi.ifi_family = AF_UNSPEC;
	ifi.ifi_index = ifindex;

	l_netlink_message_add_header(nlm, &ifi, sizeof(ifi));
	l_netlink_message_append_u32(nlm, IFLA_MTU, mtu);

	return l_netlink_send(rtnl, nlm, cb, user_data, destroy);
}

LIB_EXPORT void l_rtnl_ifaddr4_extract(const struct ifaddrmsg *ifa, int bytes,
				char **label, char **ip, char **broadcast)
{
	char buf[INET_ADDRSTRLEN];
	struct in_addr in_addr;
	struct rtattr *attr;

	for (attr = IFA_RTA(ifa); RTA_OK(attr, bytes);
						attr = RTA_NEXT(attr, bytes)) {
		switch (attr->rta_type) {
		case IFA_LOCAL:
			if (!ip)
				break;

			in_addr = *((struct in_addr *) RTA_DATA(attr));
			*ip = l_strdup(inet_ntop(AF_INET, &in_addr, buf,
							INET_ADDRSTRLEN));

			break;
		case IFA_BROADCAST:
			if (!broadcast)
				break;

			in_addr = *((struct in_addr *) RTA_DATA(attr));
			*broadcast = l_strdup(inet_ntop(AF_INET, &in_addr, buf,
							INET_ADDRSTRLEN));

			break;
		case IFA_LABEL:
			if (!label)
				break;

			*label = l_strdup(RTA_DATA(attr));
			break;
		}
	}
}

LIB_EXPORT uint32_t l_rtnl_ifaddr4_dump(struct l_netlink *rtnl,
					l_netlink_command_func_t cb,
					void *user_data,
					l_netlink_destroy_func_t destroy)
{
	struct ifaddrmsg ifa;
	struct l_netlink_message *nlm =
		l_netlink_message_new_sized(RTM_GETADDR,
						NLM_F_DUMP, sizeof(ifa));

	memset(&ifa, 0, sizeof(ifa));
	ifa.ifa_family = AF_INET;

	l_netlink_message_add_header(nlm, &ifa, sizeof(ifa));

	return l_netlink_send(rtnl, nlm, cb, user_data, destroy);
}

LIB_EXPORT uint32_t l_rtnl_ifaddr4_add(struct l_netlink *rtnl, int ifindex,
				uint8_t prefix_len, const char *ip,
				const char *broadcast,
				l_netlink_command_func_t cb, void *user_data,
				l_netlink_destroy_func_t destroy)
{
	struct l_rtnl_address a4;

	if (!rtnl_address_init(&a4, ip, prefix_len))
		return 0;

	if (broadcast)
		if (!l_rtnl_address_set_broadcast(&a4, broadcast))
			return 0;

	return l_rtnl_ifaddr_add(rtnl, ifindex, &a4, cb, user_data, destroy);
}

LIB_EXPORT uint32_t l_rtnl_ifaddr4_delete(struct l_netlink *rtnl, int ifindex,
				uint8_t prefix_len, const char *ip,
				const char *broadcast,
				l_netlink_command_func_t cb, void *user_data,
				l_netlink_destroy_func_t destroy)
{
	struct l_rtnl_address a4;

	if (!rtnl_address_init(&a4, ip, prefix_len))
		return 0;

	if (broadcast)
		if (!l_rtnl_address_set_broadcast(&a4, broadcast))
			return 0;

	return l_rtnl_ifaddr_delete(rtnl, ifindex, &a4, cb, user_data, destroy);
}

LIB_EXPORT void l_rtnl_route4_extract(const struct rtmsg *rtmsg, uint32_t len,
				uint32_t *table, uint32_t *ifindex,
				char **dst, char **gateway, char **src)
{
	l_rtnl_route_extract(rtmsg, len, AF_INET, table, ifindex,
				NULL, NULL, dst, gateway, src);
}

LIB_EXPORT uint32_t l_rtnl_route4_dump(struct l_netlink *rtnl,
				l_netlink_command_func_t cb, void *user_data,
				l_netlink_destroy_func_t destroy)
{
	struct rtmsg rtm;
	struct l_netlink_message *nlm =
		l_netlink_message_new_sized(RTM_GETROUTE,
						NLM_F_DUMP, sizeof(rtm));

	memset(&rtm, 0, sizeof(rtm));
	rtm.rtm_family = AF_INET;

	l_netlink_message_add_header(nlm, &rtm, sizeof(rtm));

	return l_netlink_send(rtnl, nlm, cb, user_data, destroy);
}

LIB_EXPORT uint32_t l_rtnl_route4_add_connected(struct l_netlink *rtnl,
					int ifindex,
					uint8_t dst_len, const char *dst,
					const char *src, uint8_t proto,
					l_netlink_command_func_t cb,
					void *user_data,
					l_netlink_destroy_func_t destroy)
{
	struct l_rtnl_route *rt = l_rtnl_route_new_prefix(dst, dst_len);
	uint32_t r = 0;

	if (!rt)
		return 0;

	l_rtnl_route_set_protocol(rt, proto);
	if (!l_rtnl_route_set_prefsrc(rt, src))
		goto err;

	r = l_rtnl_route_add(rtnl, ifindex, rt, cb, user_data, destroy);
err:
	l_rtnl_route_free(rt);
	return r;
}

LIB_EXPORT uint32_t l_rtnl_route4_add_gateway(struct l_netlink *rtnl,
					int ifindex,
					const char *gateway, const char *src,
					uint32_t priority_offset,
					uint8_t proto,
					l_netlink_command_func_t cb,
					void *user_data,
					l_netlink_destroy_func_t destroy)
{
	struct l_rtnl_route *rt = l_rtnl_route_new_gateway(gateway);
	uint32_t r;

	if (!rt)
		return 0;

	l_rtnl_route_set_protocol(rt, proto);
	l_rtnl_route_set_priority(rt, priority_offset);

	r = l_rtnl_route_add(rtnl, ifindex, rt, cb, user_data, destroy);
	l_rtnl_route_free(rt);
	return r;
}

LIB_EXPORT void l_rtnl_ifaddr6_extract(const struct ifaddrmsg *ifa, int len,
					char **ip)
{
	struct in6_addr in6_addr;
	struct rtattr *attr;
	char address[128];

	for (attr = IFA_RTA(ifa); RTA_OK(attr, len);
						attr = RTA_NEXT(attr, len)) {
		switch (attr->rta_type) {
		case IFA_ADDRESS:
			if (!ip)
				break;

			memcpy(&in6_addr.s6_addr, RTA_DATA(attr),
						sizeof(in6_addr.s6_addr));

			if (!inet_ntop(AF_INET6, &in6_addr, address,
							INET6_ADDRSTRLEN)) {
				l_error("rtnl: Failed to extract IPv6 address");
				break;
			}

			*ip = l_strdup(address);

			break;
		}
	}
}

LIB_EXPORT uint32_t l_rtnl_ifaddr6_dump(struct l_netlink *rtnl,
				l_netlink_command_func_t cb, void *user_data,
				l_netlink_destroy_func_t destroy)
{
	struct ifaddrmsg ifa;
	struct l_netlink_message *nlm =
		l_netlink_message_new_sized(RTM_GETADDR,
						NLM_F_DUMP, sizeof(ifa));

	memset(&ifa, 0, sizeof(ifa));
	ifa.ifa_family = AF_INET6;

	l_netlink_message_add_header(nlm, &ifa, sizeof(ifa));

	return l_netlink_send(rtnl, nlm, cb, user_data, destroy);
}

LIB_EXPORT uint32_t l_rtnl_ifaddr6_add(struct l_netlink *rtnl, int ifindex,
				uint8_t prefix_len, const char *ip,
				l_netlink_command_func_t cb, void *user_data,
				l_netlink_destroy_func_t destroy)
{
	struct l_rtnl_address a6;

	if (!rtnl_address_init(&a6, ip, prefix_len))
		return 0;

	return l_rtnl_ifaddr_add(rtnl, ifindex, &a6, cb, user_data, destroy);
}

LIB_EXPORT uint32_t l_rtnl_ifaddr6_delete(struct l_netlink *rtnl, int ifindex,
					uint8_t prefix_len, const char *ip,
					l_netlink_command_func_t cb,
					void *user_data,
					l_netlink_destroy_func_t destroy)
{
	struct l_rtnl_address a6;

	if (!rtnl_address_init(&a6, ip, prefix_len))
		return 0;

	return l_rtnl_ifaddr_delete(rtnl, ifindex, &a6, cb, user_data, destroy);
}

LIB_EXPORT void l_rtnl_route6_extract(const struct rtmsg *rtmsg, uint32_t len,
				uint32_t *table, uint32_t *ifindex,
				char **dst, char **gateway, char **src)
{
	l_rtnl_route_extract(rtmsg, len, AF_INET6, table, ifindex,
				NULL, NULL, dst, gateway, src);
}

LIB_EXPORT uint32_t l_rtnl_route6_dump(struct l_netlink *rtnl,
				l_netlink_command_func_t cb, void *user_data,
				l_netlink_destroy_func_t destroy)
{
	struct rtmsg rtm;
	struct l_netlink_message *nlm =
		l_netlink_message_new_sized(RTM_GETROUTE,
						NLM_F_DUMP, sizeof(rtm));

	memset(&rtm, 0, sizeof(rtm));
	rtm.rtm_family = AF_INET6;

	l_netlink_message_add_header(nlm, &rtm, sizeof(rtm));

	return l_netlink_send(rtnl, nlm, cb, user_data, destroy);
}

LIB_EXPORT uint32_t l_rtnl_route6_add_gateway(struct l_netlink *rtnl,
					int ifindex,
					const char *gateway,
					uint32_t priority_offset,
					uint8_t proto,
					l_netlink_command_func_t cb,
					void *user_data,
					l_netlink_destroy_func_t destroy)
{
	struct l_rtnl_route *rt = l_rtnl_route_new_gateway(gateway);
	uint32_t r;

	if (!rt)
		return 0;

	l_rtnl_route_set_protocol(rt, proto);
	l_rtnl_route_set_priority(rt, priority_offset);

	r = l_rtnl_route_add(rtnl, ifindex, rt, cb, user_data, destroy);
	l_rtnl_route_free(rt);
	return r;
}

LIB_EXPORT uint32_t l_rtnl_route6_delete_gateway(struct l_netlink *rtnl,
					int ifindex,
					const char *gateway,
					uint32_t priority_offset,
					uint8_t proto,
					l_netlink_command_func_t cb,
					void *user_data,
					l_netlink_destroy_func_t destroy)
{
	struct l_rtnl_route *rt = l_rtnl_route_new_gateway(gateway);
	uint32_t r;

	if (!rt)
		return 0;

	l_rtnl_route_set_protocol(rt, proto);
	l_rtnl_route_set_priority(rt, priority_offset);

	r = l_rtnl_route_delete(rtnl, ifindex, rt, cb, user_data, destroy);
	l_rtnl_route_free(rt);
	return r;
}

LIB_EXPORT struct l_rtnl_address *l_rtnl_ifaddr_extract(
						const struct ifaddrmsg *ifa,
						int bytes)
{
	struct rtattr *attr;
	struct ifa_cacheinfo *cinfo;
	struct l_rtnl_address *addr;

	if (unlikely(!ifa))
		return NULL;

	if (!L_IN_SET(ifa->ifa_family, AF_INET, AF_INET6))
		return NULL;

	addr = l_new(struct l_rtnl_address, 1);
	addr->prefix_len = ifa->ifa_prefixlen;
	addr->family = ifa->ifa_family;
	addr->flags = ifa->ifa_flags;
	addr->scope = ifa->ifa_scope;

	for (attr = IFA_RTA(ifa); RTA_OK(attr, bytes);
						attr = RTA_NEXT(attr, bytes)) {
		switch (attr->rta_type) {
		case IFA_LOCAL:
			if (ifa->ifa_family == AF_INET)
				addr->in_addr =
					*((struct in_addr *) RTA_DATA(attr));

			break;
		case IFA_ADDRESS:
			if (ifa->ifa_family == AF_INET6)
				addr->in6_addr =
					*((struct in6_addr *) RTA_DATA(attr));

			break;
		case IFA_BROADCAST:
			addr->broadcast = *((struct in_addr *) RTA_DATA(attr));
			break;
		case IFA_LABEL:
			l_strlcpy(addr->label, RTA_DATA(attr),
					sizeof(addr->label));
			break;
		case IFA_CACHEINFO:
			cinfo = RTA_DATA(attr);
			l_rtnl_address_set_lifetimes(addr, cinfo->ifa_prefered,
							cinfo->ifa_valid);
			break;
		}
	}

	return addr;
}

LIB_EXPORT uint32_t l_rtnl_ifaddr_add(struct l_netlink *rtnl, int ifindex,
					const struct l_rtnl_address *addr,
					l_netlink_command_func_t cb,
					void *user_data,
					l_netlink_destroy_func_t destroy)
{
	struct l_netlink_message *nlm =
		rtnl_message_from_address(RTM_NEWADDR,
						NLM_F_CREATE | NLM_F_REPLACE,
						ifindex, addr);

	return l_netlink_send(rtnl, nlm, cb, user_data, destroy);
}

LIB_EXPORT uint32_t l_rtnl_ifaddr_delete(struct l_netlink *rtnl, int ifindex,
					const struct l_rtnl_address *addr,
					l_netlink_command_func_t cb,
					void *user_data,
					l_netlink_destroy_func_t destroy)
{
	struct l_netlink_message *nlm =
		rtnl_message_from_address(RTM_DELADDR, 0, ifindex, addr);

	return l_netlink_send(rtnl, nlm, cb, user_data, destroy);
}

LIB_EXPORT uint32_t l_rtnl_route_add(struct l_netlink *rtnl, int ifindex,
					const struct l_rtnl_route *rt,
					l_netlink_command_func_t cb,
					void *user_data,
					l_netlink_destroy_func_t destroy)
{
	struct l_netlink_message *nlm =
		rtnl_message_from_route(RTM_NEWROUTE,
						NLM_F_CREATE | NLM_F_REPLACE,
						ifindex, rt);

	return l_netlink_send(rtnl, nlm, cb, user_data, destroy);
}

LIB_EXPORT uint32_t l_rtnl_route_delete(struct l_netlink *rtnl, int ifindex,
					const struct l_rtnl_route *rt,
					l_netlink_command_func_t cb,
					void *user_data,
					l_netlink_destroy_func_t destroy)
{
	struct l_netlink_message *nlm =
		rtnl_message_from_route(RTM_DELROUTE, 0, ifindex, rt);

	return l_netlink_send(rtnl, nlm, cb, user_data, destroy);
}

struct rtnl_neighbor_get_data {
	l_rtnl_neighbor_get_cb_t cb;
	void *user_data;
	l_netlink_destroy_func_t destroy;
};

static void rtnl_neighbor_get_cb(int error, uint16_t type, const void *data,
					uint32_t len, void *user_data)
{
	struct rtnl_neighbor_get_data *cb_data = user_data;
	const struct ndmsg *ndmsg = data;
	struct rtattr *attr;
	const uint8_t *hwaddr = NULL;
	size_t hwaddr_len = 0;

	if (error != 0)
		goto done;

	if (type != RTM_NEWNEIGH || len < NLMSG_ALIGN(sizeof(*ndmsg))) {
		error = -EIO;
		goto done;
	}

	if (!(ndmsg->ndm_state & (NUD_PERMANENT | NUD_NOARP | NUD_REACHABLE))) {
		error = -ENOENT;
		goto done;
	}

	attr = (void *) ndmsg + NLMSG_ALIGN(sizeof(*ndmsg));
	len -= NLMSG_ALIGN(sizeof(*ndmsg));

	for (; RTA_OK(attr, len); attr = RTA_NEXT(attr, len))
		switch (attr->rta_type) {
		case NDA_LLADDR:
			hwaddr = RTA_DATA(attr);
			hwaddr_len = RTA_PAYLOAD(attr);
			break;
		}

	if (!hwaddr)
		error = -EIO;

done:
	if (cb_data->cb) {
		cb_data->cb(error, hwaddr, hwaddr_len, cb_data->user_data);
		cb_data->cb = NULL;
	}
}

static void rtnl_neighbor_get_destroy_cb(void *user_data)
{
	struct rtnl_neighbor_get_data *cb_data = user_data;

	if (cb_data->destroy)
		cb_data->destroy(cb_data->user_data);

	l_free(cb_data);
}

LIB_EXPORT uint32_t l_rtnl_neighbor_get_hwaddr(struct l_netlink *rtnl,
					int ifindex, int family,
					const void *ip,
					l_rtnl_neighbor_get_cb_t cb,
					void *user_data,
					l_netlink_destroy_func_t destroy)
{
	struct ndmsg ndm;
	struct l_netlink_message *nlm = l_netlink_message_new(RTM_GETNEIGH, 0);
	__auto_type cb_data = struct_alloc(rtnl_neighbor_get_data,
						cb, user_data, destroy);
	int ret;

	memset(&ndm, 0, sizeof(ndm));
	ndm.ndm_family = family;
	ndm.ndm_ifindex = ifindex;
	ndm.ndm_flags = 0;

	l_netlink_message_add_header(nlm, &ndm, sizeof(ndm));
	append_address(nlm, NDA_DST, family, ip, ip);

	ret = l_netlink_send(rtnl, nlm, rtnl_neighbor_get_cb, cb_data,
				rtnl_neighbor_get_destroy_cb);
	if (ret)
		return ret;

	l_free(cb_data);
	return 0;
}

LIB_EXPORT uint32_t l_rtnl_neighbor_set_hwaddr(struct l_netlink *rtnl,
					int ifindex, int family,
					const void *ip,
					const uint8_t *hwaddr,
					size_t hwaddr_len,
					l_netlink_command_func_t cb,
					void *user_data,
					l_netlink_destroy_func_t destroy)
{
	struct ndmsg ndm;
	struct l_netlink_message *nlm =
			l_netlink_message_new(RTM_NEWNEIGH,
						NLM_F_CREATE | NLM_F_REPLACE);
	memset(&ndm, 0, sizeof(ndm));
	ndm.ndm_family = family;
	ndm.ndm_ifindex = ifindex;
	ndm.ndm_flags = 0;
	ndm.ndm_state = NUD_REACHABLE;

	l_netlink_message_add_header(nlm, &ndm, sizeof(ndm));
	append_address(nlm, NDA_DST, family, ip, ip);
	l_netlink_message_append(nlm, NDA_LLADDR, hwaddr, hwaddr_len);

	return l_netlink_send(rtnl, nlm, cb, user_data, destroy);
}

__attribute__((destructor(32000))) static void free_rtnl()
{
	l_netlink_destroy(rtnl);
}

LIB_EXPORT struct l_netlink *l_rtnl_get()
{
	if (!rtnl)
		rtnl = l_netlink_new(NETLINK_ROUTE);

	return rtnl;
}

struct l_netlink_message *rtnl_message_from_route(uint16_t type, uint16_t flags,
						int ifindex,
						const struct l_rtnl_route *rt)
{
	struct l_netlink_message *nlm = l_netlink_message_new(type, flags);
	uint64_t now = l_time_now();
	struct rtmsg rtm;

	memset(&rtm, 0, sizeof(struct rtmsg));
	rtm.rtm_family = rt->family;
	rtm.rtm_table = RT_TABLE_MAIN;
	rtm.rtm_protocol = rt->protocol;
	rtm.rtm_type = RTN_UNICAST;
	rtm.rtm_scope = rt->scope;
	rtm.rtm_dst_len = rt->dst_prefix_len;

	l_netlink_message_add_header(nlm, &rtm, sizeof(rtm));
	l_netlink_message_append_u32(nlm, RTA_OIF, ifindex);

	if (rt->priority)
		l_netlink_message_append_u32(nlm, RTA_PRIORITY,
						rt->priority + ifindex);

	if (!address_is_null(rt->family, &rt->gw.in_addr, &rt->gw.in6_addr))
		append_address(nlm, RTA_GATEWAY, rt->family,
					&rt->gw.in6_addr, &rt->gw.in_addr);

	if (rt->dst_prefix_len)
		append_address(nlm, RTA_DST, rt->family,
					&rt->dst.in6_addr, &rt->dst.in_addr);

	if (!address_is_null(rt->family, &rt->prefsrc.in_addr,
						&rt->prefsrc.in6_addr))
		append_address(nlm, RTA_PREFSRC, rt->family,
						&rt->prefsrc.in6_addr,
						&rt->prefsrc.in_addr);

	if (rt->mtu) {
		/*
		 * NOTE: Legacy RTNL messages do not use NLA_F_NESTED flag
		 * as they should.  l_netlink_message_enter_nested does.  The
		 * kernel should still accept this however
		 */
		l_netlink_message_enter_nested(nlm, RTA_METRICS);
		l_netlink_message_append_u32(nlm, RTAX_MTU, rt->mtu);
		l_netlink_message_leave_nested(nlm);
	}

	if (rt->preference)
		l_netlink_message_append_u8(nlm, RTA_PREF, rt->preference);

	if (rt->expiry_time > now)
		l_netlink_message_append_u32(nlm, RTA_EXPIRES,
					l_time_to_secs(rt->expiry_time - now));

	return nlm;
}

struct l_netlink_message *rtnl_message_from_address(uint16_t type,
					uint16_t flags, int ifindex,
					const struct l_rtnl_address *addr)
{
	struct l_netlink_message *nlm = l_netlink_message_new(type, flags);
	struct ifaddrmsg ifa;
	uint64_t now = l_time_now();

	memset(&ifa, 0, sizeof(ifa));
	ifa.ifa_index = ifindex;
	ifa.ifa_family = addr->family;
	ifa.ifa_scope = addr->scope;
	ifa.ifa_prefixlen = addr->prefix_len;
	/* Kernel ignores legacy flags in IFA_FLAGS, so set them here */
	ifa.ifa_flags = addr->flags & 0xff;

	l_netlink_message_add_header(nlm, &ifa, sizeof(ifa));

	if (addr->family == AF_INET) {
		l_netlink_message_append(nlm, IFA_LOCAL, &addr->in_addr,
						sizeof(struct in_addr));
		l_netlink_message_append(nlm, IFA_BROADCAST, &addr->broadcast,
						sizeof(struct in_addr));
	} else
		l_netlink_message_append(nlm, IFA_LOCAL, &addr->in6_addr,
						sizeof(struct in6_addr));

	/* Address & Prefix length are enough to perform deletions */
	if (type == RTM_DELADDR)
		goto done;

	if (addr->flags & 0xffffff00)
		l_netlink_message_append_u32(nlm, IFA_FLAGS,
						addr->flags & 0xffffff00);

	if (addr->label[0])
		l_netlink_message_append(nlm, IFA_LABEL,
					addr->label, strlen(addr->label) + 1);

	if (addr->preferred_expiry_time > now ||
			addr->valid_expiry_time > now) {
		struct ifa_cacheinfo cinfo;

		memset(&cinfo, 0, sizeof(cinfo));
		cinfo.ifa_prefered = addr->preferred_expiry_time > now ?
			l_time_to_secs(addr->preferred_expiry_time - now) : 0;
		cinfo.ifa_valid =  addr->valid_expiry_time > now ?
			l_time_to_secs(addr->valid_expiry_time - now) : 0;

		l_netlink_message_append(nlm, IFA_CACHEINFO,
						&cinfo, sizeof(cinfo));
	}
done:
	return nlm;
}
