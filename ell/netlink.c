/*
 * Embedded Linux library
 * Copyright (C) 2011-2014  Intel Corporation
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <unistd.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <limits.h>

#include "useful.h"
#include "hashmap.h"
#include "queue.h"
#include "io.h"
#include "private.h"
#include "netlink-private.h"
#include "netlink.h"

struct command {
	unsigned int id;
	l_netlink_command_func_t handler;
	l_netlink_destroy_func_t destroy;
	void *user_data;
	struct l_netlink_message *message;
};

struct notify {
	uint32_t group;
	l_netlink_notify_func_t handler;
	l_netlink_destroy_func_t destroy;
	void *user_data;
};

struct l_netlink {
	uint32_t pid;
	struct l_io *io;
	uint32_t next_seq;
	struct l_queue *command_queue;
	struct l_hashmap *command_pending;
	struct l_hashmap *command_lookup;
	unsigned int next_command_id;
	struct l_hashmap *notify_groups;
	struct l_hashmap *notify_lookup;
	unsigned int next_notify_id;
	l_netlink_debug_func_t debug_handler;
	l_netlink_destroy_func_t debug_destroy;
	void *debug_data;
};

static void destroy_command(void *data)
{
	struct command *command = data;

	if (command->destroy)
		command->destroy(command->user_data);

	l_netlink_message_unref(command->message);
	l_free(command);
}

static void destroy_notify(void *data)
{
	struct notify *notify = data;

	if (notify->destroy)
		notify->destroy(notify->user_data);

	l_free(notify);
}

static void destroy_notify_group(void *data)
{
	struct l_hashmap *notify_list = data;

	l_hashmap_destroy(notify_list, destroy_notify);
}

static bool can_write_data(struct l_io *io, void *user_data)
{
	struct l_netlink *netlink = user_data;
	struct command *command;
	struct nlmsghdr *hdr;
	struct sockaddr_nl addr;
	ssize_t written;
	int sk;

	command = l_queue_pop_head(netlink->command_queue);
	if (!command)
		return false;

	hdr = command->message->hdr;
	sk = l_io_get_fd(io);

	memset(&addr, 0, sizeof(addr));
	addr.nl_family = AF_NETLINK;
	addr.nl_pid = 0;

	written = sendto(sk, hdr, hdr->nlmsg_len, 0,
			(struct sockaddr *) &addr, sizeof(addr));
	if (written < 0 || (uint32_t) written != hdr->nlmsg_len) {
		l_hashmap_remove(netlink->command_lookup,
					L_UINT_TO_PTR(command->id));
		destroy_command(command);
		return true;
	}

	l_util_hexdump(false, hdr, hdr->nlmsg_len,
				netlink->debug_handler, netlink->debug_data);

	l_hashmap_insert(netlink->command_pending,
				L_UINT_TO_PTR(hdr->nlmsg_seq), command);

	return l_queue_length(netlink->command_queue) > 0;
}

static void do_notify(const void *key, void *value, void *user_data)
{
	struct nlmsghdr *nlmsg = user_data;
	struct notify *notify = value;

	if (notify->handler) {
		notify->handler(nlmsg->nlmsg_type, NLMSG_DATA(nlmsg),
			nlmsg->nlmsg_len - NLMSG_HDRLEN, notify->user_data);
	}
}

static void process_broadcast(struct l_netlink *netlink, uint32_t group,
						struct nlmsghdr *nlmsg)
{
	struct l_hashmap *notify_list;

	notify_list = l_hashmap_lookup(netlink->notify_groups,
						L_UINT_TO_PTR(group));
	if (!notify_list)
		return;

	l_hashmap_foreach(notify_list, do_notify, nlmsg);
}

static void process_ext_ack(struct l_netlink *netlink,
				const struct nlmsghdr *nlmsg)
{
	const char *err_str = NULL;
	uint32_t err_offset = -1U;
	_auto_(l_free) char *dbg_str = NULL;

	if (!netlink->debug_handler)
		return;

	if (!netlink_parse_ext_ack_error(nlmsg, &err_str, &err_offset) ||
			(!err_str && err_offset == -1U))
		return;

	if (err_str && err_offset != -1U)
		dbg_str = l_strdup_printf("Extended error: '%s', offset of "
					" offending element within request: "
					"%i bytes", err_str, (int) err_offset);
	else if (err_str)
		dbg_str = l_strdup_printf("Extended error: '%s'", err_str);
	else
		dbg_str = l_strdup_printf("Offset of offending element within "
					"request: %i bytes", (int) err_offset);

	netlink->debug_handler(dbg_str, netlink->debug_data);
}

static void process_message(struct l_netlink *netlink, struct nlmsghdr *nlmsg)
{
	const void *data = nlmsg;
	struct command *command;

	command = l_hashmap_remove(netlink->command_pending,
					L_UINT_TO_PTR(nlmsg->nlmsg_seq));
	if (!command)
		return;

	if (!command->handler)
		goto done;

	if (nlmsg->nlmsg_type < NLMSG_MIN_TYPE) {
		const struct nlmsgerr *err;

		switch (nlmsg->nlmsg_type) {
		case NLMSG_ERROR:
			err = NLMSG_DATA(nlmsg);

			command->handler(err->error, 0, NULL, 0,
							command->user_data);

			process_ext_ack(netlink, nlmsg);
			break;
		}
	} else {
		command->handler(0, nlmsg->nlmsg_type, data + NLMSG_HDRLEN,
					nlmsg->nlmsg_len - NLMSG_HDRLEN,
					command->user_data);
	}

done:
	l_hashmap_remove(netlink->command_lookup, L_UINT_TO_PTR(command->id));

	destroy_command(command);
}

static void process_multi(struct l_netlink *netlink, struct nlmsghdr *nlmsg)
{
	const void *data = nlmsg;
	struct command *command;

	if (nlmsg->nlmsg_type < NLMSG_MIN_TYPE) {
		command = l_hashmap_remove(netlink->command_pending,
					L_UINT_TO_PTR(nlmsg->nlmsg_seq));
		if (!command)
			return;

		l_hashmap_remove(netlink->command_lookup,
					L_UINT_TO_PTR(command->id));

		destroy_command(command);
	} else {
		command = l_hashmap_lookup(netlink->command_pending,
					L_UINT_TO_PTR(nlmsg->nlmsg_seq));
		if (!command)
			return;

		if (!command->handler)
			return;

		command->handler(0, nlmsg->nlmsg_type, data + NLMSG_HDRLEN,
					nlmsg->nlmsg_len - NLMSG_HDRLEN,
					command->user_data);
	}
}

static bool can_read_data(struct l_io *io, void *user_data)
{
	struct l_netlink *netlink = user_data;
	struct cmsghdr *cmsg;
	struct msghdr msg;
	struct iovec iov;
	struct nlmsghdr *nlmsg;
	unsigned char buffer[4096];
	unsigned char control[32];
	uint32_t group = 0;
	ssize_t len;
	int sk;

	memset(buffer, 0, sizeof(buffer));
	memset(control, 0, sizeof(control));

	sk = l_io_get_fd(io);

	iov.iov_base = buffer;
	iov.iov_len = sizeof(buffer);

	memset(&msg, 0, sizeof(msg));
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = control;
	msg.msg_controllen = sizeof(control);

	len = recvmsg(sk, &msg, 0);
	if (len < 0)
		return false;

	l_util_hexdump(true, buffer, len, netlink->debug_handler,
						netlink->debug_data);

	for (cmsg = CMSG_FIRSTHDR(&msg); cmsg != NULL;
					cmsg = CMSG_NXTHDR(&msg, cmsg)) {
		struct nl_pktinfo *pktinfo;

		if (cmsg->cmsg_level != SOL_NETLINK)
			continue;

		if (cmsg->cmsg_type != NETLINK_PKTINFO)
			continue;

		pktinfo = (void *) CMSG_DATA(cmsg);

		group = pktinfo->group;
	}

	for (nlmsg = iov.iov_base; NLMSG_OK(nlmsg, (uint32_t) len);
					nlmsg = NLMSG_NEXT(nlmsg, len)) {
		if (group > 0) {
			process_broadcast(netlink, group, nlmsg);
			continue;
		}

		if (nlmsg->nlmsg_pid != netlink->pid)
			continue;

		if (nlmsg->nlmsg_flags & NLM_F_MULTI)
			process_multi(netlink, nlmsg);
		else
			process_message(netlink, nlmsg);
	}

	return true;
}

static int create_netlink_socket(int protocol, uint32_t *pid)
{
	struct sockaddr_nl addr;
	socklen_t addrlen = sizeof(addr);
	int sk, pktinfo = 1;

	sk = socket(PF_NETLINK, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK,
								protocol);
	if (sk < 0)
		return -1;

	memset(&addr, 0, sizeof(addr));
	addr.nl_family = AF_NETLINK;

	if (bind(sk, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		close(sk);
		return -1;
	}

	if (getsockname(sk, (struct sockaddr *) &addr, &addrlen) < 0) {
		close(sk);
		return -1;
	}

	if (setsockopt(sk, SOL_NETLINK, NETLINK_PKTINFO,
					&pktinfo, sizeof(pktinfo)) < 0) {
		close(sk);
		return -1;
	}

	if (pid)
		*pid = addr.nl_pid;

	return sk;
}

LIB_EXPORT struct l_netlink *l_netlink_new(int protocol)
{
	struct l_netlink *netlink;
	int sk;
	struct l_io *io;
	uint32_t pid;

	sk = create_netlink_socket(protocol, &pid);
	if (sk < 0)
		return NULL;

	io = l_io_new(sk);
	if (!io) {
		close(sk);
		return NULL;
	}

	netlink = l_new(struct l_netlink, 1);

	netlink->pid = pid;
	netlink->next_seq = 1;
	netlink->next_command_id = 1;
	netlink->next_notify_id = 1;

	netlink->io = io;
	l_io_set_close_on_destroy(netlink->io, true);
	l_io_set_read_handler(netlink->io, can_read_data, netlink, NULL);

	netlink->command_queue = l_queue_new();
	netlink->command_pending = l_hashmap_new();
	netlink->command_lookup = l_hashmap_new();

	netlink->notify_groups = l_hashmap_new();
	netlink->notify_lookup = l_hashmap_new();

	return netlink;
}

LIB_EXPORT void l_netlink_destroy(struct l_netlink *netlink)
{
	if (unlikely(!netlink))
		return;

	l_hashmap_destroy(netlink->notify_lookup, NULL);
	l_hashmap_destroy(netlink->notify_groups, destroy_notify_group);

	l_queue_destroy(netlink->command_queue, NULL);
	l_hashmap_destroy(netlink->command_pending, NULL);
	l_hashmap_destroy(netlink->command_lookup, destroy_command);

	l_io_destroy(netlink->io);

	l_free(netlink);
}

LIB_EXPORT unsigned int l_netlink_send(struct l_netlink *netlink,
					struct l_netlink_message *message,
					l_netlink_command_func_t function,
					void *user_data,
					l_netlink_destroy_func_t destroy)
{
	struct command *command;
	uint16_t extra_flags = NLM_F_REQUEST;
	struct nlmsghdr *nlmsg;

	if (unlikely(!netlink))
		return 0;

	if (unlikely(message->nest_level))
		return 0;

	if (function)
		extra_flags |= NLM_F_ACK;

	command = l_new(struct command, 1);

	if (!l_hashmap_insert(netlink->command_lookup,
				L_UINT_TO_PTR(netlink->next_command_id),
				command)) {
		l_free(command);
		return 0;
	}

	command->handler = function;
	command->destroy = destroy;
	command->user_data = user_data;
	command->id = netlink->next_command_id++;
	command->message = message;
	message->sealed = true;

	nlmsg = message->hdr;
	nlmsg->nlmsg_flags |= extra_flags;
	nlmsg->nlmsg_seq = netlink->next_seq++;
	nlmsg->nlmsg_pid = netlink->pid;

	l_queue_push_tail(netlink->command_queue, command);
	l_io_set_write_handler(netlink->io, can_write_data, netlink, NULL);

	return command->id;
}

LIB_EXPORT bool l_netlink_cancel(struct l_netlink *netlink, unsigned int id)
{
	struct command *command;
	struct nlmsghdr *hdr;

	if (unlikely(!netlink || !id))
		return false;

	command = l_hashmap_remove(netlink->command_lookup, L_UINT_TO_PTR(id));
	if (!command)
		return false;

	hdr = command->message->hdr;

	if (!l_queue_remove(netlink->command_queue, command)) {
		l_hashmap_remove(netlink->command_pending,
					L_UINT_TO_PTR(hdr->nlmsg_seq));
	}

	destroy_command(command);

	return true;
}

LIB_EXPORT bool l_netlink_request_sent(struct l_netlink *netlink,
							unsigned int id)
{
	struct command *command;
	struct nlmsghdr *hdr;

	if (unlikely(!netlink || !id))
		return false;

	command = l_hashmap_lookup(netlink->command_lookup, L_UINT_TO_PTR(id));
	if (!command)
		return false;

	hdr = command->message->hdr;
	return l_hashmap_lookup(netlink->command_pending,
					L_UINT_TO_PTR(hdr->nlmsg_seq));
}

static bool add_membership(struct l_netlink *netlink, uint32_t group)
{
	int sk, value = group;

	sk = l_io_get_fd(netlink->io);

	if (setsockopt(sk, SOL_NETLINK, NETLINK_ADD_MEMBERSHIP,
						&value, sizeof(value)) < 0)
		return false;

	return true;
}

static bool drop_membership(struct l_netlink *netlink, uint32_t group)
{
	int sk, value = group;

	sk = l_io_get_fd(netlink->io);

	if (setsockopt(sk, SOL_NETLINK, NETLINK_DROP_MEMBERSHIP,
						&value, sizeof(value)) < 0)
		return false;

	return true;
}

LIB_EXPORT unsigned int l_netlink_register(struct l_netlink *netlink,
			uint32_t group, l_netlink_notify_func_t function,
			void *user_data, l_netlink_destroy_func_t destroy)
{
	struct l_hashmap *notify_list;
	struct notify *notify;
	unsigned int id;

	if (unlikely(!netlink))
		return 0;

	if (!netlink->notify_groups || !netlink->notify_lookup)
		return 0;

	notify_list = l_hashmap_lookup(netlink->notify_groups,
						L_UINT_TO_PTR(group));
	if (!notify_list) {
		notify_list = l_hashmap_new();
		if (!notify_list)
			return 0;

		if (!l_hashmap_insert(netlink->notify_groups,
					L_UINT_TO_PTR(group), notify_list)) {
			l_hashmap_destroy(notify_list, NULL);
			return 0;
		}
	}

	notify = l_new(struct notify, 1);

	notify->group = group;
	notify->handler = function;
	notify->destroy = destroy;
	notify->user_data = user_data;

	id = netlink->next_notify_id;

	if (!l_hashmap_insert(netlink->notify_lookup,
					L_UINT_TO_PTR(id), notify_list))
		goto free_notify;

	if (!l_hashmap_insert(notify_list, L_UINT_TO_PTR(id), notify))
		goto remove_lookup;

	if (l_hashmap_size(notify_list) == 1) {
		if (!add_membership(netlink, notify->group))
			goto remove_notify;
	}

	netlink->next_notify_id++;

	return id;

remove_notify:
	l_hashmap_remove(notify_list, L_UINT_TO_PTR(id));

remove_lookup:
	l_hashmap_remove(netlink->notify_lookup, L_UINT_TO_PTR(id));

free_notify:
	l_free(notify);

	return 0;
}

LIB_EXPORT bool l_netlink_unregister(struct l_netlink *netlink, unsigned int id)
{
	struct l_hashmap *notify_list;
	struct notify *notify;

	if (unlikely(!netlink || !id))
		return false;

	if (!netlink->notify_groups || !netlink->notify_lookup)
		return false;

	notify_list = l_hashmap_remove(netlink->notify_lookup,
						L_UINT_TO_PTR(id));
	if (!notify_list)
		return false;

	notify = l_hashmap_remove(notify_list, L_UINT_TO_PTR(id));
	if (!notify)
		return false;

	if (l_hashmap_size(notify_list) == 0)
		drop_membership(netlink, notify->group);

	destroy_notify(notify);

	return true;
}

LIB_EXPORT bool l_netlink_set_debug(struct l_netlink *netlink,
			l_netlink_debug_func_t function,
			void *user_data, l_netlink_destroy_func_t destroy)
{
	int ext_ack;

	if (unlikely(!netlink))
		return false;

	if (netlink->debug_destroy)
		netlink->debug_destroy(netlink->debug_data);

	netlink->debug_handler = function;
	netlink->debug_destroy = destroy;
	netlink->debug_data = user_data;

	/* l_io_set_debug(netlink->io, function, user_data, NULL); */

	ext_ack = function != NULL;
	if (setsockopt(l_io_get_fd(netlink->io), SOL_NETLINK, NETLINK_EXT_ACK,
			&ext_ack, sizeof(ext_ack)) < 0 && function)
		function("Failed to set NETLINK_EXT_ACK", user_data);

	return true;
}

/*
 * Parses extended error info from the extended ack.  It is assumed that the
 * caller has already checked the type of @nlmsg and it is of type NLMSG_ERROR.
 */
bool netlink_parse_ext_ack_error(const struct nlmsghdr *nlmsg,
					const char **out_error_msg,
					uint32_t *out_error_offset)
{
	const struct nlmsgerr *err = NLMSG_DATA(nlmsg);
	unsigned int offset = 0;
	struct nlattr *nla;
	int len;

	if (!(nlmsg->nlmsg_flags & NLM_F_ACK_TLVS))
		return false;

	/*
	 * If the message is capped, then err->msg.nlmsg_len contains the
	 * length of the original message and thus can't be used to
	 * calculate the offset.
	 */
	if (!(nlmsg->nlmsg_flags & NLM_F_CAPPED))
		offset = err->msg.nlmsg_len - sizeof(struct nlmsghdr);

	/*
	 * Attributes start past struct nlmsgerr.  The offset is 0 for
	 * NLM_F_CAPPED messages.  Otherwise the original message is
	 * included, and thus the offset takes err->msg.nlmsg_len into
	 * account.
	 */
	nla = (void *)(err + 1) + offset;

	/* Calculate bytes taken up by header + nlmsgerr contents */
	offset += sizeof(struct nlmsghdr) + sizeof(struct nlmsgerr);
	if (nlmsg->nlmsg_len <= offset)
		return false;

	len = nlmsg->nlmsg_len - offset;

	for (; NLA_OK(nla, len); nla = NLA_NEXT(nla, len)) {
		switch (nla->nla_type & NLA_TYPE_MASK) {
		case NLMSGERR_ATTR_MSG:
			if (out_error_msg)
				*out_error_msg = NLA_DATA(nla);
			break;
		case NLMSGERR_ATTR_OFFS:
			if (out_error_offset)
				*out_error_offset = l_get_u32(NLA_DATA(nla));
			break;
		}
	}

	return true;
}

static int message_grow(struct l_netlink_message *message, uint32_t needed)
{
	uint32_t grow_to;

	if (message->sealed)
		return -EPERM;

	if (message->size - message->hdr->nlmsg_len >= needed)
		return 0;

	/*
	 * Kernel places a practical limit on the size of messages it will
	 * accept, at least without tweaking SNDBUF.  There's no (known) reason
	 * to send very large messages, so limit accordingly
	 */
	grow_to = message->hdr->nlmsg_len + needed;
	if (grow_to > (1U << 20))
		return -EMSGSIZE;

	if (grow_to < l_util_pagesize())
		grow_to = roundup_pow_of_two(grow_to);
	else
		grow_to = align_len(grow_to, l_util_pagesize());

	message->data = l_realloc(message->data, grow_to);
	message->size = grow_to;

	return 0;
}

static inline void *message_tail(struct l_netlink_message *message)
{
	return message->data + NLMSG_ALIGN(message->hdr->nlmsg_len);
}

static int add_attribute(struct l_netlink_message *message,
				uint16_t type, size_t len,
				void **out_dest)
{
	struct nlattr *attr = message_tail(message);
	int offset = message->hdr->nlmsg_len;
	int i;

	for (i = 0; i < message->nest_level; i++) {
		uint32_t nested_len = offset + NLA_HDRLEN + NLA_ALIGN(len) -
					message->nest_offset[i];

		if (nested_len > USHRT_MAX)
			return -ERANGE;
	}

	attr->nla_type = type;
	attr->nla_len = NLA_HDRLEN + len;

	if (len) {
		void *dest = message_tail(message) + NLA_HDRLEN;

		memset(dest + len, 0, NLA_ALIGN(len) - len);

		if (out_dest)
			*out_dest = dest;
	}

	message->hdr->nlmsg_len += NLA_HDRLEN + NLA_ALIGN(len);

	return offset;
}

LIB_EXPORT struct l_netlink_message *l_netlink_message_new_sized(uint16_t type,
					uint16_t flags, size_t initial_len)
{
	struct l_netlink_message *message;

	if (flags & 0xff)
		return NULL;

	message = l_new(struct l_netlink_message, 1);

	message->size = initial_len + NLMSG_HDRLEN;
	message->hdr = l_realloc(NULL, message->size);
	memset(message->hdr, 0, NLMSG_HDRLEN);

	message->hdr->nlmsg_len = NLMSG_HDRLEN;
	message->hdr->nlmsg_type = type;
	message->hdr->nlmsg_flags = flags;
	/* seq and pid will be filled on send */
	message->hdr->nlmsg_pid = 0;

	return l_netlink_message_ref(message);

}

LIB_EXPORT struct l_netlink_message *l_netlink_message_new(uint16_t type,
								uint16_t flags)
{
	return l_netlink_message_new_sized(type, flags, 256 - NLMSG_HDRLEN);
}

struct l_netlink_message *netlink_message_from_nlmsg(
						const struct nlmsghdr *nlmsg)
{
	struct l_netlink_message *message = l_new(struct l_netlink_message, 1);

	message->hdr = l_memdup(nlmsg, nlmsg->nlmsg_len);
	message->size = nlmsg->nlmsg_len;

	return l_netlink_message_ref(message);
}

LIB_EXPORT struct l_netlink_message *l_netlink_message_ref(
					struct l_netlink_message *message)
{
	if (unlikely(!message))
		return NULL;

	__atomic_fetch_add(&message->ref_count, 1, __ATOMIC_SEQ_CST);

	return message;
}

LIB_EXPORT void l_netlink_message_unref(struct l_netlink_message *message)
{
	if (unlikely(!message))
		return;

	if (__atomic_sub_fetch(&message->ref_count, 1, __ATOMIC_SEQ_CST))
		return;

	l_free(message->hdr);
	l_free(message);
}

LIB_EXPORT int l_netlink_message_append(struct l_netlink_message *message,
						uint16_t type,
						const void *data, size_t len)
{
	void *dest;
	int r;

	if (unlikely(!message))
		return -EINVAL;

	if (len > USHRT_MAX - NLA_HDRLEN)
		return -ERANGE;

	r = message_grow(message, NLA_HDRLEN + NLA_ALIGN(len));
	if (r < 0)
		return r;

	r = add_attribute(message, type, len, &dest);
	if (r < 0)
		return r;

	memcpy(dest, data, len);

	return 0;
}

LIB_EXPORT int l_netlink_message_appendv(struct l_netlink_message *message,
					uint16_t type,
					const struct iovec *iov, size_t iov_len)
{
	size_t len = 0;
	void *dest;
	size_t i;
	int r;

	if (unlikely(!message))
		return -EINVAL;

	for (i = 0; i < iov_len; i++)
		len += iov[i].iov_len;

	if (len > USHRT_MAX - NLA_HDRLEN)
		return -ERANGE;

	r = message_grow(message, NLA_HDRLEN + NLA_ALIGN(len));
	if (r < 0)
		return r;

	r = add_attribute(message, type, len, &dest);
	if (r < 0)
		return r;

	for (i = 0, len = 0; i < iov_len; i++, iov++) {
		memcpy(dest + len, iov->iov_base, iov->iov_len);
		len += iov->iov_len;
	}

	return 0;
}

int netlink_message_reserve_header(struct l_netlink_message *message,
					size_t len, void **out_header)
{
	int r;

	if (message->hdr->nlmsg_len != NLMSG_HDRLEN)
		return -EBADE;

	if (len > USHRT_MAX)
		return -ERANGE;

	r = message_grow(message, NLA_ALIGN(len));
	if (r < 0)
		return r;

	if (out_header)
		*out_header = message_tail(message);

	memset(message_tail(message) + len, 0, NLA_ALIGN(len) - len);
	message->hdr->nlmsg_len += NLA_ALIGN(len);
	return 0;
}

LIB_EXPORT int l_netlink_message_add_header(struct l_netlink_message *message,
						const void *header,
						size_t len)
{
	int r;
	void *dest;

	if (unlikely(!message || !len))
		return -EINVAL;

	r = netlink_message_reserve_header(message, len, &dest);
	if (r < 0)
		return r;

	memcpy(dest, header, len);
	return 0;
}

LIB_EXPORT int l_netlink_message_enter_nested(struct l_netlink_message *message,
						uint16_t type)
{
	int r;

	if (unlikely(!message))
		return -EINVAL;

	if (unlikely(message->nest_level == L_ARRAY_SIZE(message->nest_offset)))
		return -EOVERFLOW;

	r = message_grow(message, NLA_HDRLEN);
	if (r < 0)
		return r;

	r = add_attribute(message, type | NLA_F_NESTED, 0, NULL);
	if (r < 0)
		return false;

	message->nest_offset[message->nest_level] = r;
	message->nest_level += 1;

	return 0;
}

LIB_EXPORT int l_netlink_message_leave_nested(struct l_netlink_message *message)
{
	struct nlattr *nla;
	uint32_t offset;

	if (unlikely(!message))
		return -EINVAL;

	if (unlikely(message->nest_level == 0))
		return -EOVERFLOW;

	message->nest_level -= 1;
	offset = message->nest_offset[message->nest_level];

	nla = message->data + offset;
	nla->nla_len = message->hdr->nlmsg_len - offset;

	return 0;
}

LIB_EXPORT int l_netlink_attr_init(struct l_netlink_attr *iter,
					size_t header_len,
					const void *data, uint32_t len)
{
	const struct nlattr *nla;

	if (unlikely(!iter) || unlikely(!data))
		return -EINVAL;

	if (len < NLA_ALIGN(header_len))
		return -EMSGSIZE;

	nla = data + NLA_ALIGN(header_len);
	len -= NLA_ALIGN(header_len);

	if (!NLA_OK(nla, len))
		return -EMSGSIZE;

	iter->data = NULL;
	iter->len = 0;
	iter->next_data = nla;
	iter->next_len = len;

	return 0;
}

LIB_EXPORT int l_netlink_attr_next(struct l_netlink_attr *iter,
					uint16_t *type, uint16_t *len,
					const void **data)
{
	const struct nlattr *nla;

	if (unlikely(!iter))
		return -EINVAL;

	nla = iter->next_data;
	if (!NLA_OK(nla, iter->next_len))
		return -EMSGSIZE;

	if (type)
		*type = nla->nla_type & NLA_TYPE_MASK;

	if (len)
		*len = NLA_PAYLOAD(nla);

	if (data)
		*data = NLA_DATA(nla);

	iter->data = iter->next_data;
	iter->len = iter->next_len;

	iter->next_data = NLA_NEXT(nla, iter->next_len);
	return 0;
}

LIB_EXPORT int l_netlink_attr_recurse(const struct l_netlink_attr *iter,
					struct l_netlink_attr *nested)
{
	const struct nlattr *nla;

	if (unlikely(!iter) || unlikely(!nested))
		return -EINVAL;

	nla = iter->data;
	if (!nla)
		return false;

	nested->data = NULL;
	nested->len = 0;
	nested->next_data = NLA_DATA(nla);
	nested->next_len = NLA_PAYLOAD(nla);

	return 0;
}
