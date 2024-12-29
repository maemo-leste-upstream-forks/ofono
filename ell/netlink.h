/*
 * Embedded Linux library
 * Copyright (C) 2011-2014  Intel Corporation
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#ifndef __ELL_NETLINK_H
#define __ELL_NETLINK_H

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef void (*l_netlink_debug_func_t) (const char *str, void *user_data);

typedef void (*l_netlink_command_func_t) (int error,
						uint16_t type, const void *data,
						uint32_t len, void *user_data);
typedef void (*l_netlink_notify_func_t) (uint16_t type, const void *data,
						uint32_t len, void *user_data);
typedef void (*l_netlink_destroy_func_t) (void *user_data);

struct l_netlink;
struct l_netlink_message;

struct l_netlink *l_netlink_new(int protocol);
void l_netlink_destroy(struct l_netlink *netlink);

unsigned int l_netlink_send(struct l_netlink *netlink,
				struct l_netlink_message *message,
				l_netlink_command_func_t function,
				void *user_data,
				l_netlink_destroy_func_t destroy);
bool l_netlink_cancel(struct l_netlink *netlink, unsigned int id);
bool l_netlink_request_sent(struct l_netlink *netlink, unsigned int id);

unsigned int l_netlink_register(struct l_netlink *netlink,
			uint32_t group, l_netlink_notify_func_t function,
			void *user_data, l_netlink_destroy_func_t destroy);
bool l_netlink_unregister(struct l_netlink *netlink, unsigned int id);

bool l_netlink_set_debug(struct l_netlink *netlink,
			l_netlink_debug_func_t function,
			void *user_data, l_netlink_destroy_func_t destroy);

struct l_netlink_message *l_netlink_message_new(uint16_t type, uint16_t flags);
struct l_netlink_message *l_netlink_message_new_sized(uint16_t type,
							uint16_t flags,
							size_t initial_size);
struct l_netlink_message *l_netlink_message_ref(
					struct l_netlink_message *message);
void l_netlink_message_unref(struct l_netlink_message *message);
int l_netlink_message_append(struct l_netlink_message *message, uint16_t type,
					const void *data, size_t len);
int l_netlink_message_appendv(struct l_netlink_message *message,
					uint16_t type,
					const struct iovec *iov, size_t iov_len);
int l_netlink_message_add_header(struct l_netlink_message *message,
					const void *header, size_t len);
int l_netlink_message_enter_nested(struct l_netlink_message *message,
					uint16_t type);
int l_netlink_message_leave_nested(struct l_netlink_message *message);

static inline int l_netlink_message_append_u8(struct l_netlink_message *message,
						uint16_t type, uint8_t u8)
{
	return l_netlink_message_append(message, type, &u8, sizeof(uint8_t));
}

static inline int l_netlink_message_append_u16(struct l_netlink_message *message,
						uint16_t type, uint16_t u16)
{
	return l_netlink_message_append(message, type, &u16, sizeof(uint16_t));
}

static inline int l_netlink_message_append_u32(struct l_netlink_message *message,
						uint16_t type, uint32_t u32)
{
	return l_netlink_message_append(message, type, &u32, sizeof(uint32_t));
}

static inline int l_netlink_message_append_u64(struct l_netlink_message *message,
						uint16_t type, uint64_t u64)
{
	return l_netlink_message_append(message, type, &u64, sizeof(uint64_t));
}

static inline int l_netlink_message_append_s8(struct l_netlink_message *message,
						uint16_t type, int8_t s8)
{
	return l_netlink_message_append(message, type, &s8, sizeof(int8_t));
}

static inline int l_netlink_message_append_s16(struct l_netlink_message *message,
						uint16_t type, int16_t s16)
{
	return l_netlink_message_append(message, type, &s16, sizeof(int16_t));
}

static inline int l_netlink_message_append_s32(struct l_netlink_message *message,
						uint16_t type, int32_t s32)
{
	return l_netlink_message_append(message, type, &s32, sizeof(int32_t));
}

static inline int l_netlink_message_append_s64(struct l_netlink_message *message,
						uint16_t type, int64_t s64)
{
	return l_netlink_message_append(message, type, &s64, sizeof(int64_t));
}

static inline int l_netlink_message_append_mac(struct l_netlink_message *message,
						uint16_t type,
						const uint8_t mac[static 6])
{
	return l_netlink_message_append(message, type, mac, 6);
}

static inline int l_netlink_message_append_string(
					struct l_netlink_message *message,
					uint16_t type,
					const char *str)
{
	return l_netlink_message_append(message, type, str, strlen(str) + 1);
}

struct l_netlink_attr {
	const struct nlattr *data;
	uint32_t len;
	const struct nlattr *next_data;
	uint32_t next_len;
};

int l_netlink_attr_init(struct l_netlink_attr *attr, size_t header_len,
					const void *data, uint32_t len);
int l_netlink_attr_next(struct l_netlink_attr *attr,
					uint16_t *type, uint16_t *len,
					const void **data);
int l_netlink_attr_recurse(const struct l_netlink_attr *iter,
					struct l_netlink_attr *nested);

#ifdef __cplusplus
}
#endif

#endif /* __ELL_NETLINK_H */
