/*
 * Embedded Linux library
 * Copyright (C) 2011-2014  Intel Corporation
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#include <stdbool.h>
#include <sys/types.h>

typedef void (*start_dbus_cb_t) (void *user_data);

pid_t start_dbus(const char *address, start_dbus_cb_t cb, void *user_data,
							bool enable_debug);
