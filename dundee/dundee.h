/*
 *
 *  oFono - Open Source Telephony
 *
 *  Copyright (C) 2008-2012  Intel Corporation. All rights reserved.
 *  Copyright (C) 2012  BMW Car IT GmbH. All rights reserved.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#include <glib.h>

#define OFONO_API_SUBJECT_TO_CHANGE

#include <ofono/types.h>

void __dundee_exit(void);

#include <ofono/log.h>

int __ofono_log_init(const char *program, const char *debug,
					ofono_bool_t detach);
void __ofono_log_cleanup(void);
void __ofono_log_enable(struct ofono_debug_desc *start,
					struct ofono_debug_desc *stop);

#include <ofono/dbus.h>

#define DUNDEE_SERVICE			"org.ofono.dundee"

int __ofono_dbus_init(DBusConnection *conn);
void __ofono_dbus_cleanup(void);

void __ofono_dbus_pending_reply(DBusMessage **msg, DBusMessage *reply);

DBusMessage *__dundee_error_invalid_args(DBusMessage *msg);
DBusMessage *__dundee_error_failed(DBusMessage *msg);