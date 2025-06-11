/*
 * Embedded Linux library
 * Copyright (C) 2011-2014  Intel Corporation
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "log.h"
#include "util.h"
#include "idle.h"
#include "test-private.h"
#include "dbus.h"

static void do_debug(const char *str, void *user_data)
{
	const char *prefix = user_data;

	l_info("%s%s", prefix, str);
}

static int create_unix_socket(const char *path)
{
	struct sockaddr_un addr;
	int fd;

	unlink(path);

	fd = socket(PF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
	if (fd < 0) {
		perror("Failed to create bus socket");
		return -1;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);

	if (bind(fd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		perror("Failed to bind to bus socket");
		close(fd);
		return -1;
	}

	if (listen(fd, 5) < 0) {
		perror("Failed to listen on bus socket");
		close(fd);
		return -1;
	}

	return fd;
}

static pid_t fork_broker(int ctl_fd, int log_fd)
{
	char *dbus_broker_exec;
	pid_t pid;

	pid = fork();
	if (pid < 0) {
		perror("Failed to fork new process");
		return -1;
	}

	dbus_broker_exec = getenv("DBUS_BROKER") ?: "/usr/bin/dbus-broker";

	if (pid == 0) {
		char **argv, **envp;
		char ctl_str[12], log_str[12];
		int pos, val;

		prctl(PR_SET_PDEATHSIG, SIGTERM);
		prctl(PR_SET_DUMPABLE, 0L);

		val = fcntl(ctl_fd, F_GETFD);
		fcntl(ctl_fd, F_SETFD, val & ~FD_CLOEXEC);

		val = fcntl(log_fd, F_GETFD);
		fcntl(log_fd, F_SETFD, val & ~FD_CLOEXEC);

		snprintf(ctl_str, sizeof(ctl_str), "%d", ctl_fd);
		snprintf(log_str, sizeof(log_str), "%d", log_fd);

		argv = alloca(sizeof(char *) * 12);
		pos = 0;
		argv[pos++] = dbus_broker_exec;
		argv[pos++] = "--controller";
		argv[pos++] = ctl_str;
		if (log_fd >= 0) {
			argv[pos++] = "--log";
			argv[pos++] = log_str;
		}
		argv[pos++] = "--machine-id";
		argv[pos++] = "0123456789abcdef0123456789abcdef";
		argv[pos++] = NULL;

		envp = alloca(sizeof(char *) * 4);
		pos = 0;
		envp[pos++] = NULL;

		printf("Running command %s\n", argv[0]);

		execve(argv[0], argv, envp);
		exit(EXIT_FAILURE);
	}

	close(ctl_fd);
	close(log_fd);

	return pid;
}

struct cb_data {
	start_dbus_cb_t cb;
	void *ud;
};

static void add_listener_reply(struct l_dbus_message *reply, void *user_data)
{
	struct cb_data *cbd = user_data;

	if (l_dbus_message_is_error(reply)) {
		l_info("Failed to add listener");
		return;
	}

	l_info("Bus socket added successfully");

	if (cbd->cb)
		cbd->cb(cbd->ud);
}

static void builder_append(struct l_dbus_message_builder *builder,
						const char *signature, ...)
{
	va_list args;

	va_start(args, signature);
	l_dbus_message_builder_append_from_valist(builder, signature, args);
	va_end(args);
}

#define POLICY_T_BATCH	"bt" "a(btbs)" "a(btssssuutt)" "a(btssssuutt)"

#define POLICY_T	"a(u(" POLICY_T_BATCH "))"	\
			"a(buu(" POLICY_T_BATCH "))"	\
			"a(ss)" "bs"

static void add_listener(struct l_dbus *dbus, int fd, const char *type,
							struct cb_data *cbd)
{
	struct l_dbus_message *msg;
	struct l_dbus_message_builder *bld;

	msg = l_dbus_message_new_method_call(dbus, NULL,
					"/org/bus1/DBus/Broker",
					"org.bus1.DBus.Broker", "AddListener");

	bld = l_dbus_message_builder_new(msg);
	builder_append(bld, "oh", "/org/bus1/DBus/Listener/0", fd);
	l_dbus_message_builder_enter_variant(bld, "(" POLICY_T ")");
	l_dbus_message_builder_enter_struct(bld, POLICY_T);

	/* per-uid batches */
	l_dbus_message_builder_enter_array(bld, "(u(" POLICY_T_BATCH "))");
	l_dbus_message_builder_enter_struct(bld, "u(" POLICY_T_BATCH ")");
	/* Fall-back UID */
	builder_append(bld, "u", (uint32_t) -1);
	l_dbus_message_builder_enter_struct(bld, POLICY_T_BATCH);
	/* Default test policy:
	 *  - allow all connections
	 *  - allow everyone to own names
	 *  - allow all sends
	 *  - allow all recvs */
	builder_append(bld, POLICY_T_BATCH,
			true, UINT64_C(1),
			1, true, UINT64_C(1), true, "",
			1, true, UINT64_C(1), "", "", "", "", 0, 0,
						UINT64_C(0), UINT64_MAX,
			1, true, UINT64_C(1), "", "", "", "", 0, 0,
						UINT64_C(0), UINT64_MAX);
	l_dbus_message_builder_leave_struct(bld);
	l_dbus_message_builder_leave_struct(bld);
	l_dbus_message_builder_leave_array(bld);

	/* per-gid and uid-range batches */
	l_dbus_message_builder_enter_array(bld, "(buu(" POLICY_T_BATCH "))");
	l_dbus_message_builder_leave_array(bld);

	/* empty SELinux policy */
	l_dbus_message_builder_enter_array(bld, "(ss)");
	l_dbus_message_builder_leave_array(bld);

	/* disable AppArmor */
	builder_append(bld, "b", false);

	/* mark as system or session bus */
	builder_append(bld, "s", type);

	l_dbus_message_builder_leave_struct(bld);
	l_dbus_message_builder_leave_variant(bld);
	msg = l_dbus_message_builder_finalize(bld);
	l_dbus_message_builder_destroy(bld);

	l_dbus_send_with_reply(dbus, msg, add_listener_reply, cbd, l_free);
}

pid_t start_dbus(const char *address, start_dbus_cb_t cb, void *user_data,
							bool enable_debug)
{
	struct cb_data *cbd;
	struct l_dbus *ctl_dbus;
	int err, bus_fd, ctl_fds[2];
	pid_t pid;

	if (!address)
		return -1;

	err = socketpair(PF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC,
								0, ctl_fds);
	if (err < 0) {
		perror("Failed to create controller socket pair");
		return -1;
	}

	ctl_dbus = l_dbus_new_private(ctl_fds[0]);
	if (!ctl_dbus) {
		close(ctl_fds[0]);
		return -1;
	}

	if (enable_debug)
		l_dbus_set_debug(ctl_dbus, do_debug, "[dbus-broker] ", NULL);

	pid = fork_broker(ctl_fds[1], -1);
	if (pid < 0) {
		close(ctl_fds[0]);
		l_dbus_destroy(ctl_dbus);
		return -1;
	}

	if (strlen(address) < 11 || strncmp(address, "unix:path=", 10)) {
		kill(pid, SIGKILL);
		close(ctl_fds[0]);
		l_dbus_destroy(ctl_dbus);
		return -1;
	}

	bus_fd = create_unix_socket(address + 10);
	if (bus_fd < 0) {
		kill(pid, SIGKILL);
		close(ctl_fds[0]);
		l_dbus_destroy(ctl_dbus);
		ctl_dbus = NULL;
		return -1;
	}

	if (enable_debug)
		l_info("Policy signature: %s", "(" POLICY_T ")");

	cbd = l_new(struct cb_data, 1);
	cbd->cb = cb;
	cbd->ud = user_data;

	add_listener(ctl_dbus, bus_fd, "test", cbd);

	close(bus_fd);

	return pid;
}
