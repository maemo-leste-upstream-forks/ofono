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
#include <string.h>
#include <getopt.h>
#include <assert.h>
#include <poll.h>
#include <signal.h>
#include <sys/signalfd.h>
#include <sys/wait.h>
#include <sys/prctl.h>

#include "log.h"
#include "main.h"
#include "idle.h"
#include "signal.h"
#include "test-private.h"
#include "test.h"
#include "private.h"
#include "useful.h"

#ifndef WAIT_ANY
#define WAIT_ANY (-1) /* Any process */
#endif

#if __BYTE_ORDER == __LITTLE_ENDIAN
static bool little_endian_system = true;
#elif __BYTE_ORDER == __BIG_ENDIAN
static bool little_endian_system = false;
#else
#error "Unknown byte order"
#endif

/**
 * SECTION:test
 * @short_description: Unit test framework
 *
 * Unit test framework
 */

struct test {
	const char *name;
	const void *data;
	l_test_func_t function;
	l_test_precheck_t precheck;
	unsigned long flags;
	unsigned int num;
	struct test *next;
	/* internal execution variables */
	bool use_main;
	const char *dbus_address;
	pid_t dbus_pid;
	struct l_signal *sigchld;
};

static struct test *test_head;
static struct test *test_tail;
static unsigned int test_count;
static bool testing_active;
static int signal_fd;

static bool run_all;
static bool cmd_list;
static bool tap_enable;
static bool debug_enable;

static pid_t test_pid = -1;

static unsigned long default_flags = 0;

/**
 * l_test_init:
 * @argc: pointer to @argc parameter of main() function
 * @argv: pointer to @argv parameter of main() function
 *
 * Initialize testing framework.
 **/
LIB_EXPORT void l_test_init(int *argc, char ***argv)
{
	static const struct option options[] = {
		{ "all",	no_argument,	NULL, 'a' },
		{ "list",	no_argument,	NULL, 'l' },
		{ "text",	no_argument,	NULL, 't' },
		{ "debug",	no_argument,	NULL, 'd' },
		{ }
	};

	test_head = NULL;
	test_tail = NULL;
	test_count = 0;

	l_log_set_stderr();

	run_all = false;
	cmd_list = false;
	tap_enable = true;
	debug_enable = false;

	for (;;) {
		int opt;

		opt = getopt_long(*argc, *argv, "altd", options, NULL);
		if (opt < 0)
			break;

		switch (opt) {
		case 'a':
			run_all = true;
			break;
		case 'l':
			cmd_list = true;
			break;
		case 't':
			tap_enable = false;
			break;
		case 'd':
			debug_enable = true;
			break;
		}
	}

	if (debug_enable)
		l_debug_enable("*");
}

static void show_tests(void)
{
	struct test *test = test_head;

	while (test) {
		struct test *tmp = test;

		printf("TEST: %s\n", test->name);

		test = test->next;
		test_head = test;

		free(tmp);
	}

	test_head = NULL;
	test_tail = NULL;
	test_count = 0;
}

static void print_result(struct test *test, bool success)
{
	bool failure_expected = test->flags & L_TEST_FLAG_FAILURE_EXPECTED;
	bool allow_failure = test->flags & L_TEST_FLAG_ALLOW_FAILURE;
	bool little_endian = test->flags & L_TEST_FLAG_LITTLE_ENDIAN_ONLY;
	bool expensive_comp = test->flags & L_TEST_FLAG_EXPENSIVE_COMPUTATION;
	bool mark_skip = false;
	const char *comment = NULL;

	if (failure_expected && !success)
		success = true;

	if (allow_failure && !success) {
		success = true;
		mark_skip = true;
		comment = " allow-failure";
	}

	if (!little_endian_system && little_endian) {
		if (!success) {
			success = true;
			mark_skip = true;
		}
		comment = " little-endian-only";
	}

	if (expensive_comp && !success) {
		success = true;
		mark_skip = true;
		comment = " expensive-computation";
	}

	printf("%sok %u - %s%s%s%s\n",
			success ? "" : "not ", test->num, test->name,
			(mark_skip || comment) ? " #" : "",
			mark_skip ? " SKIP" : "", comment ? comment : "");
}

static void test_setup(struct test *test)
{
	int err;

	test->use_main = false;
	test->dbus_address = NULL;
	test->dbus_pid = -1;

	if (test->flags & L_TEST_FLAG_REQUIRE_DBUS_SYSTEM_BUS) {
		test->use_main = true;
		test->dbus_address = "unix:path=/tmp/ell-test-system-bus";

		err = setenv("DBUS_SYSTEM_BUS_ADDRESS", test->dbus_address, 1);
		assert(err == 0);
	}

	if (test->flags & L_TEST_FLAG_REQUIRE_DBUS_SESSION_BUS) {
		test->use_main = true;
		test->dbus_address = "unix:path=/tmp/ell-test-session-bus";

		err = setenv("DBUS_SESSION_BUS_ADDRESS", test->dbus_address, 1);
		assert(err == 0);
	}

	if (test->use_main) {
		bool result = l_main_init();
		assert(result);
	}
}

static void test_sigchld(void *user_data)
{
	struct test *test = user_data;

	while (1) {
		pid_t pid;
		int wstatus;
		bool terminated = false;
		bool success;

		pid = waitpid(WAIT_ANY, &wstatus, WNOHANG);
		if (pid < 0 || pid == 0)
			break;

		if (WIFEXITED(wstatus)) {
			terminated = true;
			success = !WEXITSTATUS(wstatus);
		} else if (WIFSIGNALED(wstatus)) {
			terminated = true;
			success = false;
		}

		if (terminated && pid == test->dbus_pid) {
			l_info("D-Bus %s", success ? "terminated" : "failed");
			assert(success);
			l_main_quit();
		}
	}
}

static void dbus_ready(void *user_data)
{
	struct test *test = user_data;

	if (!run_all && (test->flags & L_TEST_FLAG_EXPENSIVE_COMPUTATION)) {
		/*
		 * Abort test cases with long running computation task
		 * to fail and with that be gracefully skipped
		 */
		abort();
		return;
	}

	test->function(test->data);
}

static void main_ready(void *user_data)
{
	struct test *test = user_data;

	if (test->dbus_address) {
		test->sigchld = l_signal_create(SIGCHLD,
						test_sigchld, test, NULL);

		test->dbus_pid = start_dbus(test->dbus_address,
						dbus_ready, test, debug_enable);
		assert(test->dbus_pid > 0);
	} else {
		dbus_ready(test);
	}
}

static void test_function(struct test *test)
{
	if (test->use_main) {
		int exit_status;

		l_idle_oneshot(main_ready, test, NULL);

		exit_status = l_main_run();
		assert(exit_status == EXIT_SUCCESS);
	} else {
		dbus_ready(test);
	}
}

static void test_teardown(struct test *test)
{
	if (test->use_main) {
		bool result = l_main_exit();
		assert(result);

		if (test->dbus_pid > 0)
			kill(test->dbus_pid, SIGKILL);

		l_signal_remove(test->sigchld);
	}
}

static void run_next_test(void *user_data)
{
	struct test *test = test_head;
	pid_t pid;

	if (!test) {
		testing_active = false;
		return;
	}

	if (!tap_enable)
		printf("TEST: %s\n", test->name);

	if (test->precheck) {
		bool result = test->precheck(test->data);

		if (test->flags & L_TEST_FLAG_INVERT_PRECHECK_RESULT)
			result = !result;

		if (!result) {
			if (tap_enable)
				printf("ok %u - %s # SKIP not-supported\n",
							test->num, test->name);

			test_head = test->next;
			free(test);

			if (!test_head)
				test_tail = NULL;

			/* Trigger the main pollfd loop */
			kill(getpid(), SIGUSR1);
			return;
		}
	}

	pid = fork();
	if (pid < 0) {
		perror("Failed to fork new process");
		testing_active = false;
		return;
	}

	if (pid == 0) {
		prctl(PR_SET_PDEATHSIG, SIGTERM);
		prctl(PR_SET_DUMPABLE, 0L);

		/* Don't keep the signalfd in the child process */
		close(signal_fd);

		/* Close stdout to not interfere with TAP */
		close(STDOUT_FILENO);

		test_setup(test);
		test_function(test);
		test_teardown(test);

		exit(EXIT_SUCCESS);
	}

	if (tap_enable && debug_enable)
		printf("# %d started\n", pid);

	test_pid = pid;
}

static void signal_handler(uint32_t signo, void *user_data)
{
	switch (signo) {
	case SIGINT:
	case SIGTERM:
		l_info("Terminate");
		if (test_pid > 0) {
			l_info("Terminate test %d", test_pid);
			kill(test_pid, SIGKILL);
		}
		break;
	}
}

static void sigchld_handler(void *user_data)
{
	while (1) {
		pid_t pid;
		int wstatus;
		bool terminated = false;
		bool success;

		pid = waitpid(WAIT_ANY, &wstatus, WNOHANG);
		if (pid < 0 || pid == 0)
			break;

		if (WIFEXITED(wstatus)) {
			if (tap_enable && debug_enable)
				printf("# %d exited with status %d\n",
						pid, WEXITSTATUS(wstatus));
			terminated = true;
			success = !WEXITSTATUS(wstatus);
		} else if (WIFSIGNALED(wstatus)) {
			if (tap_enable && debug_enable)
				printf("# %d terminated with signal %d\n",
						pid, WTERMSIG(wstatus));
			terminated = true;
			success = false;
		}

		if (terminated && pid == test_pid) {
			struct test *test = test_head;

			test_pid = -1;

			if (tap_enable)
				print_result(test, success);

			test_head = test->next;
			free(test);

			if (!test_head)
				test_tail = NULL;

			run_next_test(NULL);
		}
	}
}

/**
 * l_test_run:
 *
 * Run all configured tests.
 *
 * Returns: 0 on success
 **/
LIB_EXPORT int l_test_run(void)
{
	sigset_t sig_mask, old_mask;
	int exit_status;

	if (cmd_list) {
		show_tests();
		return EXIT_SUCCESS;
	}

	if (tap_enable) {
		printf("TAP version 12\n");
		printf("1..%u\n", test_count);
	}

	sigemptyset(&sig_mask);
	sigaddset(&sig_mask, SIGINT);
	sigaddset(&sig_mask, SIGTERM);
	sigaddset(&sig_mask, SIGCHLD);
	sigaddset(&sig_mask, SIGUSR1);

	/*
	 * Block signals so that they aren't handled according to their
	 * default dispositions.
	 */
	if (sigprocmask(SIG_BLOCK, &sig_mask, &old_mask) < 0)
		return EXIT_FAILURE;

	signal_fd = signalfd(-1, &sig_mask, SFD_CLOEXEC);
	if (signal_fd < 0) {
		sigprocmask(SIG_SETMASK, &old_mask, NULL);
		return EXIT_FAILURE;
	}

	exit_status = EXIT_SUCCESS;
	testing_active = true;

	run_next_test(NULL);

	while (testing_active) {
		struct pollfd fds[1];
		struct signalfd_siginfo ssi;
		ssize_t result;
		int res;

		fds[0].fd = signal_fd;
		fds[0].events = POLLIN;
		fds[0].revents = 0;

		res = poll(fds, 1, -1);
		if (res < 0) {
			exit_status = EXIT_FAILURE;
			break;
		}

		if (res == 0)
			continue;

		result = read(signal_fd, &ssi, sizeof(ssi));
		if (result != sizeof(ssi))
			continue;

		switch (ssi.ssi_signo) {
		case SIGINT:
		case SIGTERM:
			signal_handler(ssi.ssi_signo, NULL);
			break;
		case SIGCHLD:
			sigchld_handler(NULL);
			break;
		case SIGUSR1:
			run_next_test(NULL);
			break;
		}
	}

	close(signal_fd);

	sigprocmask(SIG_SETMASK, &old_mask, NULL);

	return exit_status;
}

static void common_add(const char *name, const void *data,
						l_test_func_t function,
						l_test_precheck_t precheck,
						unsigned long flags)
{
	struct test *test;

	if (unlikely(!name || !function))
		return;

	test = malloc(sizeof(struct test));
	if (!test)
		return;

	memset(test, 0, sizeof(struct test));
	test->name = name;
	test->data = data;
	test->function = function;
	test->precheck = precheck;
	test->flags = flags;
	test->num = ++test_count;
	test->next = NULL;

	if (test_tail)
		test_tail->next = test;

	test_tail = test;

	if (!test_head)
		test_head = test;
}

/**
 * l_test_add_func_precheck:
 * @name: test name
 * @data: test data
 * @function: test function
 * @precheck: precheck function
 * @flags: test flags;
 *
 * Add new test.
 **/
LIB_EXPORT void l_test_add_func_precheck(const char *name,
						l_test_func_t function,
						l_test_precheck_t precheck,
						unsigned long flags)
{
	common_add(name, NULL, function, precheck, flags);
}

/**
 * l_test_add_data_func_precheck:
 * @name: test name
 * @data: test data
 * @function: test function
 * @precheck: precheck function
 * @flags: test flags;
 *
 * Add new test.
 **/
LIB_EXPORT void l_test_add_data_func_precheck(const char *name,
						const void *data,
						l_test_func_t function,
						l_test_precheck_t precheck,
						unsigned long flags)
{
	common_add(name, data, function, precheck, flags);
}

/**
 * l_test_add_data_func:
 * @name: test name
 * @function: test function
 * @flags: test flags;
 *
 * Add new test.
 **/
LIB_EXPORT void l_test_add_func(const char *name, l_test_func_t function,
							unsigned long flags)
{
	common_add(name, NULL, function, NULL, flags);
}

/**
 * l_test_add_data_func:
 * @name: test name
 * @data: test data
 * @function: test function
 * @flags: test flags;
 *
 * Add new test.
 **/
LIB_EXPORT void l_test_add_data_func(const char *name, const void *data,
							l_test_func_t function,
							unsigned long flags)
{
	common_add(name, data, function, NULL, flags);
}

/**
 * l_test_add:
 * @name: test name
 * @function: test function
 * @data: test data
 *
 * Add new test.
 **/
LIB_EXPORT void l_test_add(const char *name, l_test_func_t function,
							const void *data)
{
	common_add(name, data, function, NULL, default_flags);
}

/**
 * l_test_set_default_flags:
 * @flags: test flags;
 *
 * Set default for test flags.
 **/
LIB_EXPORT void l_test_set_default_flags(unsigned long flags)
{
	default_flags = flags;
}
