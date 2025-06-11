/*
 * Embedded Linux library
 * Copyright (C) 2011-2014  Intel Corporation
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#ifndef __ELL_TEST_H
#define __ELL_TEST_H

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

void l_test_init(int *argc, char ***argv);
int l_test_run(void);

typedef void (*l_test_func_t) (const void *data);
typedef bool (*l_test_precheck_t) (const void *data);

#define L_TEST_FLAG_FAILURE_EXPECTED		(1 << 1)
#define L_TEST_FLAG_ALLOW_FAILURE		(1 << 2)
#define L_TEST_FLAG_LITTLE_ENDIAN_ONLY		(1 << 3)
#define L_TEST_FLAG_EXPENSIVE_COMPUTATION	(1 << 4)
#define L_TEST_FLAG_INVERT_PRECHECK_RESULT	(1 << 5)
#define L_TEST_FLAG_REQUIRE_DBUS_SYSTEM_BUS	(1 << 8)
#define L_TEST_FLAG_REQUIRE_DBUS_SESSION_BUS	(1 << 9)

void l_test_add_func_precheck(const char *name, l_test_func_t function,
						l_test_precheck_t precheck,
						unsigned long flags);
void l_test_add_data_func_precheck(const char *name, const void *data,
						l_test_func_t function,
						l_test_precheck_t precheck,
						unsigned long flags);

void l_test_add_func(const char *name, l_test_func_t function,
						unsigned long flags);
void l_test_add_data_func(const char *name, const void *data,
				l_test_func_t function, unsigned long flags);

void l_test_add(const char *name, l_test_func_t function, const void *data);

void l_test_set_default_flags(unsigned long flags);

#ifdef __cplusplus
}
#endif

#endif /* __ELL_TEST_H */
