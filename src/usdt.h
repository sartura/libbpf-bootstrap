/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __USDT_H
#define __USDT_H

#define TASK_COMM_LEN 16

struct event {
	char task[TASK_COMM_LEN];
	__u64 delta_us;
	pid_t pid;
};

enum usdt_arg_type {
	USDT_ARG_CONST,
	USDT_ARG_REG,
	USDT_ARG_STACK,
};

struct usdt_arg_spec {
	bool arg_signed;
	char arg_bitshift;
	short arg_sz;
	short reg_off;
	enum usdt_arg_type arg_type;
	long val_off;
};

struct usdt_spec {
	short arg_cnt;
	struct usdt_arg_spec args[12];
};

#endif /* __USDT_H */
