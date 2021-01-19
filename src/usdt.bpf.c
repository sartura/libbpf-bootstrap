// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2019 Facebook
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "usdt.h"

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, long);
	__type(value, struct usdt_spec);
} usdt_specs SEC(".maps");

static __always_inline unsigned long usdt_arg_downsize(unsigned long arg, int sz)
{
	switch (sz) {
		case 4: return (unsigned)arg;
		case -4: return (long)(int)arg;
		case 2: return (unsigned short)arg;
		case -2: return (long)(short)arg;
		case 1: return (unsigned char)arg;
		case -1: return (long)(signed char)arg;
	}
	return arg;
}

static __always_inline int usdt_arg(struct pt_regs *regs, int arg, long *res)
{
	long ip = PT_REGS_IP(regs);
	struct usdt_spec *spec;
	struct usdt_arg_spec *arg_spec;
	unsigned long val;

	*res = 0;

	spec = bpf_map_lookup_elem(&usdt_specs, &ip);
	if (!spec || arg >= spec->arg_cnt)
		return -1;

	arg_spec = &spec->args[arg];
	switch (arg_spec->arg_type) {
	case USDT_ARG_CONST:
		val = arg_spec->val_off;
		break;
	case USDT_ARG_REG:
	case USDT_ARG_STACK:
		if (bpf_probe_read_kernel(&val, sizeof(val), (void *)regs + arg_spec->reg_off))
			return -1;
		if (arg_spec->arg_type == USDT_ARG_STACK)
			if (bpf_probe_read_user(&val, sizeof(val), (void *)val + arg_spec->val_off))
				return -1;
		break;
	default:
		return -1;
	}

	val <<= arg_spec->arg_bitshift;
	if (arg_spec->arg_signed)
		val = ((long)val) >> arg_spec->arg_bitshift;
	else
		val = val >> arg_spec->arg_bitshift;
	*res = val;
	return 0;
}

SEC("uprobe/usdt")
int handle_usdt_exp(struct pt_regs *ctx)
{
	long ip = PT_REGS_IP(ctx);
	long fp = PT_REGS_FP(ctx);
	long val;
	int ret;
	int p1, p2;
	long p3;
	void *argv1, *argv2, *argv3;

	bpf_printk("USDT FIRED! IP=0x%lx FP=%lx\n", ip, fp);
	bpf_printk("ARG1 %lx ARG2 %lx ARG3 %lx\n", PT_REGS_PARM1(ctx), PT_REGS_PARM2(ctx), PT_REGS_PARM3(ctx));
	bpf_probe_read(&p1, sizeof(p1), (void *)(PT_REGS_FP(ctx)-4));
	bpf_probe_read(&p2, sizeof(p2), (void *)(PT_REGS_FP(ctx)-20));
	bpf_probe_read(&p3, sizeof(p3), (void *)(PT_REGS_FP(ctx)-32));
	bpf_probe_read(&argv1, sizeof(argv1), (void *)p3);
	bpf_probe_read(&argv2, sizeof(argv2), (void *)p3 + 8);
	bpf_probe_read(&argv3, sizeof(argv3), (void *)p3 + 16);
	bpf_printk("p1 %d p2 %d p3 %lx\n", p1, p2, p3);
	bpf_printk("argv1 %s\n", argv1);
	bpf_printk("argv2 %s\n", argv2);
	bpf_printk("argv3 %s\n", argv3);

	ret = usdt_arg(ctx, 0, &val);
	if (!ret)
		bpf_printk("arg1 0x%lx\n", val);

	ret = usdt_arg(ctx, 1, &val);
	if (!ret)
		bpf_printk("arg2 0x%lx\n", val);

	ret = usdt_arg(ctx, 2, &val);
	if (!ret)
		bpf_printk("arg3 0x%lx\n", val);
	return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";

