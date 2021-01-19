// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2019 Facebook
#include <argp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <time.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <sys/sdt.h>
#include "usdt.h"
#include "usdt.skel.h"
#include <libelf.h>
#include <gelf.h>
#include <unistd.h>
#include <fcntl.h>
#include <linux/ptrace.h>

#define _SDT_HAS_SEMAPHORES 1

struct env {
	bool verbose;
} env = {};

const char *argp_program_version = "usdt 0.1";
const char *argp_program_bug_address = "<bpf@vger.kernel.org>";
const char argp_program_doc[] =
"usdt    POC\n";

static const struct argp_option opts[] = {
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'v':
		env.verbose = true;
		break;
	case ARGP_KEY_ARG:
		fprintf(stderr,
			"Unrecognized positional argument: %s\n", arg);
		argp_usage(state);
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

int libbpf_print_fn(enum libbpf_print_level level,
		    const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static int bump_memlock_rlimit(void)
{
	struct rlimit rlim_new = {
		.rlim_cur	= RLIM_INFINITY,
		.rlim_max	= RLIM_INFINITY,
	};

	return setrlimit(RLIMIT_MEMLOCK, &rlim_new);
}

static struct usdt_spec specs[] = {
	{
		.arg_cnt = 0,
	},
	{
		.arg_cnt = 1,
		.args = {
			{
				.arg_sz = -4,
				.arg_signed = true,
				.arg_bitshift = 32,
				.reg_off = offsetof(struct pt_regs, rbp),
				.arg_type = USDT_ARG_STACK,
				.val_off = -4,
			},
		},
	},
	{
		.arg_cnt = 2,
		.args = {
			{
				.arg_sz = -4,
				.arg_signed = true,
				.arg_bitshift = 32,
				.arg_type = USDT_ARG_CONST,
				.val_off = 0x47,
			},
			{
				.arg_sz = -4,
				.arg_signed = true,
				.arg_bitshift = 32,
				.reg_off = offsetof(struct pt_regs, rbp),
				.arg_type = USDT_ARG_STACK,
				.val_off = -20,
			},
		},
	},
	{
		.arg_cnt = 3,
		.args = {
			{
				.arg_sz = -4,
				.arg_signed = true,
				.arg_bitshift = 32,
				.arg_type = USDT_ARG_REG,
				.reg_off = offsetof(struct pt_regs, rax),
			},
			{
				.arg_sz = -4,
				.arg_signed = true,
				.arg_bitshift = 32,
				.reg_off = offsetof(struct pt_regs, rbp),
				.arg_type = USDT_ARG_STACK,
				.val_off = -20,
			},
			{
				.arg_sz = 8,
				.arg_signed = false,
				.arg_bitshift = 0,
				.reg_off = offsetof(struct pt_regs, rbp),
				.arg_type = USDT_ARG_STACK,
				.val_off = -32,
			},
		},
	},
};

/* structure containing an SDT note's info */
struct sdt_note {
	char *name;			/* name of the note*/
	char *provider;			/* provider name */
	char *args;
	bool bit32;			/* whether the location is 32 bits? */
	union {				/* location, base and semaphore addrs */
		Elf64_Addr a64[3];
		Elf32_Addr a32[3];
	} addr;
};

#define SDT_BASE_SCN ".stapsdt.base"
#define SDT_SEMA_SCN ".probes"
#define SDT_NOTE_SCN  ".note.stapsdt"
#define SDT_NOTE_TYPE 3
#define SDT_NOTE_NAME "stapsdt"
#define NR_ADDR 3

enum {
	SDT_NOTE_IDX_LOC = 0,
	SDT_NOTE_IDX_BASE,
	SDT_NOTE_IDX_SEMA,
};

static void sdt_adjust_loc(struct sdt_note *tmp, GElf_Addr base_off)
{
	if (!base_off)
		return;

	if (tmp->bit32)
		tmp->addr.a32[SDT_NOTE_IDX_LOC] =
			tmp->addr.a32[SDT_NOTE_IDX_LOC] + base_off -
			tmp->addr.a32[SDT_NOTE_IDX_BASE];
	else
		tmp->addr.a64[SDT_NOTE_IDX_LOC] =
			tmp->addr.a64[SDT_NOTE_IDX_LOC] + base_off -
			tmp->addr.a64[SDT_NOTE_IDX_BASE];
}

static void sdt_adjust_sema(struct sdt_note *tmp, GElf_Addr base_addr,
			    GElf_Addr base_off)
{
	if (!base_off)
		return;

	if (tmp->bit32 && tmp->addr.a32[SDT_NOTE_IDX_SEMA])
		tmp->addr.a32[SDT_NOTE_IDX_SEMA] -= (base_addr - base_off);
	else if (tmp->addr.a64[SDT_NOTE_IDX_SEMA])
		tmp->addr.a64[SDT_NOTE_IDX_SEMA] -= (base_addr - base_off);
}

Elf_Scn *elf_section_by_name(Elf *elf, GElf_Ehdr *ep,
			     GElf_Shdr *shp, const char *name, size_t *idx)
{
	Elf_Scn *sec = NULL;
	size_t cnt = 1;

	/* Elf is corrupted/truncated, avoid calling elf_strptr. */
	if (!elf_rawdata(elf_getscn(elf, ep->e_shstrndx), NULL))
		return NULL;

	while ((sec = elf_nextscn(elf, sec)) != NULL) {
		char *str;

		gelf_getshdr(sec, shp);
		str = elf_strptr(elf, ep->e_shstrndx, shp->sh_name);
		if (str && !strcmp(name, str)) {
			if (idx)
				*idx = cnt;
			return sec;
		}
		++cnt;
	}

	return NULL;
}

/**
 * populate_sdt_note : Parse raw data and identify SDT note
 * @elf: elf of the opened file
 * @data: raw data of a section with description offset applied
 * @len: note description size
 * @type: type of the note
 * @sdt_notes: List to add the SDT note
 *
 * Responsible for parsing the @data in section .note.stapsdt in @elf and
 * if its an SDT note, it appends to @sdt_notes list.
 */
static int populate_sdt_note(Elf *elf, const char *data, size_t len,
			     struct sdt_note **sdt_note)
{
	const char *provider, *name, *args;
	struct sdt_note *tmp = NULL;
	GElf_Ehdr ehdr;
	GElf_Shdr shdr;
	int ret = -EINVAL;

	union {
		Elf64_Addr a64[NR_ADDR];
		Elf32_Addr a32[NR_ADDR];
	} buf;

	Elf_Data dst = {
		.d_buf = &buf, .d_type = ELF_T_ADDR, .d_version = EV_CURRENT,
		.d_size = gelf_fsize(elf, ELF_T_ADDR, NR_ADDR, EV_CURRENT),
		.d_off = 0, .d_align = 0
	};
	Elf_Data src = {
		.d_buf = (void *) data, .d_type = ELF_T_ADDR,
		.d_version = EV_CURRENT, .d_size = dst.d_size, .d_off = 0,
		.d_align = 0
	};

	tmp = (struct sdt_note *)calloc(1, sizeof(struct sdt_note));
	if (!tmp) {
		ret = -ENOMEM;
		goto out_err;
	}

	if (len < dst.d_size + 3)
		goto out_free_note;

	/* Translation from file representation to memory representation */
	if (gelf_xlatetom(elf, &dst, &src,
			  elf_getident(elf, NULL)[EI_DATA]) == NULL) {
		fprintf(stderr, "gelf_xlatetom : %s\n", elf_errmsg(-1));
		goto out_free_note;
	}

	/* Populate the fields of sdt_note */
	provider = data + dst.d_size;

	name = (const char *)memchr(provider, '\0', data + len - provider);
	if (name++ == NULL)
		goto out_free_note;

	tmp->provider = strdup(provider);
	if (!tmp->provider) {
		ret = -ENOMEM;
		goto out_free_note;
	}
	tmp->name = strdup(name);
	if (!tmp->name) {
		ret = -ENOMEM;
		goto out_free_prov;
	}

	args = memchr(name, '\0', data + len - name);

	/*
	 * There is no argument if:
	 * - We reached the end of the note;
	 * - There is not enough room to hold a potential string;
	 * - The argument string is empty or just contains ':'.
	 */
	if (args == NULL || data + len - args < 2 ||
		args[1] == ':' || args[1] == '\0')
		tmp->args = NULL;
	else {
		tmp->args = strdup(++args);
		if (!tmp->args) {
			ret = -ENOMEM;
			goto out_free_name;
		}
	}

	if (gelf_getclass(elf) == ELFCLASS32) {
		memcpy(&tmp->addr, &buf, 3 * sizeof(Elf32_Addr));
		tmp->bit32 = true;
	} else {
		memcpy(&tmp->addr, &buf, 3 * sizeof(Elf64_Addr));
		tmp->bit32 = false;
	}

	if (!gelf_getehdr(elf, &ehdr)) {
		fprintf(stderr, "%s : cannot get elf header.\n", __func__);
		ret = -EBADF;
		goto out_free_args;
	}

	/* Adjust the prelink effect :
	 * Find out the .stapsdt.base section.
	 * This scn will help us to handle prelinking (if present).
	 * Compare the retrieved file offset of the base section with the
	 * base address in the description of the SDT note. If its different,
	 * then accordingly, adjust the note location.
	 */
	if (elf_section_by_name(elf, &ehdr, &shdr, SDT_BASE_SCN, NULL))
		sdt_adjust_loc(tmp, shdr.sh_offset);

	/* Adjust semaphore offset */
	if (elf_section_by_name(elf, &ehdr, &shdr, SDT_SEMA_SCN, NULL))
		sdt_adjust_sema(tmp, shdr.sh_addr, shdr.sh_offset);

	*sdt_note = tmp;
	return 0;

out_free_args:
	free(&tmp->args);
out_free_name:
	free(&tmp->name);
out_free_prov:
	free(&tmp->provider);
out_free_note:
	free(tmp);
out_err:
	return ret;
}

int parse_elf(const char *path, struct usdt_bpf *obj)
{
	Elf *elf;
	GElf_Ehdr ehdr;
	Elf_Kind ekind;
	int eclass;
	int fd, err = -1;
	size_t nr_shdr, nr_phdr, shdr_stridx;
	Elf_Scn *scn = NULL;
	int spec_idx = 0;

	if (elf_version(EV_CURRENT) == EV_NONE) {
		fprintf(stderr, "libelf initialization failed: %s\n", elf_errmsg(-1));
		return -1;
	}

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		err = -errno;
		fprintf(stderr, "failed to open %s: %d\n", path, err);
		return err;
	}

	elf = elf_begin(fd, ELF_C_READ_MMAP, NULL);
	if (!elf) {
		fprintf(stderr, "elf_begin failed: %s\n", elf_errmsg(-1));
		goto err_out;
	}

	ekind = elf_kind(elf);
	switch (ekind) {
	case ELF_K_ELF:
		break;
	case ELF_K_AR:
	case ELF_K_NONE:
	default:
		fprintf(stderr, "unrecognized ELF kind: %d\n", ekind);
		goto err_out;
	}

	eclass = gelf_getclass(elf);
	if (eclass == ELFCLASSNONE) {
		fprintf(stderr, "failed to get ELF class: %s\n", elf_errmsg(-1));
		goto err_out;
	}

	if (elf_getshdrnum(elf, &nr_shdr)) {
		fprintf(stderr, "failed to get ELF section count: %s\n", elf_errmsg(-1));
		goto err_out;
	}
	if (elf_getshdrstrndx(elf, &shdr_stridx)) {
		fprintf(stderr, "failed to get ELF section headers string section index: %s\n", elf_errmsg(-1));
		goto err_out;
	}
	if (elf_getphdrnum(elf, &nr_phdr)) {
		fprintf(stderr, "failed to get ELF section count: %s\n", elf_errmsg(-1));
		goto err_out;
	}
	if (!gelf_getehdr(elf, &ehdr)) {
		fprintf(stderr, "failed to get EHDR from %s\n", path);
		goto err_out;
	}

	/* Elf is corrupted/truncated, avoid calling elf_strptr. */
	if (!elf_rawdata(elf_getscn(elf, shdr_stridx), NULL)) {
		fprintf(stderr, "failed to get e_shstrndx from %s: %s\n", path, elf_errmsg(-1));
		goto err_out;
	}

	while ((scn = elf_nextscn(elf, scn)) != NULL) {
		char *name;
		GElf_Shdr sh;
		Elf_Data *data;
		int idx;

		if (gelf_getshdr(scn, &sh) != &sh) {
			fprintf(stderr, "failed to get section(%ld) header from %s\n",
				elf_ndxscn(scn), path);
			goto err_out;
		}

		idx = elf_ndxscn(scn);

		name = elf_strptr(elf, shdr_stridx, sh.sh_name);
		if (!name) {
			fprintf(stderr, "failed to get section(%d) name from %s\n",
				idx, path);
			goto err_out;
		}

		data = elf_getdata(scn, 0);
		if (!data) {
			fprintf(stderr, "failed to get section(%d) data from %s(%s)\n",
				idx, name, path);
			goto err_out;
		}
		fprintf(stderr, "section(%d) %s, size %ld, link %d, flags %lx, type=%d\n",
			 idx, name, (unsigned long)data->d_size,
			 (int)sh.sh_link, (unsigned long)sh.sh_flags,
			 (int)sh.sh_type);

#define SDT_NOTE_SCN ".note.stapsdt"
#define SDT_NOTE_NAME "stapsdt"
#define SDT_NOTE_TYPE 3 

		if (strcmp(name, SDT_NOTE_SCN) == 0) {
			GElf_Nhdr nhdr;
			size_t next, off, name_off, desc_off;

			if (sh.sh_type != SHT_NOTE) {
				fprintf(stderr, "unexpected section type %d\n", (int)sh.sh_type);
				goto err_out;
			}
			if (sh.sh_flags & SHF_ALLOC) {
				fprintf(stderr, "allocatable note?\n");
				goto err_out;
			}

			for (off = 0; (next = gelf_getnote(data, off, &nhdr, &name_off, &desc_off)) > 0; off = next) {
				struct sdt_note *note;

				if (strcmp(data->d_buf + name_off, SDT_NOTE_NAME))
					goto err_out;
				if (nhdr.n_type != SDT_NOTE_TYPE)
					goto err_out;

				if (populate_sdt_note(elf, data->d_buf + desc_off,
							nhdr.n_descsz, &note))
					goto err_out;

				long usdt_ip = 0x400000 + note->addr.a64[SDT_NOTE_IDX_LOC];
				fprintf(stderr, "Found SDT NOTE: %s %s is32:%d IP:%lx loc: %lx, base:%lx, sema: %lx args=%s\n",  note->provider, note->name, !!note->bit32, usdt_ip, note->addr.a64[SDT_NOTE_IDX_LOC], note->addr.a64[SDT_NOTE_IDX_BASE], note->addr.a64[SDT_NOTE_IDX_SEMA], note->args);

				if (bpf_map_update_elem(bpf_map__fd(obj->maps.usdt_specs), &usdt_ip,
							&specs[spec_idx], 0)) {
					fprintf(stderr, "failed to set USDT spec #%d\n", spec_idx);
					goto err_out;
				}
				spec_idx++;

				struct bpf_link *link;
				link = bpf_program__attach_uprobe(
					obj->progs.handle_usdt_exp,
					false, 0, "/proc/self/exe", note->addr.a64[SDT_NOTE_IDX_LOC]);
				if (libbpf_get_error(link)) {
					fprintf(stderr, "failed to attach USDT %s/%s: %ld\n",
						note->provider, note->name,
						libbpf_get_error(link));
					goto err_out;
				}
			}
		}
	}

	elf_end(elf);
	return 0;
err_out:
	if (elf)
		elf_end(elf);
	close(fd);
	return err;
}

unsigned short hello_probe_main_semaphore __attribute__ ((unused)) __attribute__ ((section (".probes")));
unsigned short hello_probe_main1_semaphore __attribute__ ((unused)) __attribute__ ((section (".probes")));
unsigned short hello_probe_main2_semaphore __attribute__ ((unused)) __attribute__ ((section (".probes")));
unsigned short hello_probe_main3_semaphore __attribute__ ((unused)) __attribute__ ((section (".probes")));

int bla = 0x123;

int main(int argc, char **argv)
{
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};
	struct usdt_bpf *obj;
	int err;
	int a = 1;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	libbpf_set_print(libbpf_print_fn);

	err = bump_memlock_rlimit();
	if (err) {
		fprintf(stderr, "failed to increase rlimit: %d", err);
		return 1;
	}

	obj = usdt_bpf__open();
	if (!obj) {
		fprintf(stderr, "failed to open and/or load BPF object\n");
		return 1;
	}

	err = usdt_bpf__load(obj);
	if (err) {
		fprintf(stderr, "failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	const char *path = "usdt";
	err = parse_elf(path, obj);
	if (err) {
		fprintf(stderr, "failed to parse ELF at %s: %d\n", path, err);
		return 1;
	}

	err = usdt_bpf__attach(obj);
	if (err) {
		fprintf(stderr, "failed to attach BPF programs\n");
		goto cleanup;
	}

	printf("Tracing...\n");

	while (true) {
		STAP_PROBE(hello, probe_main);
		STAP_PROBE1(hello, probe_main1, a);
		STAP_PROBE2(hello, probe_main2, 0x47, a);
		STAP_PROBE3(hello, probe_main3, bla, a, argc);
		sleep(1);
	}

cleanup:
	usdt_bpf__destroy(obj);

	return err != 0;
}
