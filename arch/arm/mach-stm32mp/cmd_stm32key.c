// SPDX-License-Identifier: GPL-2.0+ OR BSD-3-Clause
/*
 * Copyright (C) 2019, STMicroelectronics - All Rights Reserved
 */

#include <common.h>
#include <command.h>
#include <console.h>
#include <misc.h>
#include <dm/device.h>
#include <dm/uclass.h>

#define STM32_OTP_HASH_KEY_START 24
#define STM32_OTP_HASH_KEY_SIZE 8

static void read_hash_value(u32 addr)
{
	int i;

	for (i = 0; i < STM32_OTP_HASH_KEY_SIZE; i++) {
		printf("OTP value %i: %x\n", STM32_OTP_HASH_KEY_START + i,
		       __be32_to_cpu(*(u32 *)addr));
		addr += 4;
	}
}

static void fuse_hash_value(u32 addr, bool print)
{
	struct udevice *dev;
	u32 word, val;
	int i, ret;

	ret = uclass_get_device_by_driver(UCLASS_MISC,
					  DM_GET_DRIVER(stm32mp_bsec),
					  &dev);
	if (ret) {
		pr_err("Can't find stm32mp_bsec driver\n");
		return;
	}

	for (i = 0; i < STM32_OTP_HASH_KEY_SIZE; i++) {
		if (print)
			printf("Fuse OTP %i : %x\n",
			       STM32_OTP_HASH_KEY_START + i,
			       __be32_to_cpu(*(u32 *)addr));

		word = STM32_OTP_HASH_KEY_START + i;
		val = __be32_to_cpu(*(u32 *)addr);
		misc_write(dev, STM32_BSEC_OTP(word), &val, 4);

		addr += 4;
	}
}

static int confirm_prog(void)
{
	puts("Warning: Programming fuses is an irreversible operation!\n"
			"         This may brick your system.\n"
			"         Use this command only if you are sure of what you are doing!\n"
			"\nReally perform this fuse programming? <y/N>\n");

	if (confirm_yesno())
		return 1;

	puts("Fuse programming aborted\n");
	return 0;
}

static int do_stm32key_read(struct cmd_tbl *cmdtp, int flag, int argc, char *const argv[])
{
	u32 addr;

	if (argc == 1)
		return CMD_RET_USAGE;

	addr = simple_strtoul(argv[1], NULL, 16);
	if (!addr)
		return CMD_RET_USAGE;

	read_hash_value(addr);

	return CMD_RET_SUCCESS;
}

static int do_stm32key_fuse(struct cmd_tbl *cmdtp, int flag, int argc, char *const argv[])
{
	u32 addr;
	bool yes = false;

	if (argc < 2)
		return CMD_RET_USAGE;

	if (argc == 3) {
		if (strcmp(argv[1], "-y"))
			return CMD_RET_USAGE;
		yes = true;
	}

	addr = simple_strtoul(argv[argc - 1], NULL, 16);
	if (!addr)
		return CMD_RET_USAGE;

	if (!yes && !confirm_prog())
		return CMD_RET_FAILURE;

	fuse_hash_value(addr, !yes);
	printf("Hash key updated !\n");

	return CMD_RET_SUCCESS;
}

static char stm32key_help_text[] =
	"read <addr>: Read the hash stored at addr in memory\n"
	"stm32key fuse [-y] <addr> : Fuse hash stored at addr in OTP\n";

U_BOOT_CMD_WITH_SUBCMDS(stm32key, "Fuse ST Hash key", stm32key_help_text,
	U_BOOT_SUBCMD_MKENT(read, 2, 0, do_stm32key_read),
	U_BOOT_SUBCMD_MKENT(fuse, 3, 0, do_stm32key_fuse));
