// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright 2019 NXP
 */

#include <common.h>
#include <console.h>
#include <errno.h>
#include <fuse.h>
#include <firmware/imx/sci/sci.h>
#include <asm/arch/sys_proto.h>
#include <asm/global_data.h>
#include <linux/arm-smccc.h>
#include <env.h>

DECLARE_GLOBAL_DATA_PTR;

#define FSL_ECC_WORD_START_1	 0x10
#define FSL_ECC_WORD_END_1	 0x10F

#ifdef CONFIG_IMX8QM
#define FSL_ECC_WORD_START_2	 0x1A0
#define FSL_ECC_WORD_END_2	 0x1FF
#elif defined(CONFIG_IMX8QXP) || defined(CONFIG_IMX8DXL)
#define FSL_ECC_WORD_START_2	 0x220
#define FSL_ECC_WORD_END_2	 0x31F
#endif

#define FSL_QXP_FUSE_GAP_START	 0x110
#define FSL_QXP_FUSE_GAP_END	 0x21F

#define FSL_SIP_OTP_READ             0xc200000A
#define FSL_SIP_OTP_WRITE            0xc200000B

static bool allow_prog = false;

void fuse_allow_prog(bool allow)
{
	allow_prog = allow;
}

bool fuse_is_prog_allowed(void)
{
	return allow_prog;
}

int fuse_read(u32 bank, u32 word, u32 *val)
{
	return fuse_sense(bank, word, val);
}

int fuse_sense(u32 bank, u32 word, u32 *val)
{
	struct arm_smccc_res res;

	if (bank != 0) {
		printf("Invalid bank argument, ONLY bank 0 is supported\n");
		return -EINVAL;
	}

	arm_smccc_smc(FSL_SIP_OTP_READ, (unsigned long)word, 0, 0,
		      0, 0, 0, 0, &res);
	*val = (u32)res.a1;

	return res.a0;
}

int fuse_prog(u32 bank, u32 word, u32 val)
{
	struct arm_smccc_res res;
	int force_prog = 0;

	if (bank != 0) {
		printf("Invalid bank argument, ONLY bank 0 is supported\n");
		return -EINVAL;
	}

	if (IS_ENABLED(CONFIG_IMX8QXP) || IS_ENABLED(CONFIG_IMX8DXL)) {
		if (word >= FSL_QXP_FUSE_GAP_START &&
		    word <= FSL_QXP_FUSE_GAP_END) {
			printf("Invalid word argument for this SoC\n");
			return -EINVAL;
		}
	}

	if (!fuse_is_prog_allowed()) {
		force_prog = env_get_yesno("force_prog_ecc");
		if (force_prog != 1) {
			if ((word >= FSL_ECC_WORD_START_1 && word <= FSL_ECC_WORD_END_1) ||
			(word >= FSL_ECC_WORD_START_2 && word <= FSL_ECC_WORD_END_2)) {
				puts("Warning: Words in this index range have ECC protection\n"
				"and can only be programmed once per word. Individual bit\n"
				"operations will be rejected after the first one.\n"
				"\n\n Really program this word? <y/N>\n");

				if (!confirm_yesno()) {
					puts("Word programming aborted\n");
					return -EPERM;
				}
			}
		}
	}

	arm_smccc_smc(FSL_SIP_OTP_WRITE, (unsigned long)word,
		      (unsigned long)val, 0, 0, 0, 0, 0, &res);

	return res.a0;
}

int fuse_override(u32 bank, u32 word, u32 val)
{
	printf("Override fuse to i.MX8 in u-boot is forbidden\n");
	return -EPERM;
}
