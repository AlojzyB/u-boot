/*
 * Copyright (C) 2024, Digi International Inc.
 *
 * SPDX-License-Identifier: GPL-2.0+
 */

#include <common.h>
#include <command.h>
#include <fdt_support.h>
#include <fuse.h>
#include <asm/mach-imx/hab.h>
#include <mapmem.h>

#include "../helper.h"
#include "boot.h"
#include "encryption.h"

extern int rng_swtest_status;

/*
 * Check if all SRK words have been burned.
 *
 * Returns:
 * 0 if all SRK are burned
 * i+1 if SRK word i is not burned
 * <0 on error
 */
__weak int fuse_check_srk(void)
{
	int i;
	u32 val;
	int bank, word;

	for (i = 0; i < CONFIG_TRUSTFENCE_SRK_WORDS; i++) {
		bank = CONFIG_TRUSTFENCE_SRK_BANK +
		       (i / CONFIG_TRUSTFENCE_SRK_WORDS_PER_BANK);
		word = i % CONFIG_TRUSTFENCE_SRK_WORDS_PER_BANK;
		if (fuse_sense(bank, word+CONFIG_TRUSTFENCE_SRK_WORDS_OFFSET,
			       &val))
			return -1;
		if (val == 0)
			return i + 1;
	}

	return 0;
}

__weak int fuse_prog_srk(u32 addr, u32 size)
{
	int i;
	int ret;
	int bank, word;
	uint32_t *src_addr = map_sysmem(addr, size);

	if (size != CONFIG_TRUSTFENCE_SRK_WORDS * 4) {
		puts("Bad size\n");
		return -1;
	}

	for (i = 0; i < CONFIG_TRUSTFENCE_SRK_WORDS; i++) {
		bank = CONFIG_TRUSTFENCE_SRK_BANK +
		       (i / CONFIG_TRUSTFENCE_SRK_WORDS_PER_BANK);
		word = i % CONFIG_TRUSTFENCE_SRK_WORDS_PER_BANK;
		ret = fuse_prog(bank, word+CONFIG_TRUSTFENCE_SRK_WORDS_OFFSET,
				src_addr[i]);
		if (ret)
			return ret;
	}

	return 0;
}

#if defined(CONFIG_TRUSTFENCE_SRK_OTP_LOCK_BANK) && \
    defined(CONFIG_TRUSTFENCE_SRK_OTP_LOCK_WORD) && \
    defined(CONFIG_TRUSTFENCE_SRK_OTP_LOCK_OFFSET)
__weak int lock_srk_otp(void)
{
	return fuse_prog(CONFIG_TRUSTFENCE_SRK_OTP_LOCK_BANK,
			 CONFIG_TRUSTFENCE_SRK_OTP_LOCK_WORD,
			 1 << CONFIG_TRUSTFENCE_SRK_OTP_LOCK_OFFSET);
}
#else
__weak int lock_srk_otp(void)	{return 0;}
#endif

#if defined(CONFIG_IMX_HAB)
__weak int revoke_key_index(int i)
{
	u32 val = ((1 << i) & CONFIG_TRUSTFENCE_SRK_REVOKE_MASK) <<
		    CONFIG_TRUSTFENCE_SRK_REVOKE_OFFSET;
	return fuse_prog(CONFIG_TRUSTFENCE_SRK_REVOKE_BANK,
			 CONFIG_TRUSTFENCE_SRK_REVOKE_WORD,
			 val);
}
#endif

#if defined(CONFIG_AHAB_BOOT)
__weak int revoke_keys(void)
{
	return -1;
}
#endif

#if defined(CONFIG_TRUSTFENCE_SRK_REVOKE_BANK) && \
    defined(CONFIG_TRUSTFENCE_SRK_REVOKE_WORD) && \
    defined(CONFIG_TRUSTFENCE_SRK_REVOKE_MASK) && \
    defined(CONFIG_TRUSTFENCE_SRK_REVOKE_OFFSET)
__weak int sense_key_status(u32 *val)
{
	if (fuse_sense(CONFIG_TRUSTFENCE_SRK_REVOKE_BANK,
			CONFIG_TRUSTFENCE_SRK_REVOKE_WORD,
			val))
		return -1;

	*val = (*val >> CONFIG_TRUSTFENCE_SRK_REVOKE_OFFSET) &
		CONFIG_TRUSTFENCE_SRK_REVOKE_MASK;

	return 0;
}
#else
__weak int sense_key_status(u32 * val) { return -1; }
#endif

#if defined(CONFIG_TRUSTFENCE_DIRBTDIS_BANK) && \
    defined(CONFIG_TRUSTFENCE_DIRBTDIS_WORD) && \
    defined(CONFIG_TRUSTFENCE_DIRBTDIS_OFFSET)
__weak int disable_ext_mem_boot(void)
{
	return fuse_prog(CONFIG_TRUSTFENCE_DIRBTDIS_BANK,
			 CONFIG_TRUSTFENCE_DIRBTDIS_WORD,
			 1 << CONFIG_TRUSTFENCE_DIRBTDIS_OFFSET);
}
#else
__weak int disable_ext_mem_boot(void) { return -1; }
#endif

#if defined(CONFIG_TRUSTFENCE_CLOSE_BIT_BANK) && \
    defined(CONFIG_TRUSTFENCE_CLOSE_BIT_WORD) && \
    defined(CONFIG_TRUSTFENCE_CLOSE_BIT_OFFSET)
__weak int close_device(int confirmed)
{
	hab_rvt_report_status_t *hab_report_status = (hab_rvt_report_status_t *)HAB_RVT_REPORT_STATUS;
	enum hab_config config = 0;
	enum hab_state state = 0;
	int ret = -1;

	ret = hab_report_status(&config, &state);
	if (ret == HAB_FAILURE) {
		puts("[ERROR]\n There are HAB Events which will prevent the target from booting once closed.\n");
		puts("Run 'hab_status' and check the errors.\n");
		return CMD_RET_FAILURE;
	} else if (ret == HAB_WARNING) {
		if (rng_swtest_status == SW_RNG_TEST_FAILED) {
			puts("[WARNING]\n There are HAB warnings which could prevent the target from booting once closed.\n");
			puts("Run 'hab_status' and check the errors.\n");
			return CMD_RET_FAILURE;
		}
	}

	puts("Before closing the device DIR_BT_DIS will be burned.\n");
	puts("This permanently disables the ability to boot using external memory.\n");
	puts("The SRK_LOCK OTP bit will also be programmed, locking the SRK fields.\n");
	puts("Please confirm the programming of SRK_LOCK, DIR_BT_DIS and SEC_CONFIG[1]\n\n");
	if (!confirmed && !confirm_prog())
		return CMD_RET_FAILURE;

	puts("Programming DIR_BT_DIS eFuse...\n");
	if (disable_ext_mem_boot())
		goto err;
	puts("[OK]\n");

	puts("Programming SRK_LOCK eFuse...\n");
	if (lock_srk_otp())
		goto err;
	puts("[OK]\n");

	puts("Closing device...\n");
	return fuse_prog(CONFIG_TRUSTFENCE_CLOSE_BIT_BANK,
			 CONFIG_TRUSTFENCE_CLOSE_BIT_WORD,
			 1 << CONFIG_TRUSTFENCE_CLOSE_BIT_OFFSET);
err:
	return ret;
}
#else
__weak int close_device(int confirmed) { return -1; }
#endif

void fdt_fixup_trustfence(void *fdt)
{
	/* Environment encryption is not enabled on open devices */
	if (!imx_hab_is_enabled()) {
		do_fixup_by_path(fdt, "/", "digi,tf-open", NULL, 0, 1);
		return;
	}

	if (IS_ENABLED(CONFIG_ENV_ENCRYPT))
		do_fixup_by_path(fdt, "/", "digi,uboot-env,encrypted", NULL, 0,
				 1);
	if (IS_ENABLED(CONFIG_OPTEE_ENV_ENCRYPT))
		do_fixup_by_path(fdt, "/", "digi,uboot-env,encrypted-optee",
				 NULL, 0, 1);

	do_fixup_by_path(fdt, "/", "digi,tf-closed", NULL, 0, 1);
}

/* Platform */
__weak int trustfence_status(void)
{
	hab_rvt_report_status_t *hab_report_status = (hab_rvt_report_status_t *)HAB_RVT_REPORT_STATUS;
	enum hab_config config = 0;
	enum hab_state state = 0;
	int ret;

	printf("* Encrypted U-Boot:\t%s\n", is_uboot_encrypted() ?
			"[YES]" : "[NO]");
	puts("* HAB events:\t\t");
	ret = hab_report_status(&config, &state);
	if (ret == HAB_SUCCESS)
		puts("[NO ERRORS]\n");
	else if (ret == HAB_FAILURE)
		puts("[ERRORS PRESENT!]\n");
	else if (ret == HAB_WARNING) {
		if (rng_swtest_status == SW_RNG_TEST_PASSED) {
			puts("[NO ERRORS]\n");
			puts("\n");
			puts("Note: RNG selftest failed, but software test passed\n");
		} else {
			puts("[WARNINGS PRESENT!]\n");
		}
	}

	return 0;
}
