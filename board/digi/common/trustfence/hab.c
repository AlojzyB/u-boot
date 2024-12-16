/*
 * Copyright (C) 2024, Digi International Inc.
 *
 * SPDX-License-Identifier: GPL-2.0+
 */

#include <command.h>
#include <common.h>
#include <fuse.h>
#include <asm/mach-imx/hab.h>

#include "../helper.h"
#include "encryption.h"
#include "hab.h"

#define BLOB_DEK_OFFSET		0x100

extern int rng_swtest_status;

__weak int get_dek_blob(ulong addr, u32 *size)
{
	return 1;
}

__weak int get_dek_blob_offset(ulong addr, u32 *offset)
{
	return -1;
}

__weak int get_dek_blob_size(ulong addr, u32 *size)
{
	return -1;
}

/*
 * For secure OS, we want to have the DEK blob in a common absolute
 * memory address, so that there are no dependencies between the CSF
 * appended to the uImage and the U-Boot image size.
 * This copies the DEK blob into $loadaddr - BLOB_DEK_OFFSET. That is the
 * smallest negative offset that guarantees that the DEK blob fits and that it
 * is properly aligned.
 */
void copy_dek(void)
{
	ulong loadaddr = env_get_ulong("loadaddr", 16, CONFIG_SYS_LOAD_ADDR);
	ulong dek_blob_dst = loadaddr - BLOB_DEK_OFFSET;
	u32 dek_size;

	get_dek_blob(dek_blob_dst, &dek_size);
}

__weak void copy_spl_dek(void)
{
	return;
}

int trustfence_status(void)
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

static int disable_ext_mem_boot(void)
{
	return fuse_prog(CONFIG_TRUSTFENCE_DIRBTDIS_BANK,
			 CONFIG_TRUSTFENCE_DIRBTDIS_WORD,
			 1 << CONFIG_TRUSTFENCE_DIRBTDIS_OFFSET);
}

static int lock_srk_otp(void)
{
	return fuse_prog(CONFIG_TRUSTFENCE_SRK_OTP_LOCK_BANK,
			 CONFIG_TRUSTFENCE_SRK_OTP_LOCK_WORD,
			 1 << CONFIG_TRUSTFENCE_SRK_OTP_LOCK_OFFSET);
}

int close_device(int confirmed)
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

int sense_key_status(u32 *val)
{
	if (fuse_sense(CONFIG_TRUSTFENCE_SRK_REVOKE_BANK,
			CONFIG_TRUSTFENCE_SRK_REVOKE_WORD,
			val))
		return -1;

	*val = (*val >> CONFIG_TRUSTFENCE_SRK_REVOKE_OFFSET) &
		CONFIG_TRUSTFENCE_SRK_REVOKE_MASK;

	return 0;
}

int revoke_key_index(int i)
{
	u32 val = ((1 << i) & CONFIG_TRUSTFENCE_SRK_REVOKE_MASK) <<
		    CONFIG_TRUSTFENCE_SRK_REVOKE_OFFSET;
	return fuse_prog(CONFIG_TRUSTFENCE_SRK_REVOKE_BANK,
			 CONFIG_TRUSTFENCE_SRK_REVOKE_WORD,
			 val);
}
