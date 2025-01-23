/*
 * Copyright (C) 2019-2024, Digi International Inc.
 * Copyright 2018 NXP
 *
 * SPDX-License-Identifier:	GPL-2.0+
 */

#include <common.h>
#include <env.h>
#include <mmc.h>
#include <asm/global_data.h>
#include <asm/arch/sys_proto.h>
#include <asm/mach-imx/boot_mode.h>
#include <spl.h>

#include "../common/hwid.h"

DECLARE_GLOBAL_DATA_PTR;

int board_phys_sdram_size(phys_size_t *size)
{
	/* Default to RAM size of DVK variant 0x01 (1 GiB) */
	u64 ram;
	struct digi_hwid my_hwid;

	/* Default to minimum RAM size for each platform */
	if (is_imx8mn())
		ram = SZ_512M;  /* ccimx8mn variant 0x03 (512MB) */
	else
		ram = SZ_1G;    /* ccimx8mm variant 0x01 (1GB) */

	if (board_read_hwid(&my_hwid)) {
		debug("Cannot read HWID. Using default DDR configuration.\n");
		my_hwid.ram = 0;
	}

	if (my_hwid.ram)
		ram = hwid_get_ramsize(&my_hwid);

	*size = ram;

	return 0;
}

int mmc_get_bootdevindex(void)
{
	switch(get_boot_device()) {
	case SD2_BOOT:
		return 1;	/* index of USDHC2 (SD card) */
	case MMC3_BOOT:
		return 0;	/* index of USDHC3 (eMMC) */
	default:
		/* return default value otherwise */
		return EMMC_BOOT_DEV;
	}
}

uint mmc_get_env_part(struct mmc *mmc)
{
	switch(get_boot_device()) {
	case SD1_BOOT ... SD3_BOOT:
		return 0;	/* When booting from an SD card the
				 * environment will be saved to the unique
				 * hardware partition: 0 */
	case MMC3_BOOT:
	default:
		return CONFIG_SYS_MMC_ENV_PART;
				/* When booting from USDHC3 (eMMC) the
				 * environment will be saved to boot
				 * partition 2 to protect it from
				 * accidental overwrite during U-Boot update */
	}
}

void calculate_uboot_update_settings(struct blk_desc *mmc_dev,
				     struct disk_partition *info)
{
	struct mmc *mmc = find_mmc_device(EMMC_BOOT_DEV);
	int part = env_get_ulong("mmcbootpart", 10, EMMC_BOOT_PART);

	/*
	 * Use a different offset depending on the target device and partition:
	 * - For eMMC BOOT1 and BOOT2
	 *	Offset = 0
	 * - For eMMC User Data area.
	 *	Offset = EMMC_BOOT_PART_OFFSET
	 */
	if (is_imx8mn() && (part == 1 || part == 2)) {
		/* eMMC BOOT1 or BOOT2 partitions */
		info->start = 0;
	} else {
		info->start = EMMC_BOOT_PART_OFFSET / mmc_dev->blksz;
	}
	/* Boot partition size - Start of boot image */
	info->size = (mmc->capacity_boot / mmc_dev->blksz) - info->start;
}
