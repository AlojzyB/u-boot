/*
 * Copyright (C) 2018-2024, Digi International Inc.
 * Copyright 2017 NXP
 *
 * SPDX-License-Identifier:	GPL-2.0+
 */

#include <common.h>
#include <cpu.h>
#include <env.h>
#include <mmc.h>
#include <fdt_support.h>
#include <dm/device.h>
#include <linux/ctype.h>
#include <linux/sizes.h>
#include <asm/arch/sys_proto.h>
#include <asm/arch-imx/cpu.h>
#include <asm/mach-imx/boot_mode.h>
#include <asm/global_data.h>

#include "../common/helper.h"
#include "../common/hwid.h"
#include "../common/mca.h"

DECLARE_GLOBAL_DATA_PTR;

struct ccimx8_variant ccimx8x_variants[] = {
/* 0x00 */ { IMX8_NONE,	0, 0, "Unknown"},
/* 0x01 - 55001984-01 */
	{
		IMX8QXP,
		SZ_1G,
		CCIMX8_HAS_WIRELESS | CCIMX8_HAS_BLUETOOTH,
		"Automotive QuadXPlus, 8GB eMMC, 1GB LPDDR4, -40/+85C, Wireless, Bluetooth",
	},
/* 0x02 - 55001984-02 */
	{
		IMX8QXP,
		SZ_2G,
		CCIMX8_HAS_WIRELESS | CCIMX8_HAS_BLUETOOTH,
		"Industrial QuadXPlus, 16GB eMMC, 2GB LPDDR4, -40/+85C, Wireless, Bluetooth",
	},
/* 0x03 - 55001984-03 */
	{
		IMX8QXP,
		SZ_2G,
		0,
		"Industrial QuadXPlus, 8GB eMMC, 2GB LPDDR4, -40/+85C",
	},
/* 0x04 - 55001984-04 */
	{
		IMX8DX,
		SZ_1G,
		CCIMX8_HAS_WIRELESS | CCIMX8_HAS_BLUETOOTH,
		"Industrial DualX, 8GB eMMC, 1GB LPDDR4, -40/+85C, Wireless, Bluetooth",
	},
/* 0x05 - 55001984-05 */
	{
		IMX8DX,
		SZ_1G,
		0,
		"Industrial DualX, 8GB eMMC, 1GB LPDDR4, -40/+85C",
	},
/* 0x06 - 55001984-06 */
	{
		IMX8DX,
		SZ_512M,
		0,
		"Industrial DualX, 8GB eMMC, 512MB LPDDR4, -40/+85C",
	},
/* 0x07 - 55001984-07 */
	{
		IMX8QXP,
		SZ_1G,
		0,
		"Industrial QuadXPlus, 8GB eMMC, 1GB LPDDR4, -40/+85C",
	},
/* 0x08 - 55001984-08 */
	{
		IMX8QXP,
		SZ_1G,
		CCIMX8_HAS_WIRELESS | CCIMX8_HAS_BLUETOOTH,
		"Industrial QuadXPlus, 8GB eMMC, 1GB LPDDR4, -40/+85C, Wireless, Bluetooth",
	},
/* 0x09 - 55001984-09 */
	{
		IMX8DX,
		SZ_512M,
		0,
		"Industrial DualX, 8GB eMMC, 512MB LPDDR4, -40/+85C",
	},
/* 0x0A - 55001984-10 */
	{
		IMX8DX,
		SZ_1G,
		0,
		"Industrial DualX, 8GB eMMC, 1GB LPDDR4, -40/+85C",
	},
/* 0x0B - 55001984-11 */
	{
		IMX8DX,
		SZ_1G,
		CCIMX8_HAS_WIRELESS | CCIMX8_HAS_BLUETOOTH,
		"Industrial DualX, 8GB eMMC, 1GB LPDDR4, -40/+85C, Wireless, Bluetooth",
	},
/* 0x0C - 55001984-12 */
	{
		IMX8QXP,
		SZ_2G,
		CCIMX8_HAS_WIRELESS | CCIMX8_HAS_BLUETOOTH,
		"Industrial QuadXPlus, 16GB eMMC, 2GB LPDDR4, -40/+85C, Wireless, Bluetooth",
	},
/* 0x0D - 55001984-13 */
	{
		IMX8QXP,
		SZ_4G,
		CCIMX8_HAS_WIRELESS | CCIMX8_HAS_BLUETOOTH,
		"Industrial QuadXPlus, 32GB eMMC, 4GB LPDDR4, -40/+85C, Wireless, Bluetooth",
	},
};

void board_mem_get_layout(u64 *phys_sdram_1_start,
			  u64 *phys_sdram_1_size,
			  u64 *phys_sdram_2_start,
			  u64 *phys_sdram_2_size)
{
	struct digi_hwid my_hwid;

	/* Default values */
	*phys_sdram_1_start = PHYS_SDRAM_1;
	*phys_sdram_1_size = 0;
	*phys_sdram_2_start = PHYS_SDRAM_2;
	*phys_sdram_2_size = PHYS_SDRAM_2_SIZE;

	if (!board_read_hwid(&my_hwid)) {
		*phys_sdram_1_size = (u64)hwid_get_ramsize(&my_hwid);
		if (!*phys_sdram_1_size) {
			/* if RAM size was not coded, use variant to obtain RAM size */
			if (my_hwid.variant < ARRAY_SIZE(ccimx8x_variants))
				*phys_sdram_1_size = (unsigned int)ccimx8x_variants[my_hwid.variant].sdram;
		}
	}

	if (*phys_sdram_1_size > SZ_2G) {
		/*
		 * Special case: split the size between the two SDRAM banks:
		 *     * First 2 GiB go in bank 1
		 *     * Remaining size goes in bank 2
		 */
		*phys_sdram_2_size = *phys_sdram_1_size - SZ_2G;
		*phys_sdram_1_size = SZ_2G;
	} else if (!*phys_sdram_1_size) {
		*phys_sdram_1_size = PHYS_SDRAM_1_SIZE;
		printk("Cannot determine RAM size. Using default size (%d MiB).\n", PHYS_SDRAM_1_SIZE >> 20);
	}
}

int mmc_get_bootdevindex(void)
{
	switch(get_boot_device()) {
	case SD2_BOOT:
		return 1;	/* index of USDHC2 (SD card) */
	case MMC1_BOOT:
		return 0;	/* index of USDHC1 (eMMC) */
	default:
		/* return default value otherwise */
		return EMMC_BOOT_DEV;
	}
}

uint mmc_get_env_part(struct mmc *mmc)
{
	switch(get_boot_device()) {
	case SD2_BOOT:
		return 0;	/* When booting from an SD card the
				 * environment will be saved to the unique
				 * hardware partition: 0 */
	case MMC1_BOOT:
	default:
		return CONFIG_SYS_MMC_ENV_PART;
				/* When booting from USDHC1 (eMMC) the
				 * environment will be saved to boot
				 * partition 2 to protect it from
				 * accidental overwrite during U-Boot update */
	}
}

int hwid_in_db(int variant)
{
	if (variant < ARRAY_SIZE(ccimx8x_variants))
		if (ccimx8x_variants[variant].cpu != IMX8_NONE)
			return 1;

	return 0;
}

int board_lock_hwid(void)
{
	/* SCU performs automatic lock after programming */
	printf("not supported. Fuses automatically locked after programming.\n");
	return 1;
}

/*
 * Board specific reset that is system reset.
 */
void reset_cpu(void)
{
	sc_pm_reboot(-1, SC_PM_RESET_TYPE_COLD);
	while(1);
}

void detail_board_ddr_info(void)
{
	puts("\nDDR    ");
}

void calculate_uboot_update_settings(struct blk_desc *mmc_dev,
				     struct disk_partition *info)
{
	/* Use a different offset depending on the i.MX8X QXP CPU revision */
	u32 cpurev = get_cpu_rev();
	struct mmc *mmc = find_mmc_device(EMMC_BOOT_DEV);
	int part = env_get_ulong("mmcbootpart", 10, EMMC_BOOT_PART);

	switch (cpurev & 0xFFF) {
	case CHIP_REV_A:
		info->start = EMMC_BOOT_PART_OFFSET_A0 / mmc_dev->blksz;
		break;
	case CHIP_REV_B:
		info->start = EMMC_BOOT_PART_OFFSET / mmc_dev->blksz;
		break;
	default:
		/*
		 * Starting from RevC, use a different offset depending on the
		 * target device and partition:
		 * - For eMMC BOOT1 and BOOT2
		 *	Offset = 0
		 * - For eMMC User Data area.
		 *	Offset = EMMC_BOOT_PART_OFFSET
		 */
		if (part == 1 || part == 2) {
			/* eMMC BOOT1 or BOOT2 partitions */
			info->start = 0;
		} else {
			info->start = EMMC_BOOT_PART_OFFSET / mmc_dev->blksz;
		}
		break;
	}
	/* Boot partition size - Start of boot image */
	info->size = (mmc->capacity_boot / mmc_dev->blksz) - info->start;
}


/*
 * According to NXP, reading the imx-boot image at this offset will give us the
 * hash of the config file used in the SECO fw compilation. This hash is
 * guaranteed to be different in B0 and C0 versions of the fw, allowing us to
 * verify the SECO fw against the SOC revision programatically.
 *
 * It's also likely that it won't change in future releases within the same BSP
 * (such as v5.4), so we probably won't need to update it very often.
 */
#define SECO_CONFIG_HASH_OFFSET	8244

/*
 * List of currently known SECO watermarks. It needs to be updated if new
 * watermarks appear in future SECO fw releases. Each watermark can be obtained
 * with the following shell command:
 *
 * $ od -t x4 -j 8244 -N 4 imx-boot.bin
 */
#define C0_DEY_NEXT_SECO	0x8f8d084a	/* v3.8.4 */
#define C0_DEY_3_2_SECO		0xa1432215	/* v3.7.5 */
#define C0_DEY_3_0_r3_SECO	0xf93f6828	/* v3.7.1 */
#define C0_DEY_3_0_SECO		0x7ad5f995	/* v2.6.1 - v3.6.3 */

#define B0_DEY_NEXT_SECO	0x885b57e7	/* v3.8.4 */
#define B0_DEY_3_0_r3_SECO	0x86166309	/* v3.7.1 - v3.7.5 */
#define B0_DEY_3_0_SECO		0x0920f7b1	/* v2.6.1 - v3.6.3 */
#define B0_DEY_2_6_r3_SECO	0xce4ef011	/* v2.5.4 */
#define B0_DEY_2_6_r2_SECO	0xe83f52d7
#define B0_DEY_2_6_r1_SECO	0x14955700
#define B0_DEY_2_4_SECO		0x00000006

/**
 * Parse an imx-boot image in memory to try to identify which SOC revision the
 * SECO fw is meant for. Then, compare that revision with the SOC revision on
 * the hardware and print an error if they don't match.
 */
bool validate_bootloader_image(void *loadaddr)
{
	const char *soc_rev;
	char seco_rev;
	u32 *seco_watermark;

	/* Pointer arithmetic adds in increments of 4, so divide offset by 4 */
	seco_watermark = (u32 *)loadaddr + (SECO_CONFIG_HASH_OFFSET / 4);

	switch (*seco_watermark) {
	case C0_DEY_NEXT_SECO:
	case C0_DEY_3_2_SECO:
	case C0_DEY_3_0_r3_SECO:
	case C0_DEY_3_0_SECO:
		seco_rev = 'C';
		break;
	case B0_DEY_NEXT_SECO:
	case B0_DEY_3_0_r3_SECO:
	case B0_DEY_3_0_SECO:
	case B0_DEY_2_6_r3_SECO:
	case B0_DEY_2_6_r2_SECO:
	case B0_DEY_2_6_r1_SECO:
	case B0_DEY_2_4_SECO:
		seco_rev = 'B';
		break;
	default:
		/*
		 * Watermark not recognized, it's likely a newer imx-boot that
		 * can be for either B0 or C0. In this case, print a different
		 * error message with instructions on how to ensure a correct
		 * update.
		 */
		seco_rev = '!';
		break;
	}

	soc_rev = is_soc_rev(CHIP_REV_C) ? "C" : "B";

	if (*soc_rev != seco_rev) {
		if (seco_rev == '!')
			printf("ERROR: the bootloader image has an unknown version of the SECO firmware.\n"
			       "If you're updating to a newer bootloader, make sure it matches your module's SOC revision (%s0).\n",
			       soc_rev);
		else
			printf("ERROR: the bootloader image has %c0 SECO firmware, but the module's SOC revision is %s0.\n"
			       "Proceeding with the update will result in a non-booting device.\n",
			       seco_rev, soc_rev);

		return false;
	}

	return true;
}

__weak void fdt_fixup_soc_revision(void *fdt)
{
	const char *rev = is_soc_rev(CHIP_REV_C) ? "C" : "B";

	do_fixup_by_path(fdt, "/cpus/", "rev", rev, strlen(rev) + 1, 1);
}

void fdt_fixup_ccimx8x(void *fdt) {
	fdt_fixup_soc_revision(fdt);
}
