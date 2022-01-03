/*
 * Copyright (C) 2018-2020 Digi International, Inc.
 * Copyright 2017 NXP
 *
 * SPDX-License-Identifier:	GPL-2.0+
 */
#include <common.h>
#include <cpu.h>
#include <fuse.h>
#include <mmc.h>
#include <fdt_support.h>
#include <dm/device.h>
#include <linux/ctype.h>
#include <linux/sizes.h>
#include <asm/arch/sys_proto.h>
#include <asm/arch-imx/cpu.h>
#include <asm/arch-imx8/sci/sci.h>
#include <asm/mach-imx/boot_mode.h>
#include <stdlib.h>

#include "../common/helper.h"
#include "../common/hwid.h"
#include "../common/mca.h"
#ifdef CONFIG_HAS_TRUSTFENCE
#include "../common/trustfence.h"
#endif
#ifdef CONFIG_AHAB_BOOT
#include <asm/arch-imx8/image.h>
#endif

DECLARE_GLOBAL_DATA_PTR;

extern const char *get_imx8_rev(u32 rev);

int confirm_close(void);

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
};

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
void reset_cpu(ulong addr)
{
	sc_pm_reboot(-1, SC_PM_RESET_TYPE_COLD);
	while(1);
}

void detail_board_ddr_info(void)
{
	puts("\nDDR    ");
}

void calculate_uboot_update_settings(struct blk_desc *mmc_dev,
				     disk_partition_t *info)
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

int close_device(int confirmed_close)
{
	int err;
	uint16_t lc;
	uint8_t idx = 0U;

	if (!confirmed_close && !confirm_close())
		return -EACCES;

	err = sc_seco_chip_info(-1, &lc, NULL, NULL, NULL);
	if (err != SC_ERR_NONE) {
		printf("Error in get lifecycle\n");
		return -EIO;
	}

	if (lc != 0x20) {
		printf("Current lifecycle is NOT NXP closed, can't move to OEM closed (0x%x)\n", lc);
		return -EPERM;
	}

	/* Verifiy that we do not have any AHAB events */
	err = sc_seco_get_event(-1, idx, NULL);
	if (err == SC_ERR_NONE) {
		printf ("SECO Event[%u] - abort closing device.\n", idx);
		return -EIO;
	}

	err = sc_seco_forward_lifecycle(-1, 16);
	if (err != SC_ERR_NONE) {
		printf("Error in forward lifecycle to OEM closed\n");
		return -EIO;
	}

	puts("Closing device...\n");

	return 0;
}

int revoke_keys(void)
{
	int err;

	err = seco_commit(-1, 0x10);
	if (err != SC_ERR_NONE) {
		printf("%s: Error in seco_commit\n", __func__);
		return -EIO;
	}

	return 0;
}

/* Trustfence helper functions */
int trustfence_status(void)
{
	uint8_t idx = 0U;
	int err;

	if (!is_usb_boot())
		printf("* Encrypted U-Boot:\t%s\n", is_uboot_encrypted() ?
				"[YES]" : "[NO]");
	puts("* AHAB events:\t\t");
	err = sc_seco_get_event(-1, idx, NULL);
	if (err == SC_ERR_NONE)
		idx++;
	if (idx == 0)
		puts("[NO ERRORS]\n");
	else
		puts("[ERRORS PRESENT!]\n");

	return err;
}

void board_print_trustfence_jtag_mode(u32 *sjc)
{
	return;
}

void board_print_trustfence_jtag_key(u32 *sjc)
{
	return;
}

#define AHAB_AUTH_CONTAINER_TAG		0x87
#define AHAB_AUTH_BLOB_TAG		0x81
#define AHAB_VERSION			0x00

int get_dek_blob_offset(char *address, u32 *offset)
{
	char *nd_cont_header;
	char *nd_sig_block;
	char *dek_blob;
	int cont_header_offset = 0x400;
	int sig_block_offset;
	int blob_offset;

	/* Second Container Header is set with a 1KB padding */
	nd_cont_header = address + cont_header_offset;
	debug("Second Container Header Address: 0x%lx\n", (long unsigned int)nd_cont_header);

	if (address[0] != AHAB_VERSION || address[3] != AHAB_AUTH_CONTAINER_TAG) {
		debug("Tag does not match as expected\n");
		return -EINVAL;
	}

	sig_block_offset = (((nd_cont_header[13] & 0xff) << 8) | (nd_cont_header[12] & 0xff));
	debug("Signature Block offset is 0x%04x \n", sig_block_offset);
	nd_sig_block = nd_cont_header + sig_block_offset;
	debug("Second Signature Block Address: 0x%lx\n", (long unsigned int)nd_sig_block);

	blob_offset = (((nd_sig_block[11] & 0xff) << 8) | (nd_sig_block[10] & 0xff));
	debug("DEK Blob offset is 0x%04x \n", blob_offset);
	dek_blob = nd_sig_block + blob_offset;
	debug("DEK Blob Address: 0x%lx\n", (long unsigned int)dek_blob);
	*offset = dek_blob - address;

	return 0;
}

int get_dek_blob_size(char *address, u32 *size)
{
	if (address[0] != AHAB_VERSION || address[3] != AHAB_AUTH_BLOB_TAG) {
		debug("Tag does not match as expected\n");
		return -EINVAL;
	}

	*size = (((address[2] & 0xff) << 8) | (address[1] & 0xff));
	debug("DEK blob size is 0x%04x\n", *size);

	return 0;
}

/* Read the SRK Revoke mask from the Container header*/
int get_srk_revoke_mask(u32 *mask)
{
	int ret = CMD_RET_SUCCESS;
	int mmc_dev_index, mmc_part;
	disk_partition_t info;
	struct blk_desc *mmc_dev;
	uint blk_cnt, blk_start;
	char *buffer = NULL;
	struct container_hdr *second_cont;
	u32 buffer_size = 0;

	/* Container Header can only be read from the storage media */
	if (is_usb_boot())
		return CMD_RET_FAILURE;

	/* Obtain storage media settings */
	mmc_dev_index = env_get_ulong("mmcbootdev", 0, mmc_get_bootdevindex());
	if (mmc_dev_index == EMMC_BOOT_DEV) {
		mmc_part = env_get_ulong("mmcbootpart", 0, EMMC_BOOT_PART);
	} else {
		/*
		 * When booting from an SD card there is
		 * a unique hardware partition: 0
		 */
		mmc_part = 0;
	}
	mmc_dev = blk_get_devnum_by_type(IF_TYPE_MMC, mmc_dev_index);
	if (NULL == mmc_dev) {
		debug("Cannot determine sys storage device\n");
		return CMD_RET_FAILURE;
	}
	calculate_uboot_update_settings(mmc_dev, &info);
	blk_start = info.start;
	/* Second Container Header is set with a 1KB padding + 3KB Header info */
	buffer_size = SZ_4K;
	blk_cnt = buffer_size / mmc_dev->blksz;

	/* Initialize boot partition */
	ret = blk_select_hwpart_devnum(IF_TYPE_MMC, mmc_dev_index, mmc_part);
	if (ret != 0) {
		debug("Error to switch to partition %d on dev %d (%d)\n",
			  mmc_part, mmc_dev_index, ret);
		return CMD_RET_FAILURE;
	}

	/* Read from boot media */
	buffer = malloc(roundup(buffer_size, mmc_dev->blksz));
	if (!buffer)
		return -ENOMEM;
	debug("MMC read: dev # %u, block # %u, count %u ...\n",
	       mmc_dev_index, blk_start, blk_cnt);
	if (!blk_dread(mmc_dev, blk_start, blk_cnt, buffer)) {
		ret = CMD_RET_FAILURE;
		goto sanitize;
	}

	/* Read mask from the Second Container Header Flags (11:8) */
	second_cont = (struct container_hdr *)(buffer+CONTAINER_HDR_ALIGNMENT);
	*mask = (second_cont->flags>>8) & 0xF;

sanitize:
	/* Sanitize memory */
	memset(buffer, '\0', sizeof(buffer));
	free(buffer);
	buffer = NULL;

	return ret;
}

int get_dek_blob(char *output, u32 *size)
{
	int ret, mmc_dev_index, mmc_part;
	disk_partition_t info;
	struct blk_desc *mmc_dev;
	uint blk_cnt, blk_start;
	char *buffer = NULL;
	char *dek_blob_src = NULL;
	u32 buffer_size = 0;
	u32 dek_blob_size = 0;
	u32 dek_blob_offset = 0;

	/* Obtain storage media settings */
	mmc_dev_index = env_get_ulong("mmcbootdev", 0, mmc_get_bootdevindex());
	if (mmc_dev_index == EMMC_BOOT_DEV) {
		mmc_part = env_get_ulong("mmcbootpart", 0, EMMC_BOOT_PART);
	} else {
		/*
		 * When booting from an SD card there is
		 * a unique hardware partition: 0
		 */
		mmc_part = 0;
	}
	mmc_dev = blk_get_devnum_by_type(IF_TYPE_MMC, mmc_dev_index);
	if (NULL == mmc_dev) {
		debug("Cannot determine sys storage device\n");
		return CMD_RET_FAILURE;
	}
	calculate_uboot_update_settings(mmc_dev, &info);
	blk_start = info.start;
	/* Second Container Header is set with a 1KB padding + 3KB Header info */
	buffer_size = SZ_4K;
	blk_cnt = buffer_size / mmc_dev->blksz;

	/* Initialize boot partition */
	ret = blk_select_hwpart_devnum(IF_TYPE_MMC, mmc_dev_index, mmc_part);
	if (ret != 0) {
		debug("Error to switch to partition %d on dev %d (%d)\n",
			  mmc_part, mmc_dev_index, ret);
		return CMD_RET_FAILURE;
	}

	/* Read from boot media */
	buffer = malloc(roundup(buffer_size, mmc_dev->blksz));
	if (!buffer)
		return -ENOMEM;
	debug("MMC read: dev # %u, block # %u, count %u ...\n",
	       mmc_dev_index, blk_start, blk_cnt);
	if (!blk_dread(mmc_dev, blk_start, blk_cnt, buffer)) {
		ret = CMD_RET_FAILURE;
		goto sanitize;
	}

	/* Recover DEK blob placed into the Signature Block */
	debug("Recovering DEK blob...\n");
	ret = get_dek_blob_offset(buffer, &dek_blob_offset);
	if (ret != 0) {
		debug("Error getting the DEK Blob offset (%d)\n", ret);
		goto sanitize;
	}

	/* Obtain the DEK Blob size */
	dek_blob_src = buffer + dek_blob_offset;
	ret = get_dek_blob_size(dek_blob_src, &dek_blob_size);
	if (ret != 0) {
		debug("Error getting the DEK Blob size (%d)\n", ret);
		goto sanitize;
	}

	/* Save DEK Blob */
	memcpy(output, dek_blob_src, dek_blob_size);

sanitize:
	/* Sanitize memory */
	memset(buffer, '\0', sizeof(buffer));
	free(buffer);
	buffer = NULL;

	return ret;
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

	soc_rev = get_imx8_rev(get_cpu_rev() & 0xFFF);

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
	const char *rev = get_imx8_rev(get_cpu_rev() & 0xFFF);

	do_fixup_by_path(fdt, "/cpus/", "rev", rev, strlen(rev) + 1, 1);
}

void fdt_fixup_ccimx8x(void *fdt) {
	fdt_fixup_soc_revision(fdt);
}
