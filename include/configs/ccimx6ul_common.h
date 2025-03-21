/*
 * Copyright (C) 2016-2025 Digi International, Inc.
 * Copyright (C) 2015 Freescale Semiconductor, Inc.
 *
 * Configuration settings for the Digi ConnecCore 6UL System-On-Module.
 *
 * SPDX-License-Identifier:	GPL-2.0+
 */
#ifndef CCIMX6UL_CONFIG_H
#define CCIMX6UL_CONFIG_H

#include <asm/arch/imx-regs.h>
#include <asm/mach-imx/gpio.h>
#include <linux/sizes.h>
#include "mx6_common.h"
#include "digi_common.h"		/* Load Digi common stuff... */

#define CONFIG_CC6
#define DIGI_IMX_FAMILY
#define CONFIG_SOM_DESCRIPTION		"ConnectCore 6UL"

/*
 * RAM
 */
/* Physical Memory Map */
#define PHYS_SDRAM			MMDC0_ARB_BASE_ADDR
#define CFG_SYS_SDRAM_BASE		PHYS_SDRAM
#define CFG_SYS_INIT_RAM_ADDR	IRAM_BASE_ADDR
#define CFG_SYS_INIT_RAM_SIZE	IRAM_SIZE

/* NAND stuff */
#define CFG_SYS_NAND_BASE		0x40000000

/* Lock Fuses */
#define OCOTP_LOCK_BANK		0
#define OCOTP_LOCK_WORD		0

/* Digi ConnectCore 6UL carrier board IDs */
#define CCIMX6ULSTARTER_ID129	129
#define CCIMX6ULSBC_ID135	135
#define CCIMX6ULSBC_ID136	136

/* Secure boot configs */
#define CONFIG_TRUSTFENCE_SRK_N_REVOKE_KEYS		3
#define CONFIG_TRUSTFENCE_SRK_REVOKE_BANK		5
#define CONFIG_TRUSTFENCE_SRK_REVOKE_WORD		7
#define CONFIG_TRUSTFENCE_SRK_REVOKE_MASK		0x7
#define CONFIG_TRUSTFENCE_SRK_REVOKE_OFFSET		0

#define CONFIG_TRUSTFENCE_SRK_BANK			3
#define CONFIG_TRUSTFENCE_SRK_WORDS			8
#define CONFIG_TRUSTFENCE_SRK_WORDS_PER_BANK		8
#define CONFIG_TRUSTFENCE_SRK_WORDS_OFFSET		0

#define CONFIG_TRUSTFENCE_SRK_OTP_LOCK_BANK		0
#define CONFIG_TRUSTFENCE_SRK_OTP_LOCK_WORD		0
#define CONFIG_TRUSTFENCE_SRK_OTP_LOCK_OFFSET		14

#define CONFIG_TRUSTFENCE_CLOSE_BIT_BANK		0
#define CONFIG_TRUSTFENCE_CLOSE_BIT_WORD		6
#define CONFIG_TRUSTFENCE_CLOSE_BIT_OFFSET		1

#define CONFIG_TRUSTFENCE_DIRBTDIS_BANK			0
#define CONFIG_TRUSTFENCE_DIRBTDIS_WORD			6
#define CONFIG_TRUSTFENCE_DIRBTDIS_OFFSET		3

/* Secure JTAG configs */
#define CONFIG_TRUSTFENCE_JTAG_MODE_BANK		0
#define CONFIG_TRUSTFENCE_JTAG_MODE_START_WORD		6
#define CONFIG_TRUSTFENCE_JTAG_MODE_WORDS_NUMBER	1
#define CONFIG_TRUSTFENCE_JTAG_KEY_BANK			4
#define CONFIG_TRUSTFENCE_JTAG_KEY_START_WORD		0
#define CONFIG_TRUSTFENCE_JTAG_KEY_WORDS_NUMBER		2
#define CONFIG_TRUSTFENCE_JTAG_LOCK_FUSE		(1 << 2)
#define CONFIG_TRUSTFENCE_JTAG_KEY_LOCK_FUSE		(1 << 6)

#define TRUSTFENCE_JTAG_DISABLE_OFFSET			20
#define TRUSTFENCE_JTAG_SMODE_OFFSET			22

#define TRUSTFENCE_JTAG_DISABLE_JTAG_MASK 		0x01
#define TRUSTFENCE_JTAG_SMODE_MASK 			0x03

#define TRUSTFENCE_JTAG_SMODE_ENABLE 			0x00
#define TRUSTFENCE_JTAG_SMODE_SECURE 			0x01
#define TRUSTFENCE_JTAG_SMODE_NO_DEBUG			0x03

#define TRUSTFENCE_JTAG_DISABLE_JTAG			(0x01 << TRUSTFENCE_JTAG_DISABLE_OFFSET)
#define TRUSTFENCE_JTAG_ENABLE_JTAG 			(TRUSTFENCE_JTAG_SMODE_ENABLE << TRUSTFENCE_JTAG_SMODE_OFFSET)
#define TRUSTFENCE_JTAG_ENABLE_SECURE_JTAG_MODE		(TRUSTFENCE_JTAG_SMODE_SECURE << TRUSTFENCE_JTAG_SMODE_OFFSET)
#define TRUSTFENCE_JTAG_DISABLE_DEBUG			(TRUSTFENCE_JTAG_SMODE_NO_DEBUG << TRUSTFENCE_JTAG_SMODE_OFFSET)

/* MMC Configs */
#define CONFIG_SUPPORT_MMC_ECSD

/* Extra network settings for second Ethernet */
#define CONFIG_EXTRA_NETWORK_SETTINGS \
	"eth1addr=" DEFAULT_MAC_ETHADDR1 "\0"

#undef CFG_ENV_FLAGS_LIST_STATIC
#define CFG_ENV_FLAGS_LIST_STATIC	\
	"eth1addr:mc,"			\
	"wlanaddr:mc,"			\
	"wlan1addr:mc,"			\
	"wlan2addr:mc,"			\
	"wlan3addr:mc,"			\
	"btaddr:mc,"			\
	"bootargs_once:sr,"		\
	"board_version:so,"		\
	"board_id:so,"

/* I2C configs */
#define CONFIG_I2C_MULTI_BUS
#define CONFIG_SYS_I2C_SPEED		100000

/* MCA */
#define BOARD_MCA_DEVICE_ID		0x61

/* USB Configs */
#ifdef CONFIG_CMD_USB
#define CFG_MXC_USB_PORTSC  (PORT_PTS_UTMI | PORT_PTS_PTW)
#define CFG_MXC_USB_FLAGS   0
#endif

/* MTD (NAND) */
#define CONFIG_SKIP_NAND_BBT_SCAN
#define UBOOT_PARTITION			"bootloader"
#define UBOOT_PART_SIZE_SMALL		3
#define UBOOT_PART_SIZE_BIG		5
#define ENV_PART_SIZE_SMALL		1
#define ENV_PART_SIZE_BIG		3

#define LINUX_PARTITION			"linux"
#define RECOVERY_PARTITION		"recovery"
#define ROOTFS_PARTITION		"rootfs"
#define UPDATE_PARTITION		"update"
#define DATA_PARTITION			"data"
#define SYSTEM_PARTITION		"system"

/* Dualboot partition configuration */
#define LINUX_A_PARTITION		"linux_a"
#define LINUX_B_PARTITION		"linux_b"
#define ROOTFS_A_PARTITION		"rootfs_a"
#define ROOTFS_B_PARTITION		"rootfs_b"

#define ALTBOOTCMD	\
	"altbootcmd=" \
		"if test \"${dualboot}\" = yes; then " \
			"if test \"${active_system}\" = linux_a; then " \
				"setenv active_system linux_b;" \
			"else " \
				"setenv active_system linux_a;" \
			"fi;" \
			"saveenv;" \
			"echo \"## System boot failed; Switching active partitions bank to ${active_system}...\";" \
		"fi;" \
		"bootcount reset;" \
		"reset;\0"

/* One 'system' partition containing many UBI volumes (modern layout) */
#define MTDPARTS_SMALL			"mtdparts=" CONFIG_NAND_NAME ":" \
					__stringify(UBOOT_PART_SIZE_SMALL) "m(" UBOOT_PARTITION ")," \
					__stringify(ENV_PART_SIZE_SMALL) "m(environment)," \
					"1m(safe)," \
					"-(" SYSTEM_PARTITION ")"
#define MTDPARTS_BIG			"mtdparts=" CONFIG_NAND_NAME ":" \
					__stringify(UBOOT_PART_SIZE_BIG) "m(" UBOOT_PARTITION ")," \
					__stringify(ENV_PART_SIZE_BIG) "m(environment)," \
					"1m(safe)," \
					"-(" SYSTEM_PARTITION ")"
#define UBIVOLS_256MB			"ubi create " LINUX_PARTITION " 1000000;" \
					"ubi create " RECOVERY_PARTITION " 1400000;" \
					"ubi create " ROOTFS_PARTITION " 8C00000;" \
					"ubi create " UPDATE_PARTITION " 3500000;" \
					"ubi create " DATA_PARTITION ";"
#define UBIVOLS_512MB			"ubi create " LINUX_PARTITION " 1800000;" \
					"ubi create " RECOVERY_PARTITION " 2000000;" \
					"ubi create " ROOTFS_PARTITION " 10000000;" \
					"ubi create " UPDATE_PARTITION " A000000;" \
					"ubi create " DATA_PARTITION ";"
#define UBIVOLS_1024MB			"ubi create " LINUX_PARTITION " 1800000;" \
					"ubi create " RECOVERY_PARTITION " 2000000;" \
					"ubi create " ROOTFS_PARTITION " 20000000;" \
					"ubi create " UPDATE_PARTITION " 18000000;" \
					"ubi create " DATA_PARTITION ";"
#define UBIVOLS_DUALBOOT_256MB		"ubi create " LINUX_A_PARTITION " c00000;" \
					"ubi create " LINUX_B_PARTITION " c00000;" \
					"ubi create " ROOTFS_A_PARTITION " 6900000;" \
					"ubi create " ROOTFS_B_PARTITION " 6900000;" \
					"ubi create " DATA_PARTITION ";"
#define UBIVOLS_DUALBOOT_512MB		"ubi create " LINUX_A_PARTITION " 4000000;" \
					"ubi create " LINUX_B_PARTITION " 4000000;" \
					"ubi create " ROOTFS_A_PARTITION " ac00000;" \
					"ubi create " ROOTFS_B_PARTITION " ac00000;" \
					"ubi create " DATA_PARTITION ";"
#define UBIVOLS_DUALBOOT_1024MB		"ubi create " LINUX_A_PARTITION " 4000000;" \
					"ubi create " LINUX_B_PARTITION " 4000000;" \
					"ubi create " ROOTFS_A_PARTITION " 18000000;" \
					"ubi create " ROOTFS_B_PARTITION " 18000000;" \
					"ubi create " DATA_PARTITION ";"
#define CREATE_UBIVOLS_SCRIPT		"if test \"${singlemtdsys}\" = yes; then " \
						"nand erase.part " SYSTEM_PARTITION ";" \
						"if test $? = 1; then " \
						"	echo \"** Error erasing '" SYSTEM_PARTITION "' partition\";" \
						"else" \
						"	ubi part " SYSTEM_PARTITION ";" \
						"	if test \"${dualboot}\" = yes; then " \
						"		%s" \
						"	else " \
						"		%s" \
						"	fi;" \
						"fi;" \
					"else " \
						"echo \"Set \'singlemtdsys\' to \'yes\' first\";" \
					"fi"

/* One partition for each UBI volume (traditional layout) */
#define MTDPARTS_DUALBOOT_256MB		"mtdparts=" CONFIG_NAND_NAME ":" \
					__stringify(UBOOT_PART_SIZE_SMALL) "m(" UBOOT_PARTITION ")," \
					__stringify(ENV_PART_SIZE_SMALL) "m(environment)," \
					"1m(safe)," \
					"12m(" LINUX_A_PARTITION ")," \
					"12m(" LINUX_B_PARTITION ")," \
					"113m(rootfs_a)," \
					"113m(rootfs_b)," \
					"-(data)"
#define MTDPARTS_DUALBOOT_512MB		"mtdparts=" CONFIG_NAND_NAME ":" \
					__stringify(UBOOT_PART_SIZE_BIG) "m(" UBOOT_PARTITION ")," \
					__stringify(ENV_PART_SIZE_BIG) "m(environment)," \
					"1m(safe)," \
					"24m(" LINUX_A_PARTITION ")," \
					"24m(" LINUX_B_PARTITION ")," \
					"226m(rootfs_a)," \
					"226m(rootfs_b)," \
					"-(data)"
#define MTDPARTS_DUALBOOT_1024MB	"mtdparts=" CONFIG_NAND_NAME ":" \
					__stringify(UBOOT_PART_SIZE_BIG) "m(" UBOOT_PARTITION ")," \
					__stringify(ENV_PART_SIZE_BIG) "m(environment)," \
					"1m(safe)," \
					"46m(" LINUX_A_PARTITION ")," \
					"46m(" LINUX_B_PARTITION ")," \
					"450m(rootfs_a)," \
					"450m(rootfs_b)," \
					"-(data)"

#define MTDPARTS_256MB			"mtdparts=" CONFIG_NAND_NAME ":" \
					__stringify(UBOOT_PART_SIZE_SMALL) "m(" UBOOT_PARTITION ")," \
					__stringify(ENV_PART_SIZE_SMALL) "m(environment)," \
					"1m(safe)," \
					"16m(" LINUX_PARTITION ")," \
					"20m(" RECOVERY_PARTITION ")," \
					"140m(" ROOTFS_PARTITION ")," \
					"70m(update)," \
					"-(data)"
#define MTDPARTS_512MB			"mtdparts=" CONFIG_NAND_NAME ":" \
					__stringify(UBOOT_PART_SIZE_BIG) "m(" UBOOT_PARTITION ")," \
					__stringify(ENV_PART_SIZE_BIG) "m(environment)," \
					"1m(safe)," \
					"24m(" LINUX_PARTITION ")," \
					"32m(" RECOVERY_PARTITION ")," \
					"256m(" ROOTFS_PARTITION ")," \
					"185m(update)," \
					"-(data)"
#define MTDPARTS_1024MB			"mtdparts=" CONFIG_NAND_NAME ":" \
					__stringify(UBOOT_PART_SIZE_BIG) "m(" UBOOT_PARTITION ")," \
					__stringify(ENV_PART_SIZE_BIG) "m(environment)," \
					"1m(safe)," \
					"24m(" LINUX_PARTITION ")," \
					"32m(" RECOVERY_PARTITION ")," \
					"512m(" ROOTFS_PARTITION ")," \
					"440m(update)," \
					"-(data)"
#define CREATE_MTDPARTS_SCRIPT		"if test \"${singlemtdsys}\" = yes; then " \
						"setenv mtdparts %s;" \
					"else " \
						"if test \"${dualboot}\" = yes; then " \
							"setenv mtdparts %s;" \
						"else " \
							"setenv mtdparts %s;" \
						"fi;" \
					"fi"

#define CONFIG_NAND_NAME                "gpmi-nand"
#define CONFIG_ENV_MTD_SETTINGS		"mtdids=" CONFIG_MTDIDS_DEFAULT "\0"
/* Previous offset locations for the environment */
#define OLD_ENV_OFFSET_1		(3 * SZ_1M)
#define OLD_ENV_OFFSET_2		(5 * SZ_1M)
#define OLD_ENV_OFFSET_LOCATIONS	2

/* Max percentage of reserved blocks for bad block management per partition */
#define CONFIG_MTD_UBI_MAXRSVDPEB_PCNT	4

/* Supported sources for update|dboot */
#define CONFIG_SUPPORTED_SOURCES	((1 << SRC_TFTP) | \
					 (1 << SRC_NFS) | \
					 (1 << SRC_MMC) | \
					 (1 << SRC_USB) | \
					 (1 << SRC_NAND) | \
					 (1 << SRC_RAM))
#define CONFIG_SUPPORTED_SOURCES_NET	"tftp|nfs"
#define CONFIG_SUPPORTED_SOURCES_BLOCK	"mmc|usb"
#define CONFIG_SUPPORTED_SOURCES_NAND	"nand"
#define CONFIG_SUPPORTED_SOURCES_RAM	"ram"

/* Digi boot command 'dboot' */
#define CONFIG_DBOOT_SUPPORTED_SOURCES_LIST	\
	CONFIG_SUPPORTED_SOURCES_NET "|" \
	CONFIG_SUPPORTED_SOURCES_NAND "|" \
	CONFIG_SUPPORTED_SOURCES_BLOCK
#define CONFIG_DBOOT_SUPPORTED_SOURCES_ARGS_HELP	\
	DIGICMD_DBOOT_NET_ARGS_HELP "\n" \
	DIGICMD_DBOOT_NAND_ARGS_HELP "\n" \
	DIGICMD_DBOOT_BLOCK_ARGS_HELP

/* Firmware update */
#define CONFIG_UPDATE_SUPPORTED_SOURCES_LIST	\
	CONFIG_SUPPORTED_SOURCES_NET "|" \
	CONFIG_SUPPORTED_SOURCES_BLOCK "|" \
	CONFIG_SUPPORTED_SOURCES_RAM
#define CONFIG_UPDATE_SUPPORTED_SOURCES_ARGS_HELP	\
	DIGICMD_UPDATE_NET_ARGS_HELP "\n" \
	DIGICMD_UPDATE_BLOCK_ARGS_HELP "\n" \
	DIGICMD_UPDATE_RAM_ARGS_HELP
#define CONFIG_UPDATEFILE_SUPPORTED_SOURCES_ARGS_HELP	\
	DIGICMD_UPDATEFILE_NET_ARGS_HELP "\n" \
	DIGICMD_UPDATEFILE_BLOCK_ARGS_HELP "\n" \
	DIGICMD_UPDATEFILE_RAM_ARGS_HELP

/* Miscellaneous configurable options */
#define FSL_FASTBOOT_FB_DEV "nand"

/*
 * 'update' command will Ask for confirmation before updating any partition
 * in this comma-separated list
 */
#define SENSITIVE_PARTITIONS \
	UBOOT_PARTITION "," \
	"environment"

#endif /* CCIMX6UL_CONFIG_H */
