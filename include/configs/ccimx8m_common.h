/*
 * Copyright 2019 Digi International Inc
 * Copyright 2018 NXP
 *
 * SPDX-License-Identifier:	GPL-2.0+
 */

#ifndef __CCIMX8M_COMMON_H
#define __CCIMX8M_COMMON_H

#include <asm/arch/imx-regs.h>
#include "digi_common.h"		/* Load Digi common stuff... */

#define CONFIG_CC8
#define CONFIG_CC8M
#define CONFIG_DISPLAY_BOARDINFO_LATE

#define CONFIG_SPL_MAX_SIZE		(208 * 1024)
#define CONFIG_SYS_MONITOR_LEN		(512 * 1024)
#define CONFIG_SYS_MMCSD_RAW_MODE_U_BOOT_USE_SECTOR
#define CONFIG_SYS_MMCSD_RAW_MODE_U_BOOT_SECTOR	0x300
#define CONFIG_SYS_MMCSD_FS_BOOT_PARTITION	1
#define CONFIG_SYS_UBOOT_BASE		(QSPI0_AMBA_BASE + CONFIG_SYS_MMCSD_RAW_MODE_U_BOOT_SECTOR * 512)

#ifdef CONFIG_SPL_BUILD
#define CONFIG_SPL_ABORT_ON_RAW_IMAGE /* For RAW image gives a error info not panic */

/* PMIC */
#define CONFIG_POWER
#define CONFIG_POWER_I2C
#define CONFIG_POWER_BD71837
#define CONFIG_POWER_PCA9450

#define CONFIG_SYS_I2C

#endif

#define CONFIG_SERIAL_TAG
#define CONFIG_FASTBOOT_USB_DEV 0

#define CONFIG_REMAKE_ELF

/* HWID */
#define CONFIG_HAS_HWID
#define CONFIG_HWID_BANK		9
#define CONFIG_HWID_START_WORD		0
#define CONFIG_HWID_WORDS_NUMBER	3
#define CONFIG_HWID_LOCK_FUSE		(0x1 << 14)

/* Lock Fuses */
#define OCOTP_LOCK_BANK		0
#define OCOTP_LOCK_WORD		0

/* MCA */
#define CONFIG_MCA_I2C_BUS		0
#define CONFIG_MCA_I2C_ADDR		0x63
#define CONFIG_MCA_OFFSET_LEN           2
#define BOARD_MCA_DEVICE_ID		0x4A

/* Ethernet */
#define WIRED_NICS			1

/* Supported sources for update|dboot */
#define CONFIG_SUPPORTED_SOURCES	((1 << SRC_TFTP) | \
					 (1 << SRC_NFS) | \
					 (1 << SRC_MMC) | \
					 (1 << SRC_USB) | \
					 (1 << SRC_RAM))
#define CONFIG_SUPPORTED_SOURCES_NET	"tftp|nfs"
#define CONFIG_SUPPORTED_SOURCES_BLOCK	"mmc|usb"
#define CONFIG_SUPPORTED_SOURCES_RAM	"ram"

/* Digi boot command 'dboot' */
#define CONFIG_CMD_DBOOT

#define CONFIG_DBOOT_SUPPORTED_SOURCES_LIST	\
	CONFIG_SUPPORTED_SOURCES_NET "|" \
	CONFIG_SUPPORTED_SOURCES_BLOCK
#define CONFIG_DBOOT_SUPPORTED_SOURCES_ARGS_HELP	\
	DIGICMD_DBOOT_NET_ARGS_HELP "\n" \
	DIGICMD_DBOOT_BLOCK_ARGS_HELP

/* SUPPORT UPDATE */
#define CONFIG_TFTP_UPDATE_ONTHEFLY      /* support to tftp and update on-the-fly */

/* Firmware update */
#define CONFIG_CMD_UPDATE_MMC
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
/* On the fly update chunk (must be a multiple of mmc block size) */
#define CONFIG_OTF_CHUNK		(32 * 1024 * 1024)

/* Link Definitions */
#define CONFIG_LOADADDR			0x40480000
#define CONFIG_SYS_LOAD_ADDR           CONFIG_LOADADDR
#define CONFIG_DIGI_LZIPADDR		0x44000000
#define CONFIG_DIGI_UPDATE_ADDR		0x50000000

#define CONFIG_SYS_INIT_RAM_ADDR        0x40000000
#define CONFIG_SYS_INIT_RAM_SIZE        0x80000
#define CONFIG_SYS_INIT_SP_OFFSET \
        (CONFIG_SYS_INIT_RAM_SIZE - GENERATED_GBL_DATA_SIZE)
#define CONFIG_SYS_INIT_SP_ADDR \
        (CONFIG_SYS_INIT_RAM_ADDR + CONFIG_SYS_INIT_SP_OFFSET)

/* RAM memory reserved for U-Boot, stack, malloc pool... */
#define CONFIG_UBOOT_RESERVED		(10 * 1024 * 1024)


#define CONFIG_SYS_STORAGE_MEDIA       "mmc"
#define CONFIG_SYS_MMC_ENV_DEV		0   /* USDHC3 */
#define CONFIG_SYS_MMC_ENV_PART		2   /* Boot2 partition of eMMC */

/* MMC device and partition where U-Boot image is */
#define EMMC_BOOT_ACK			1
#define EMMC_BOOT_DEV			0
#define EMMC_BOOT_PART			1

/* Size of malloc() pool */
#define CONFIG_SYS_MALLOC_LEN		SZ_32M

#define CONFIG_SYS_SDRAM_BASE           0x40000000
#define PHYS_SDRAM                      0x40000000

#define CONFIG_SYS_MEMTEST_START    PHYS_SDRAM
#define CONFIG_SYS_MEMTEST_END      (CONFIG_SYS_MEMTEST_START + (PHYS_SDRAM_SIZE >> 1))

/* Monitor Command Prompt */
#define CONFIG_SYS_PROMPT_HUSH_PS2     "> "
#define CONFIG_SYS_CBSIZE              2048

#define CONFIG_IMX_BOOTAUX

/* Tamper */
#define CONFIG_MCA_TAMPER

/*
 * Trustfence configs
 */
#define CONFIG_HAS_TRUSTFENCE

/* Secure boot configs */
#define CONFIG_TRUSTFENCE_SRK_N_REVOKE_KEYS		3
#define CONFIG_TRUSTFENCE_SRK_REVOKE_BANK		9
#define CONFIG_TRUSTFENCE_SRK_REVOKE_WORD		3
#define CONFIG_TRUSTFENCE_SRK_REVOKE_MASK		0x7
#define CONFIG_TRUSTFENCE_SRK_REVOKE_OFFSET		0

#define CONFIG_TRUSTFENCE_SRK_BANK			6 /* Bank 6: Words 0-3 */
#define CONFIG_TRUSTFENCE_SRK_WORDS			8 /* Bank 7: Words 0-3 */
#define CONFIG_TRUSTFENCE_SRK_WORDS_PER_BANK		4
#define CONFIG_TRUSTFENCE_SRK_WORDS_OFFSET    		0

#define CONFIG_TRUSTFENCE_SRK_OTP_LOCK_BANK		0
#define CONFIG_TRUSTFENCE_SRK_OTP_LOCK_WORD		0
#define CONFIG_TRUSTFENCE_SRK_OTP_LOCK_OFFSET		9

#define CONFIG_TRUSTFENCE_CLOSE_BIT_BANK		1
#define CONFIG_TRUSTFENCE_CLOSE_BIT_WORD		3
#define CONFIG_TRUSTFENCE_CLOSE_BIT_OFFSET		25

#define CONFIG_TRUSTFENCE_DIRBTDIS_BANK			1
#define CONFIG_TRUSTFENCE_DIRBTDIS_WORD			3
#define CONFIG_TRUSTFENCE_DIRBTDIS_OFFSET		27

/* Secure JTAG configs */
#define CONFIG_TRUSTFENCE_JTAG_MODE_BANK		1
#define CONFIG_TRUSTFENCE_JTAG_MODE_START_WORD		3
#define CONFIG_TRUSTFENCE_JTAG_MODE_WORDS_NUMBER	1
#define CONFIG_TRUSTFENCE_JTAG_KEY_BANK			8
#define CONFIG_TRUSTFENCE_JTAG_KEY_START_WORD		0
#define CONFIG_TRUSTFENCE_JTAG_KEY_WORDS_NUMBER		2
#define CONFIG_TRUSTFENCE_JTAG_LOCK_FUSE		(1 << 2)
#define CONFIG_TRUSTFENCE_JTAG_KEY_LOCK_FUSE		(1 << 10)

#define TRUSTFENCE_JTAG_DISABLE_OFFSET			21
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
#define CONFIG_SUPPORT_EMMC_BOOT	/* eMMC specific */
#define CONFIG_SUPPORT_MMC_ECSD
#define CONFIG_SYS_MMC_IMG_LOAD_PART	1

#define CONFIG_SYS_I2C_SPEED		100000

/* USB configs */
#ifndef CONFIG_SPL_BUILD
#define CONFIG_USBD_HS
#endif

#define CONFIG_USB_GADGET_VBUS_DRAW 2

#define CONFIG_MXC_USB_PORTSC  (PORT_PTS_UTMI | PORT_PTS_PTW)
#define CONFIG_USB_MAX_CONTROLLER_COUNT         2

#ifdef CONFIG_DM_VIDEO
#define CONFIG_VIDEO_MXS
#define CONFIG_VIDEO_LOGO
#define CONFIG_SPLASH_SCREEN
#define CONFIG_SPLASH_SCREEN_ALIGN
#define CONFIG_CMD_BMP
#define CONFIG_BMP_16BPP
#define CONFIG_BMP_24BPP
#define CONFIG_BMP_32BPP
#define CONFIG_VIDEO_BMP_RLE8
#define CONFIG_VIDEO_BMP_LOGO
#endif

#define ALTBOOTCMD	\
	"altbootcmd=" \
	"if load mmc ${mmcbootdev}:${mmcpart} ${loadaddr} altboot.scr; then " \
		"source ${loadaddr};" \
	"fi;\0"

/* Pool of randomly generated UUIDs at host machine */
#define RANDOM_UUIDS	\
	"uuid_disk=075e2a9b-6af6-448c-a52a-3a6e69f0afff\0" \
	"part1_uuid=43f1961b-ce4c-4e6c-8f22-2230c5d532bd\0" \
	"part2_uuid=f241b915-4241-47fd-b4de-ab5af832a0f6\0" \
	"part3_uuid=1c606ef5-f1ac-43b9-9bb5-d5c578580b6b\0" \
	"part4_uuid=c7d8648b-76f7-4e2b-b829-e95a83cc7b32\0" \
	"part5_uuid=ebae5694-6e56-497c-83c6-c4455e12d727\0" \
	"part6_uuid=3845c9fc-e581-49f3-999f-86c9bab515ef\0" \
	"part7_uuid=3fcf7bf1-b6fe-419d-9a14-f87950727bc0\0" \
	"part8_uuid=12c08a28-fb40-430a-a5bc-7b4f015b0b3c\0" \
	"part9_uuid=dc83dea8-c467-45dc-84eb-5e913daec17e\0" \
	"part10_uuid=df0dba76-d5e0-11e8-9f8b-f2801f1b9fd1\0"

#define LINUX_4GB_PARTITION_TABLE \
	"\"uuid_disk=${uuid_disk};" \
	"start=2MiB," \
	"name=linux,size=64MiB,uuid=${part1_uuid};" \
	"name=recovery,size=64MiB,uuid=${part2_uuid};" \
	"name=rootfs,size=1536MiB,uuid=${part3_uuid};" \
	"name=update,size=1536MiB,uuid=${part4_uuid};" \
	"name=safe,size=16MiB,uuid=${part5_uuid};" \
	"name=safe2,size=16MiB,uuid=${part6_uuid};" \
	"name=data,size=-,uuid=${part7_uuid};" \
	"\""

#define LINUX_8GB_PARTITION_TABLE \
	"\"uuid_disk=${uuid_disk};" \
	"start=2MiB," \
	"name=linux,size=64MiB,uuid=${part1_uuid};" \
	"name=recovery,size=64MiB,uuid=${part2_uuid};" \
	"name=rootfs,size=3GiB,uuid=${part3_uuid};" \
	"name=update,size=3GiB,uuid=${part4_uuid};" \
	"name=safe,size=16MiB,uuid=${part5_uuid};" \
	"name=safe2,size=16MiB,uuid=${part6_uuid};" \
	"name=data,size=-,uuid=${part7_uuid};" \
	"\""

#define LINUX_16GB_PARTITION_TABLE \
	"\"uuid_disk=${uuid_disk};" \
	"start=2MiB," \
	"name=linux,size=64MiB,uuid=${part1_uuid};" \
	"name=recovery,size=64MiB,uuid=${part2_uuid};" \
	"name=rootfs,size=7GiB,uuid=${part3_uuid};" \
	"name=update,size=7GiB,uuid=${part4_uuid};" \
	"name=safe,size=16MiB,uuid=${part5_uuid};" \
	"name=safe2,size=16MiB,uuid=${part6_uuid};" \
	"name=data,size=-,uuid=${part7_uuid};" \
	"\""

#define ANDROID_4GB_PARTITION_TABLE \
	"\"uuid_disk=${uuid_disk};" \
	"start=2MiB," \
	"name=boot,size=32MiB,uuid=${part1_uuid};" \
	"name=recovery,size=32MiB,uuid=${part2_uuid};" \
	"name=system,size=1024MiB,uuid=${part3_uuid};" \
	"name=cache,size=1024MiB,uuid=${part4_uuid};" \
	"name=vendor,size=112MiB,uuid=${part5_uuid};" \
	"name=datafooter,size=16MiB,uuid=${part6_uuid};" \
	"name=safe,size=16MiB,uuid=${part7_uuid};" \
	"name=frp,size=1MiB,uuid=${part8_uuid};" \
	"name=metadata,size=16MiB,uuid=${part9_uuid};" \
	"name=userdata,size=-,uuid=${part10_uuid};" \
	"\""

#define ANDROID_8GB_PARTITION_TABLE \
	"\"uuid_disk=${uuid_disk};" \
	"start=2MiB," \
	"name=boot,size=32MiB,uuid=${part1_uuid};" \
	"name=recovery,size=32MiB,uuid=${part2_uuid};" \
	"name=system,size=2GiB,uuid=${part3_uuid};" \
	"name=cache,size=2GiB,uuid=${part4_uuid};" \
	"name=vendor,size=112MiB,uuid=${part5_uuid};" \
	"name=datafooter,size=16MiB,uuid=${part6_uuid};" \
	"name=safe,size=16MiB,uuid=${part7_uuid};" \
	"name=frp,size=1MiB,uuid=${part8_uuid};" \
	"name=metadata,size=16MiB,uuid=${part9_uuid};" \
	"name=userdata,size=-,uuid=${part10_uuid};" \
	"\""

#define ANDROID_16GB_PARTITION_TABLE \
	"\"uuid_disk=${uuid_disk};" \
	"start=2MiB," \
	"name=boot,size=32MiB,uuid=${part1_uuid};" \
	"name=recovery,size=32MiB,uuid=${part2_uuid};" \
	"name=system,size=2GiB,uuid=${part3_uuid};" \
	"name=cache,size=2GiB,uuid=${part4_uuid};" \
	"name=vendor,size=112MiB,uuid=${part5_uuid};" \
	"name=datafooter,size=16MiB,uuid=${part6_uuid};" \
	"name=safe,size=16MiB,uuid=${part7_uuid};" \
	"name=frp,size=1MiB,uuid=${part8_uuid};" \
	"name=metadata,size=16MiB,uuid=${part9_uuid};" \
	"name=userdata,size=-,uuid=${part10_uuid};" \
	"\""

#define LINUX_DUALBOOT_4GB_PARTITION_TABLE \
	"\"uuid_disk=${uuid_disk};" \
	"start=2MiB," \
	"name=linux_a,size=64MiB,uuid=${part1_uuid};" \
	"name=linux_b,size=64MiB,uuid=${part2_uuid};" \
	"name=rootfs_a,size=1536MiB,uuid=${part3_uuid};" \
	"name=rootfs_b,size=1536MiB,uuid=${part4_uuid};" \
	"name=safe,size=16MiB,uuid=${part5_uuid};" \
	"name=safe2,size=16MiB,uuid=${part6_uuid};" \
	"name=data,size=-,uuid=${part7_uuid};" \
	"\""

#define LINUX_DUALBOOT_8GB_PARTITION_TABLE \
	"\"uuid_disk=${uuid_disk};" \
	"start=2MiB," \
	"name=linux_a,size=64MiB,uuid=${part1_uuid};" \
	"name=linux_b,size=64MiB,uuid=${part2_uuid};" \
	"name=rootfs_a,size=3GiB,uuid=${part3_uuid};" \
	"name=rootfs_b,size=3GiB,uuid=${part4_uuid};" \
	"name=safe,size=16MiB,uuid=${part5_uuid};" \
	"name=safe2,size=16MiB,uuid=${part6_uuid};" \
	"name=data,size=-,uuid=${part7_uuid};" \
	"\""

#define LINUX_DUALBOOT_16GB_PARTITION_TABLE \
	"\"uuid_disk=${uuid_disk};" \
	"start=2MiB," \
	"name=linux_a,size=64MiB,uuid=${part1_uuid};" \
	"name=linux_b,size=64MiB,uuid=${part2_uuid};" \
	"name=rootfs_a,size=7GiB,uuid=${part3_uuid};" \
	"name=rootfs_b,size=7GiB,uuid=${part4_uuid};" \
	"name=safe,size=16MiB,uuid=${part5_uuid};" \
	"name=safe2,size=16MiB,uuid=${part6_uuid};" \
	"name=data,size=-,uuid=${part7_uuid};" \
	"\""

/* Partition defines */
#define CONFIG_RECOVERY_PARTITION	"2"

/* protected environment variables (besides ethaddr and serial#) */
#define CONFIG_ENV_FLAGS_LIST_STATIC	\
	"wlanaddr:mc,"			\
	"wlan1addr:mc,"			\
	"wlan2addr:mc,"			\
	"wlan3addr:mc,"			\
	"btaddr:mc,"			\
	"bootargs_once:sr,"		\
	"board_version:so,"		\
	"board_id:so,"			\
	"mmcbootdev:so"

#define FSL_FASTBOOT_FB_DEV "mmc"

#endif /* __CCIMX8M_COMMON_H */
