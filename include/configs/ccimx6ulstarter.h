/*
 * Copyright (C) 2016-2024, Digi International Inc.
 * Copyright (C) 2015 Freescale Semiconductor, Inc.
 *
 * Configuration settings for the Digi ConnecCore 6UL Starter board.
 *
 * SPDX-License-Identifier:	GPL-2.0+
 */
#ifndef CCIMX6ULSTARTER_CONFIG_H
#define CCIMX6ULSTARTER_CONFIG_H

#include "ccimx6ul_common.h"

#define CONFIG_BOARD_DESCRIPTION	"SBC Express"

/* MMC Configs */
#ifdef CONFIG_FSL_USDHC
#define CFG_SYS_FSL_ESDHC_ADDR	USDHC2_BASE_ADDR
#define CFG_SYS_FSL_USDHC_NUM	1
#endif

/* U-Boot Environment */
#if defined(CONFIG_ENV_IS_IN_MMC)
#undef CONFIG_ENV_SIZE
#undef CONFIG_ENV_OFFSET
#define CONFIG_ENV_SIZE			SZ_16K
#define CONFIG_ENV_OFFSET		(8 * SZ_64K)
#elif defined(CONFIG_ENV_IS_IN_SPI_FLASH)
#undef CONFIG_ENV_SIZE
#undef CONFIG_ENV_OFFSET
#define CONFIG_ENV_SIZE			SZ_16K
#define CONFIG_ENV_OFFSET		(768 * 1024)
#define CONFIG_ENV_SPI_BUS		CONFIG_SF_DEFAULT_BUS
#define CONFIG_ENV_SPI_CS		CONFIG_SF_DEFAULT_CS
#define CONFIG_ENV_SPI_MODE		CONFIG_SF_DEFAULT_MODE
#define CONFIG_ENV_SPI_MAX_HZ		CONFIG_SF_DEFAULT_SPEED
#endif
#define CONFIG_DYNAMIC_ENV_LOCATION

/* Serial port */
#define CFG_MXC_UART_BASE		UART5_BASE
#define CONSOLE_DEV			"ttymxc4"

#define CONFIG_COMMON_ENV	\
	CONFIG_DEFAULT_NETWORK_SETTINGS \
	CONFIG_EXTRA_NETWORK_SETTINGS \
	ALTBOOTCMD \
	"bootcmd_mfg=fastboot " __stringify(CONFIG_FASTBOOT_USB_DEV) "\0" \
	"dualboot=no\0" \
	"boot_fdt=yes\0" \
	"bootargs_mmc_linux=setenv bootargs console=${console},${baudrate} " \
		"${bootargs_linux} root=${mmcroot} ${mtdparts}" \
		"${bootargs_once} ${extra_bootargs}\0" \
	"bootargs_nfs=" \
		"if test ${ip_dyn} = yes; then " \
			"bootargs_ip=\"ip=dhcp\";" \
		"else " \
			"bootargs_ip=\"ip=\\${ipaddr}:\\${serverip}:" \
			"\\${gatewayip}:\\${netmask}:\\${hostname}:" \
			"eth0:off\";" \
		"fi;\0" \
	"bootargs_nfs_linux=run bootargs_nfs;" \
		"setenv bootargs console=${console},${baudrate} " \
		"${bootargs_linux} root=/dev/nfs " \
		"${bootargs_ip} nfsroot=${serverip}:${rootpath},v3,tcp " \
		"${mtdparts} ${bootargs_once} ${extra_bootargs}\0" \
	"bootargs_tftp=" \
		"if test ${ip_dyn} = yes; then " \
			"bootargs_ip=\"ip=dhcp\";" \
		"else " \
			"bootargs_ip=\"ip=\\${ipaddr}:\\${serverip}:" \
			"\\${gatewayip}:\\${netmask}:\\${hostname}:" \
			"eth0:off\";" \
		"fi;\0" \
	"bootargs_tftp_linux=run bootargs_tftp;" \
		"setenv bootargs console=${console},${baudrate} " \
		"${bootargs_linux} root=/dev/nfs " \
		"${bootargs_ip} nfsroot=${serverip}:${rootpath},v3,tcp " \
		"${mtdparts} ${bootargs_once} ${extra_bootargs}\0" \
	"console=" CONSOLE_DEV "\0" \
	"dboot_kernel_var=zimage\0" \
	"fdt_addr=0x83000000\0" \
	"fdt_file=" CONFIG_DEFAULT_FDT_FILE "\0" \
	"fdt_high=0xffffffff\0"	  \
	"initrd_addr=0x83800000\0" \
	"initrd_file=uramdisk.img\0" \
	"initrd_high=0xffffffff\0" \
	"update_addr=" __stringify(CONFIG_DIGI_UPDATE_ADDR) "\0" \
	"mmcroot=/dev/mmcblk1p2 rootwait rw\0" \
	"recovery_file=recovery.img\0" \
	"script=boot.scr\0" \
	"uboot_file=u-boot.imx\0" \
	"zimage=zImage-" CONFIG_SYS_BOARD ".bin\0"

#if defined(CONFIG_NAND_BOOT)

#define ROOTARGS_SINGLEMTDSYSTEM_UBIFS \
	"ubi.mtd=" SYSTEM_PARTITION " " \
	"root=ubi0:${rootfsvol} " \
	"rootfstype=ubifs rw"
#define ROOTARGS_MULTIMTDSYSTEM_UBIFS \
	"ubi.mtd=${mtdbootpart} " \
	"ubi.mtd=${mtdrootfspart} " \
	"root=ubi1:${rootfsvol} " \
	"rootfstype=ubifs rw"
#define ROOTARGS_SINGLEMTDSYSTEM_SQUASHFS \
	"ubi.mtd=" SYSTEM_PARTITION " " \
	"ubi.block=0,2 root=/dev/ubiblock0_2 " \
	"rootfstype=squashfs ro"
#define ROOTARGS_MULTIMTDSYSTEM_SQUASHFS \
	"ubi.mtd=${mtdbootpart} " \
	"ubi.mtd=${mtdrootfspart} " \
	"ubi.block=1,0 root=/dev/ubiblock1_0 " \
	"rootfstype=squashfs ro"

#define MTDPART_ENV_SETTINGS \
	"mtdbootpart=" LINUX_PARTITION "\0" \
	"mtdrootfspart=" ROOTFS_PARTITION "\0" \
	"singlemtdsys=no\0" \
	"rootfsvol=" ROOTFS_PARTITION "\0" \
	"bootargs_nand_linux=" \
		"if test \"${singlemtdsys}\" = yes; then " \
			"if test \"${rootfstype}\" = squashfs; then " \
				"setenv rootargs " ROOTARGS_SINGLEMTDSYSTEM_SQUASHFS ";" \
			"else " \
				"setenv rootargs " ROOTARGS_SINGLEMTDSYSTEM_UBIFS ";" \
			"fi;" \
		"else " \
			"if test \"${rootfstype}\" = squashfs; then " \
				"setenv rootargs " ROOTARGS_MULTIMTDSYSTEM_SQUASHFS ";" \
			"else " \
				"setenv rootargs " ROOTARGS_MULTIMTDSYSTEM_UBIFS ";" \
			"fi;" \
		"fi;" \
		"setenv bootargs console=${console},${baudrate} " \
			"${bootargs_linux} ${mtdparts} " \
			"${rootargs} " \
			"${bootargs_once} ${extra_bootargs};\0" \
	"loadscript=" \
		"if test \"${dualboot}\" = yes; then " \
			"if test -z \"${active_system}\"; then " \
				"setenv active_system " LINUX_A_PARTITION ";" \
			"fi;" \
			"setenv mtdbootpart ${active_system};" \
		"else " \
			"if test -z \"${mtdbootpart}\" || " \
			"   test \"${mtdbootpart}\" = " LINUX_A_PARTITION " || " \
			"   test \"${mtdbootpart}\" = " LINUX_B_PARTITION "; then " \
				"setenv mtdbootpart " LINUX_PARTITION ";" \
			"fi;" \
		"fi;" \
		"if test \"${singlemtdsys}\" = yes; then " \
			"if ubi part " SYSTEM_PARTITION "; then " \
				"if ubifsmount ubi0:${mtdbootpart}; then " \
					"ubifsload ${loadaddr} ${script};" \
				"fi;" \
			"fi;" \
		"else " \
			"if ubi part ${mtdbootpart}; then " \
				"if ubifsmount ubi0:${mtdbootpart}; then " \
					"ubifsload ${loadaddr} ${script};" \
				"fi;" \
			"fi;" \
		"fi;\0" \
	"recoverycmd=" \
		"setenv mtdbootpart " RECOVERY_PARTITION ";" \
		"boot\0"
#define DUALBOOT_ENV_SETTINGS \
	"linux_a=" LINUX_A_PARTITION "\0" \
	"linux_b=" LINUX_B_PARTITION "\0" \
	"rootfsvol_a=" ROOTFS_A_PARTITION "\0" \
	"rootfsvol_b=" ROOTFS_B_PARTITION "\0" \
	"active_system=" LINUX_A_PARTITION "\0"

#define CFG_EXTRA_ENV_SETTINGS \
	CONFIG_COMMON_ENV \
	CONFIG_ENV_MTD_SETTINGS \
	DUALBOOT_ENV_SETTINGS \
	MTDPART_ENV_SETTINGS \
	"bootargs_linux=\0" \
	"install_linux_fw_sd=if load mmc 0 ${loadaddr} install_linux_fw_sd.scr;then " \
			"source ${loadaddr};" \
		"fi;\0" \
	"install_linux_fw_usb=usb start;" \
		"if load usb 0 ${loadaddr} install_linux_fw_usb.scr;then " \
			"source ${loadaddr};" \
		"fi;\0" \
	"linux_file=core-image-base-" CONFIG_SYS_BOARD ".boot.ubifs\0" \
	"rootfs_file=core-image-base-" CONFIG_SYS_BOARD ".ubifs\0" \
	""	/* end line */
#else
#define CFG_EXTRA_ENV_SETTINGS \
	CONFIG_COMMON_ENV \
	"loadscript=load mmc ${mmcbootdev}:${mmcpart} ${loadaddr} ${script}\0" \
	"mmcdev="__stringify(CONFIG_SYS_MMC_ENV_DEV)"\0" \
	"mmcpart=1\0" \
	"mmcautodetect=yes\0" \
	"mmcargs=setenv bootargs console=${console},${baudrate} " \
		"${mtdparts} " \
		"root=${mmcroot}\0" \
	""	/* end line */
#endif

/* Carrier board version and ID commands */
#define CONFIG_CMD_BOARD_VERSION
#define CONFIG_CMD_BOARD_ID

/* Carrier board version in OTP bits */
#define CONFIG_HAS_CARRIERBOARD_VERSION
#ifdef CONFIG_HAS_CARRIERBOARD_VERSION
/* The carrier board version is stored in Bank 4 Word 6 (GP1)
 * in bits 3..0 */
#define CONFIG_CARRIERBOARD_VERSION_ON_OTP
#define CONFIG_CARRIERBOARD_VERSION_BANK	4
#define CONFIG_CARRIERBOARD_VERSION_WORD	6
#define CONFIG_CARRIERBOARD_VERSION_MASK	0xf
#define CONFIG_CARRIERBOARD_VERSION_OFFSET	0
#endif /* CONFIG_HAS_CARRIERBOARD_VERSION */

/* Carrier board ID in OTP bits */
#define CONFIG_HAS_CARRIERBOARD_ID
#ifdef CONFIG_HAS_CARRIERBOARD_ID
/* The carrier board ID is stored in Bank 4 Word 6 (GP1)
 * in bits 11..4 */
#define CONFIG_CARRIERBOARD_ID_ON_OTP
#define CONFIG_CARRIERBOARD_ID_BANK	4
#define CONFIG_CARRIERBOARD_ID_WORD	6
#define CONFIG_CARRIERBOARD_ID_MASK	0xff
#define CONFIG_CARRIERBOARD_ID_OFFSET	4
#endif /* CONFIG_HAS_CARRIERBOARD_ID */

#endif /* CCIMX6ULSTARTER_CONFIG_H */
