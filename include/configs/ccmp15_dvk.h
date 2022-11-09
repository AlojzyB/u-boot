/* SPDX-License-Identifier: GPL-2.0+ OR BSD-3-Clause */
/*
 * Copyright (C) 2022, Digi International Inc
 * Copyright (C) 2018, STMicroelectronics - All Rights Reserved
 *
 */

#ifndef __CCMP15_DVK_CONFIG_H__
#define __CCMP15_DVK_CONFIG_H__

#include <configs/ccmp1_common.h>

#define CONFIG_SOM_DESCRIPTION		"ConnectCore MP15"
#define CONFIG_BOARD_DESCRIPTION	"Development Kit"
#define BOARD_DEY_NAME			"ccmp15-dvk"

/* Serial */
#define CONSOLE_DEV			"ttySTM0"

#define CONFIG_MMCROOT			"/dev/mmcblk1p2"  /* USDHC2 */

/* Carrier board version in environment */
#define CONFIG_HAS_CARRIERBOARD_VERSION

#define CONFIG_COMMON_ENV	\
	CONFIG_DEFAULT_NETWORK_SETTINGS \
	CONFIG_EXTRA_NETWORK_SETTINGS \
	ALTBOOTCMD \
	"bootcmd_mfg=fastboot " __stringify(CONFIG_FASTBOOT_USB_DEV) "\0" \
	"dualboot=yes\0" \
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
	"fdt_addr=0xc4000000\0" \
	"fdt_file=" CONFIG_DEFAULT_FDT_FILE "\0" \
	"fdt_high=0xffffffff\0"	  \
	"initrd_addr=0xc4400000\0" \
	"initrd_file=uramdisk.img\0" \
	"initrd_high=0xffffffff\0" \
	"update_addr=" __stringify(CONFIG_DIGI_UPDATE_ADDR) "\0" \
	"mmcroot=" CONFIG_MMCROOT " rootwait rw\0" \
	"recovery_file=recovery.img\0" \
	"script=boot.scr\0" \
	"uboot_file=u-boot.imx\0" \
	"zimage=zImage-" BOARD_DEY_NAME ".bin\0"

#define ROOTARGS_UBIFS \
	"ubi.mtd=" SYSTEM_PARTITION " " \
	"root=ubi0:${rootfsvol} " \
	"rootfstype=ubifs rw"
#define ROOTARGS_SQUASHFS \
	"ubi.mtd=" SYSTEM_PARTITION " " \
	"ubi.block=0,2 root=/dev/ubiblock0_2 " \
	"rootfstype=squashfs ro"

#define MTDPART_ENV_SETTINGS \
	"mtdbootpart=" LINUX_A_PARTITION "\0" \
	"rootfsvol=" ROOTFS_A_PARTITION "\0" \
	"bootargs_nand_linux=" \
		"if test \"${rootfstype}\" = squashfs; then " \
			"setenv rootargs " ROOTARGS_SQUASHFS ";" \
		"else " \
			"setenv rootargs " ROOTARGS_UBIFS ";" \
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
		"if ubi part " SYSTEM_PARTITION "; then " \
			"if ubifsmount ubi0:${mtdbootpart}; then " \
				"ubifsload ${loadaddr} ${script};" \
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

/*
 * memory layout for 32M uncompressed/compressed kernel,
 * 1M fdt, 1M script, 1M pxe and 1M for splashimage
 * and the ramdisk at the end.
 */
#define CONFIG_EXTRA_ENV_SETTINGS \
	CONFIG_COMMON_ENV \
	MTDPART_ENV_SETTINGS \
	DUALBOOT_ENV_SETTINGS \
	STM32MP_MEM_LAYOUT \
	BOOTENV \

#undef CONFIG_BOOTCOMMAND
#define CONFIG_BOOTCOMMAND \
	"if run loadscript; then " \
		"source ${loadaddr};" \
	"fi;"

/* UBI volumes layout */
#define UBIVOLS_UBOOTENV		"ubi create uboot_config 20000;" \
					"ubi create uboot_config_r 20000;"

#define UBIVOLS_256MB			"ubi create " LINUX_PARTITION " 1800000;" \
					"ubi create " RECOVERY_PARTITION " 2000000;" \
					"ubi create " ROOTFS_PARTITION " bb00000;" \
					"ubi create " DATA_PARTITION " 500000;" \
					"ubi create update;"

#define UBIVOLS_512MB			"ubi create " LINUX_PARTITION " 1800000;" \
					"ubi create " RECOVERY_PARTITION " 2000000;" \
					"ubi create " ROOTFS_PARTITION " 10000000;" \
					"ubi create " DATA_PARTITION " 2000000;" \
					"ubi create update;"

#define UBIVOLS_DUALBOOT_256MB		"ubi create " LINUX_A_PARTITION " c00000;" \
					"ubi create " LINUX_B_PARTITION " c00000;" \
					"ubi create " ROOTFS_A_PARTITION " 6d80000;" \
					"ubi create " ROOTFS_B_PARTITION " 6d80000;" \
					"ubi create " DATA_PARTITION ";"

#define UBIVOLS_DUALBOOT_512MB		"ubi create " LINUX_A_PARTITION " 1000000;" \
					"ubi create " LINUX_B_PARTITION " 1000000;" \
					"ubi create " ROOTFS_A_PARTITION " dc00000;" \
					"ubi create " ROOTFS_B_PARTITION " dc00000;" \
					"ubi create " DATA_PARTITION ";"

#define CREATE_UBIVOLS_SCRIPT		"ubi detach;" \
					"nand erase.part " SYSTEM_PARTITION ";" \
					"if test $? = 1; then " \
					"	echo \"** Error erasing '" SYSTEM_PARTITION "' partition\";" \
					"else" \
					"	ubi part " SYSTEM_PARTITION ";" \
					"	if test $? = 1; then " \
					"		echo \"Error attaching '" SYSTEM_PARTITION "' partition\";" \
					"	else " \
							UBIVOLS_UBOOTENV \
					"		if test \"${dualboot}\" = yes; then " \
					"			%s" \
					"		else " \
					"			%s" \
					"		fi;" \
					"		saveenv;" \
					"		saveenv;" \
					"	fi;" \
					"fi"

#endif /* __CCMP15_DVK_CONFIG_H__ */
