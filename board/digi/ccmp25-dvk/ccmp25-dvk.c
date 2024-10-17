// SPDX-License-Identifier: GPL-2.0-or-later OR BSD-3-Clause
/*
 * Copyright (C) 2022, STMicroelectronics - All Rights Reserved
 * Copyright (C) 2024, Digi International Inc - All Rights Reserved
 */

#define LOG_CATEGORY LOGC_BOARD

#include <common.h>
#include <button.h>
#include <config.h>
#include <dm.h>
#include <efi_loader.h>
#include <env.h>
#include <env_internal.h>
#include <fdt_simplefb.h>
#include <fdt_support.h>
#include <g_dnl.h>
#include <i2c.h>
#include <led.h>
#include <log.h>
#include <misc.h>
#include <mmc.h>
#include <init.h>
#include <net.h>
#include <netdev.h>
#include <phy.h>
#include <regmap.h>
#include <syscon.h>
#include <asm/io.h>
#include <asm/global_data.h>
#include <asm/gpio.h>
#include <asm/arch/sys_proto.h>
#include <dm/device.h>
#include <dm/device-internal.h>
#include <dm/ofnode.h>
#include <dm/uclass.h>
#include <dt-bindings/gpio/gpio.h>
#include <linux/delay.h>
#include <linux/err.h>
#include <linux/iopoll.h>

#include "../ccmp2/ccmp2.h"
#include "../common/carrier_board.h"

unsigned int board_version = CARRIERBOARD_VERSION_UNDEFINED;
unsigned int board_id = CARRIERBOARD_ID_UNDEFINED;

#define SYSCFG_ETHCR_ETH_SEL_MII	0
#define SYSCFG_ETHCR_ETH_SEL_RGMII	BIT(4)
#define SYSCFG_ETHCR_ETH_SEL_RMII	BIT(6)
#define SYSCFG_ETHCR_ETH_CLK_SEL	BIT(1)
#define SYSCFG_ETHCR_ETH_REF_CLK_SEL	BIT(0)
/* CLOCK feed to PHY*/
#define ETH_CK_F_25M	25000000
#define ETH_CK_F_50M	50000000
#define ETH_CK_F_125M	125000000

#if CONFIG_IS_ENABLED(EFI_HAVE_CAPSULE_SUPPORT)
struct efi_fw_image fw_images[1];

struct efi_capsule_update_info update_info = {
	.num_images = ARRAY_SIZE(fw_images),
	.images = fw_images,
};

u8 num_image_type_guids = ARRAY_SIZE(fw_images);
#endif /* EFI_HAVE_CAPSULE_SUPPORT */

/*
 * Get a global data pointer
 */
DECLARE_GLOBAL_DATA_PTR;

int checkboard(void)
{
	board_version = get_carrierboard_version();
	board_id = get_carrierboard_id();

	print_som_info();
	print_carrierboard_info();
	print_bootinfo();

	return 0;
}

#ifdef CONFIG_USB_GADGET_DOWNLOAD
#define STM32MP1_G_DNL_DFU_PRODUCT_NUM 0xdf11
#define STM32MP1_G_DNL_FASTBOOT_PRODUCT_NUM 0x0afb

int g_dnl_bind_fixup(struct usb_device_descriptor *dev, const char *name)
{
	if (IS_ENABLED(CONFIG_DFU_OVER_USB) &&
	    !strcmp(name, "usb_dnl_dfu"))
		put_unaligned(STM32MP1_G_DNL_DFU_PRODUCT_NUM, &dev->idProduct);
	else if (IS_ENABLED(CONFIG_FASTBOOT) &&
		 !strcmp(name, "usb_dnl_fastboot"))
		put_unaligned(STM32MP1_G_DNL_FASTBOOT_PRODUCT_NUM,
			      &dev->idProduct);
	else
		put_unaligned(CONFIG_USB_GADGET_PRODUCT_NUM, &dev->idProduct);

	return 0;
}
#endif /* CONFIG_USB_GADGET_DOWNLOAD */

/* board dependent setup after realloc */
int board_init(void)
{
#if CONFIG_IS_ENABLED(EFI_HAVE_CAPSULE_SUPPORT)
	efi_guid_t image_type_guid = STM32MP_FIP_IMAGE_GUID;

	guidcpy(&fw_images[0].image_type_id, &image_type_guid);
	fw_images[0].fw_name = u"STM32MP-FIP";
	fw_images[0].image_index = 1;
#endif

	/* SOM init */
	ccmp2_init();

	return 0;
}

/* eth init function : weak called in eqos driver */
int board_interface_eth_init(struct udevice *dev,
			     phy_interface_t interface_type, ulong rate)
{
	struct regmap *regmap;
	uint regmap_mask, regmap_offset;
	int ret;
	u32 value;
	bool ext_phyclk;

	/* Ethernet PHY have no cristal or need to be clock by RCC */
	ext_phyclk = dev_read_bool(dev, "st,ext-phyclk");

	regmap = syscon_regmap_lookup_by_phandle(dev,"st,syscon");

	if (!IS_ERR(regmap)) {
		u32 fmp[3];

		ret = dev_read_u32_array(dev, "st,syscon", fmp, 3);
		if (ret) {
			pr_err("%s: Need to specify Offset and Mask of syscon register\n", __func__);
			return ret;
		}
		else {
			regmap_mask = fmp[2];
			regmap_offset = fmp[1];
		}
	} else
		return -ENODEV;

	switch (interface_type) {
	case PHY_INTERFACE_MODE_MII:
		value = SYSCFG_ETHCR_ETH_SEL_MII;
		debug("%s: PHY_INTERFACE_MODE_MII\n", __func__);
		break;
	case PHY_INTERFACE_MODE_RMII:
		if ((rate == ETH_CK_F_50M) && ext_phyclk)
			value = SYSCFG_ETHCR_ETH_SEL_RMII |
				SYSCFG_ETHCR_ETH_REF_CLK_SEL;
		else
			value = SYSCFG_ETHCR_ETH_SEL_RMII;
		debug("%s: PHY_INTERFACE_MODE_RMII\n", __func__);
		break;
	case PHY_INTERFACE_MODE_RGMII:
	case PHY_INTERFACE_MODE_RGMII_ID:
	case PHY_INTERFACE_MODE_RGMII_RXID:
	case PHY_INTERFACE_MODE_RGMII_TXID:
		if ((rate == ETH_CK_F_125M) && ext_phyclk)
			value = SYSCFG_ETHCR_ETH_SEL_RGMII |
				SYSCFG_ETHCR_ETH_CLK_SEL;
		else
			value = SYSCFG_ETHCR_ETH_SEL_RGMII;
		debug("%s: PHY_INTERFACE_MODE_RGMII\n", __func__);
		break;
	default:
		debug("%s: Do not manage %d interface\n",
		      __func__, interface_type);
		/* Do not manage others interfaces */
		return -EINVAL;
	}

	ret = regmap_update_bits(regmap, regmap_offset, regmap_mask, value);

	return ret;
}

int mmc_get_boot(void)
{
	struct udevice *dev;
	u32 boot_mode = get_bootmode();
	unsigned int instance = (boot_mode & TAMP_BOOT_INSTANCE_MASK) - 1;
	char cmd[20];
	const u32 sdmmc_addr[] = {
		STM32_SDMMC1_BASE,
		STM32_SDMMC2_BASE,
		STM32_SDMMC3_BASE
	};

	if (instance > ARRAY_SIZE(sdmmc_addr))
		return 0;

	/* search associated sdmmc node in devicetree */
	snprintf(cmd, sizeof(cmd), "mmc@%x", sdmmc_addr[instance]);
	if (uclass_get_device_by_name(UCLASS_MMC, cmd, &dev)) {
		log_err("mmc%d = %s not found in device tree!\n", instance, cmd);
		return 0;
	}

	return dev_seq(dev);
};

int mmc_get_env_dev(void)
{
	const int mmc_env_dev = CONFIG_IS_ENABLED(ENV_IS_IN_MMC, (CONFIG_SYS_MMC_ENV_DEV), (-1));

	if (mmc_env_dev >= 0)
		return mmc_env_dev;

	/* use boot instance to select the correct mmc device identifier */
	return mmc_get_boot();
}

void platform_default_environment(void)
{
	som_default_environment();
}

int board_late_init(void)
{
	const void *fdt_compat;
	int fdt_compat_len;
	char dtb_name[256];
	int buf_len;

	if (IS_ENABLED(CONFIG_ENV_VARS_UBOOT_RUNTIME_CONFIG)) {
		fdt_compat = fdt_getprop(gd->fdt_blob, 0, "compatible",
					 &fdt_compat_len);
		if (fdt_compat && fdt_compat_len) {
			if (strncmp(fdt_compat, "st,", 3) != 0) {
				env_set("board_name", fdt_compat);
			} else {
				env_set("board_name", fdt_compat + 3);

				buf_len = sizeof(dtb_name);
				strncpy(dtb_name, fdt_compat + 3, buf_len);
				buf_len -= strlen(fdt_compat + 3);
				strncat(dtb_name, ".dtb", buf_len);
				env_set("fdtfile", dtb_name);
			}
		}
	}

	/* Set default dynamic variables */
	platform_default_environment();

	return 0;
}

int ft_board_setup(void *blob, struct bd_info *bd)
{
	fdt_fixup_ccmp2(blob);
	fdt_fixup_carrierboard(blob);
	fdt_copy_fixed_partitions(blob);

	if (CONFIG_IS_ENABLED(FDT_SIMPLEFB))
		fdt_simplefb_enable_and_mem_rsv(blob);

	return 0;
}

#if defined(CONFIG_USB_DWC3) && defined(CONFIG_CMD_STM32PROG_USB)
#include <dfu.h>
/*
 * TEMP: force USB BUS reset forced to false, because it is not supported
 *       in DWC3 USB driver
 * avoid USB bus reset support in DFU stack is required to reenumeration in
 * stm32prog command after flashlayout load or after "dfu-util -e -R"
 */
bool dfu_usb_get_reset(void)
{
	return false;
}
#endif

#if defined(CONFIG_STM32_HYPERBUS)
/* weak function called from common/board_r.c */
int is_flash_available(void)
{
	struct udevice *dev;
	int ret;

	ret = uclass_get_device_by_driver(UCLASS_MTD,
					  DM_DRIVER_GET(stm32_hyperbus),
					  &dev);
	if (ret)
		return 0;

	return 1;
}
#endif

/* weak function called from env/sf.c */
void *env_sf_get_env_addr(void)
{
	return NULL;
}

#if defined(CONFIG_OF_BOARD_FIXUP)

int fdt_update_fwu_properties(void *blob, int nodeoff,
			      const char *compat_str,
			      const char *storage_path)
{
	int ret;
	int storage_off;

	ret = fdt_increase_size(blob, 100);
	if (ret) {
		printf("fdt_increase_size: err=%s\n", fdt_strerror(ret));
		return ret;
	}

	ret = fdt_setprop_string(blob, nodeoff, "compatible", compat_str);
	if (ret) {
		log_err("Can't set compatible property\n");
		return ret;
	}

	storage_off = fdt_path_offset(blob, storage_path);
	if (storage_off < 0) {
		log_err("Can't find %s path\n", storage_path);
		return nodeoff;
	}

	ret = fdt_setprop_string(blob, nodeoff, "fwu-mdata-store", storage_path);

	if (ret < 0)
		log_err("Can't set fwu-mdata-store property\n");

	return ret;
}

int fdt_update_fwu_mdata(void *blob)
{
	int nodeoff, ret = 0;
	u32 bootmode;

	nodeoff = fdt_path_offset(blob, "/fwu-mdata");
	if (nodeoff < 0) {
		log_info("no /fwu-mdata node ?\n");

		return 0;
	}

	bootmode = get_bootmode() & TAMP_BOOT_DEVICE_MASK;

	switch (bootmode) {
	case BOOT_FLASH_SD:
		/* sdmmc1 : nothing to do, already the default device tree configuration */
		break;
	case BOOT_FLASH_EMMC:
		/* sdmmc2 */
		ret = fdt_update_fwu_properties(blob, nodeoff, "u-boot,fwu-mdata-mtd",
						"/soc@0/rifsc@42080000/mmc@48230000");
		break;

	case BOOT_FLASH_SPINAND:
	case BOOT_FLASH_NOR:
		/* flash0 */
		ret = fdt_update_fwu_properties(blob, nodeoff, "u-boot,fwu-mdata-gpt",
						"/soc@0/ommanager@40500000/spi@40430000/flash@0");
		break;
	}

	return ret;
}

int board_fix_fdt(void *blob)
{
	int ret = 0;

	if (CONFIG_IS_ENABLED(FWU_MDATA))
		ret = fdt_update_fwu_mdata(blob);

	return ret;
}
#endif /* CONFIG_OF_BOARD_FIXUP */

