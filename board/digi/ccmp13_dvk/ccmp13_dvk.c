// SPDX-License-Identifier: GPL-2.0+ OR BSD-3-Clause
/*
 * Copyright (C) 2018, STMicroelectronics - All Rights Reserved
 * Copyright (C) 2022, Digi International Inc - All Rights Reserved
 */

#define LOG_CATEGORY LOGC_BOARD

#include <common.h>
#include <adc.h>
#include <bootm.h>
#include <clk.h>
#include <config.h>
#include <dm.h>
#include <env.h>
#include <env_internal.h>
#include <fdt_simplefb.h>
#include <fdt_support.h>
#include <g_dnl.h>
#include <generic-phy.h>
#include <hang.h>
#include <i2c.h>
#include <regmap.h>
#include <init.h>
#include <led.h>
#include <log.h>
#include <malloc.h>
#include <misc.h>
#include <mtd_node.h>
#include <net.h>
#include <netdev.h>
#include <phy.h>
#include <remoteproc.h>
#include <reset.h>
#include <syscon.h>
#include <usb.h>
#include <watchdog.h>
#include <asm/global_data.h>
#include <asm/io.h>
#include <asm/gpio.h>
#include <asm/arch/stm32.h>
#include <asm/arch/sys_proto.h>
#include <configs/digi_common.h>
#include <dm/device.h>
#include <dm/device-internal.h>
#include <jffs2/load_kernel.h>
#include <linux/bitops.h>
#include <linux/delay.h>
#include <linux/err.h>
#include <linux/iopoll.h>
#include <power/regulator.h>
#include <tee/optee.h>
#include <usb/dwc2_udc.h>

#include "../ccmp1/ccmp1.h"

/* SYSCFG registers */
#define SYSCFG_BOOTR		0x00
#define SYSCFG_PMCSETR		0x04
#define SYSCFG_IOCTRLSETR	0x18
#define SYSCFG_ICNR		0x1C
#define SYSCFG_CMPCR		0x20
#define SYSCFG_CMPENSETR	0x24
#define SYSCFG_PMCCLRR		0x08
#define SYSCFG_MP13_PMCCLRR	0x44

#define SYSCFG_BOOTR_BOOT_MASK		GENMASK(2, 0)
#define SYSCFG_BOOTR_BOOTPD_SHIFT	4

#define SYSCFG_IOCTRLSETR_HSLVEN_TRACE		BIT(0)
#define SYSCFG_IOCTRLSETR_HSLVEN_QUADSPI	BIT(1)
#define SYSCFG_IOCTRLSETR_HSLVEN_ETH		BIT(2)
#define SYSCFG_IOCTRLSETR_HSLVEN_SDMMC		BIT(3)
#define SYSCFG_IOCTRLSETR_HSLVEN_SPI		BIT(4)

#define SYSCFG_CMPCR_SW_CTRL		BIT(1)
#define SYSCFG_CMPCR_READY		BIT(8)

#define SYSCFG_CMPENSETR_MPU_EN		BIT(0)

#define GOODIX_REG_ID		0x8140
#define GOODIX_ID_LEN		4

/*
 * Get a global data pointer
 */
DECLARE_GLOBAL_DATA_PTR;

#define USB_LOW_THRESHOLD_UV		200000
#define USB_WARNING_LOW_THRESHOLD_UV	660000
#define USB_START_LOW_THRESHOLD_UV	1230000
#define USB_START_HIGH_THRESHOLD_UV	2150000

int board_early_init_f(void)
{
	/* nothing to do, only used in SPL */
	return 0;
}

int checkboard(void)
{
	int ret;
	char *mode;
	u32 otp;
	struct udevice *dev;
	const char *fdt_compat;
	int fdt_compat_len;

	if (IS_ENABLED(CONFIG_TFABOOT)) {
		if (IS_ENABLED(CONFIG_STM32MP15x_STM32IMAGE))
			mode = "trusted - stm32image";
		else
			mode = "trusted";
	} else {
		mode = "basic";
	}

	fdt_compat = fdt_getprop(gd->fdt_blob, 0, "compatible",
				 &fdt_compat_len);

	log_info("Board: %s in %s mode (%s)\n", CONFIG_SYS_BOARD, mode,
		 fdt_compat && fdt_compat_len ? fdt_compat : "");

	/* display the STMicroelectronics board identification */
	if (CONFIG_IS_ENABLED(CMD_STBOARD)) {
		ret = uclass_get_device_by_driver(UCLASS_MISC,
						  DM_DRIVER_GET(stm32mp_bsec),
						  &dev);
		if (!ret)
			ret = misc_read(dev, STM32_BSEC_SHADOW(BSEC_OTP_BOARD),
					&otp, sizeof(otp));
		if (ret > 0 && otp)
			log_info("Board: MB%04x Var%d.%d Rev.%c-%02d\n",
				 otp >> 16,
				 (otp >> 12) & 0xF,
				 (otp >> 4) & 0xF,
				 ((otp >> 8) & 0xF) - 1 + 'A',
				 otp & 0xF);
	}

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

static int get_led(struct udevice **dev, char *led_string)
{
	char *led_name;
	int ret;

	led_name = fdtdec_get_config_string(gd->fdt_blob, led_string);
	if (!led_name) {
		log_debug("could not find %s config string\n", led_string);
		return -ENOENT;
	}
	ret = led_get_by_label(led_name, dev);
	if (ret) {
		log_debug("get=%d\n", ret);
		return ret;
	}

	return 0;
}

static int setup_led(enum led_state_t cmd)
{
	struct udevice *dev;
	int ret;

	if (!CONFIG_IS_ENABLED(LED))
		return 0;

	ret = get_led(&dev, "u-boot,boot-led");
	if (ret)
		return ret;

	ret = led_set_state(dev, cmd);
	return ret;
}

static void __maybe_unused led_error_blink(u32 nb_blink)
{
	int ret;
	struct udevice *led;
	u32 i;

	if (!nb_blink)
		return;

	if (CONFIG_IS_ENABLED(LED)) {
		ret = get_led(&led, "u-boot,error-led");
		if (!ret) {
			/* make u-boot,error-led blinking */
			/* if U32_MAX and 125ms interval, for 17.02 years */
			for (i = 0; i < 2 * nb_blink; i++) {
				led_set_state(led, LEDST_TOGGLE);
				mdelay(125);
				WATCHDOG_RESET();
			}
			led_set_state(led, LEDST_ON);
		}
	}

	/* infinite: the boot process must be stopped */
	if (nb_blink == U32_MAX)
		hang();
}

static void sysconf_init(void)
{
	u8 *syscfg;
	struct udevice *pwr_dev;
	struct udevice *pwr_reg;
	struct udevice *dev;
	u32 otp = 0;
	int ret;
	u32 bootr, val;

	syscfg = (u8 *)syscon_get_first_range(STM32MP_SYSCON_SYSCFG);

	/* interconnect update : select master using the port 1 */
	/* LTDC = AXI_M9 */
	/* GPU  = AXI_M8 */
	/* today information is hardcoded in U-Boot */
	writel(BIT(9), syscfg + SYSCFG_ICNR);

	/* disable Pull-Down for boot pin connected to VDD */
	bootr = readl(syscfg + SYSCFG_BOOTR);
	bootr &= ~(SYSCFG_BOOTR_BOOT_MASK << SYSCFG_BOOTR_BOOTPD_SHIFT);
	bootr |= (bootr & SYSCFG_BOOTR_BOOT_MASK) << SYSCFG_BOOTR_BOOTPD_SHIFT;
	writel(bootr, syscfg + SYSCFG_BOOTR);

	/* High Speed Low Voltage Pad mode Enable for SPI, SDMMC, ETH, QSPI
	 * and TRACE. Needed above ~50MHz and conditioned by AFMUX selection.
	 * The customer will have to disable this for low frequencies
	 * or if AFMUX is selected but the function not used, typically for
	 * TRACE. Otherwise, impact on power consumption.
	 *
	 * WARNING:
	 *   enabling High Speed mode while VDD>2.7V
	 *   with the OTP product_below_2v5 (OTP 18, BIT 13)
	 *   erroneously set to 1 can damage the IC!
	 *   => U-Boot set the register only if VDD < 2.7V (in DT)
	 *      but this value need to be consistent with board design
	 */
	ret = uclass_get_device_by_driver(UCLASS_PMIC,
					  DM_DRIVER_GET(stm32mp_pwr_pmic),
					  &pwr_dev);
	if (!ret && IS_ENABLED(CONFIG_DM_REGULATOR)) {
		ret = uclass_get_device_by_driver(UCLASS_MISC,
						  DM_DRIVER_GET(stm32mp_bsec),
						  &dev);
		if (ret) {
			log_err("Can't find stm32mp_bsec driver\n");
			return;
		}

		ret = misc_read(dev, STM32_BSEC_SHADOW(18), &otp, 4);
		if (ret > 0)
			otp = otp & BIT(13);

		/* get VDD = vdd-supply */
		ret = device_get_supply_regulator(pwr_dev, "vdd-supply",
						  &pwr_reg);

		/* check if VDD is Low Voltage */
		if (!ret) {
			if (regulator_get_value(pwr_reg) < 2700000) {
				writel(SYSCFG_IOCTRLSETR_HSLVEN_TRACE |
				       SYSCFG_IOCTRLSETR_HSLVEN_QUADSPI |
				       SYSCFG_IOCTRLSETR_HSLVEN_ETH |
				       SYSCFG_IOCTRLSETR_HSLVEN_SDMMC |
				       SYSCFG_IOCTRLSETR_HSLVEN_SPI,
				       syscfg + SYSCFG_IOCTRLSETR);

				if (!otp)
					log_err("product_below_2v5=0: HSLVEN protected by HW\n");
			} else {
				if (otp)
					log_err("product_below_2v5=1: HSLVEN update is destructive, no update as VDD>2.7V\n");
			}
		} else {
			log_debug("VDD unknown");
		}
	}

	/* activate automatic I/O compensation
	 * warning: need to ensure CSI enabled and ready in clock driver
	 */
	writel(SYSCFG_CMPENSETR_MPU_EN, syscfg + SYSCFG_CMPENSETR);

	/* poll until ready (1s timeout) */
	ret = readl_poll_timeout(syscfg + SYSCFG_CMPCR, val,
				 val & SYSCFG_CMPCR_READY,
				 1000000);
	if (ret) {
		log_err("SYSCFG: I/O compensation failed, timeout.\n");
		led_error_blink(10);
	}

	clrbits_le32(syscfg + SYSCFG_CMPCR, SYSCFG_CMPCR_SW_CTRL);
}

/* board dependent setup after realloc */
int board_init(void)
{
	struct udevice *dev;
	int ret;

	/* probe RCC to avoid circular access with usbphyc probe as clk provider */
	if (IS_ENABLED(CONFIG_CLK_STM32MP13)) {
		ret = uclass_get_device_by_driver(UCLASS_CLK, DM_DRIVER_GET(stm32mp1_clock), &dev);
		log_debug("Clock init failed: %d\n", ret);
	}

	if (IS_ENABLED(CONFIG_DM_REGULATOR))
		regulators_enable_boot_on(_DEBUG);

	/*
	 * sysconf initialisation done only when U-Boot is running in secure
	 * done in TF-A for TFABOOT.
	 */
	if (IS_ENABLED(CONFIG_ARMV7_NONSEC))
		sysconf_init();

	if (CONFIG_IS_ENABLED(LED))
		led_default_state();

	setup_led(LEDST_ON);

	return 0;
}

int board_late_init(void)
{
	const void *fdt_compat;
	int fdt_compat_len;
	int ret;
	u32 otp;
	struct udevice *dev;
	char buf[10];
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
		ret = uclass_get_device_by_driver(UCLASS_MISC,
						  DM_DRIVER_GET(stm32mp_bsec),
						  &dev);

		if (!ret)
			ret = misc_read(dev, STM32_BSEC_SHADOW(BSEC_OTP_BOARD),
					&otp, sizeof(otp));
		if (ret > 0 && otp) {
			snprintf(buf, sizeof(buf), "0x%04x", otp >> 16);
			env_set("board_id", buf);

			snprintf(buf, sizeof(buf), "0x%04x",
				 ((otp >> 8) & 0xF) - 1 + 0xA);
			env_set("board_rev", buf);
		}
	}

	if (IS_ENABLED(CONFIG_ADC)) {
		/* probe all ADC for calibration */
		uclass_foreach_dev_probe(UCLASS_ADC, dev) {
			log_debug("ACD probe for calibration: %s\n", dev->name);
		}
	}

	return 0;
}

void board_quiesce_devices(void)
{
	setup_led(LEDST_OFF);
}

/* CLOCK feed to PHY*/
#define ETH_CK_F_25M	25000000
#define ETH_CK_F_50M	50000000
#define ETH_CK_F_125M	125000000

struct stm32_syscfg_pmcsetr {
	u32 syscfg_clr_off;
	u32 eth1_clk_sel;
	u32 eth1_ref_clk_sel;
	u32 eth1_sel_mii;
	u32 eth1_sel_rgmii;
	u32 eth1_sel_rmii;
	u32 eth2_clk_sel;
	u32 eth2_ref_clk_sel;
	u32 eth2_sel_rgmii;
	u32 eth2_sel_rmii;
};

const struct stm32_syscfg_pmcsetr stm32mp13_syscfg_pmcsetr = {
	.syscfg_clr_off		= 0x08,
	.eth1_clk_sel		= BIT(16),
	.eth1_ref_clk_sel	= BIT(17),
	.eth1_sel_mii		= 0,
	.eth1_sel_rgmii		= BIT(21),
	.eth1_sel_rmii		= BIT(23),
	.eth2_clk_sel		= BIT(24),
	.eth2_ref_clk_sel	= BIT(25),
	.eth2_sel_rgmii		= BIT(29),
	.eth2_sel_rmii		= BIT(31)
};

#define SYSCFG_PMCSETR_ETH_MASK		GENMASK(23, 16)
#define SYSCFG_PMCR_ETH_SEL_GMII	0

/* eth init function : weak called in eqos driver */
int board_interface_eth_init(struct udevice *dev,
			     phy_interface_t interface_type, ulong rate)
{
	struct regmap *regmap;
	uint regmap_mask;
	int ret;
	u32 value;
	bool ext_phyclk, eth_clk_sel_reg, eth_ref_clk_sel_reg;
	const struct stm32_syscfg_pmcsetr *pmcsetr;

	/* Ethernet PHY have no crystal */
	ext_phyclk = dev_read_bool(dev, "st,ext-phyclk");

	/* Gigabit Ethernet 125MHz clock selection. */
	eth_clk_sel_reg = dev_read_bool(dev, "st,eth-clk-sel");

	/* Ethernet 50Mhz RMII clock selection */
	eth_ref_clk_sel_reg = dev_read_bool(dev, "st,eth-ref-clk-sel");

	if (device_is_compatible(dev, "st,stm32mp13-dwmac"))
		pmcsetr = &stm32mp13_syscfg_pmcsetr;
	else {
		log_err("ERROR: DT compatible incorrect\n");
		return -EINVAL;
	}

	regmap = syscon_regmap_lookup_by_phandle(dev, "st,syscon");
	if (!IS_ERR(regmap)) {
		u32 fmp[3];

		ret = dev_read_u32_array(dev, "st,syscon", fmp, 3);
		if (ret)
			/*  If no mask in DT, it is MP15 (backward compatibility) */
			regmap_mask = SYSCFG_PMCSETR_ETH_MASK;
		else
			regmap_mask = fmp[2];
	} else {
		return -ENODEV;
	}

	switch (interface_type) {
	case PHY_INTERFACE_MODE_MII:
		value = pmcsetr->eth1_sel_mii;
		log_debug("PHY_INTERFACE_MODE_MII\n");
		break;
	case PHY_INTERFACE_MODE_GMII:
		value = SYSCFG_PMCR_ETH_SEL_GMII;
		log_debug("PHY_INTERFACE_MODE_GMII\n");
		break;
	case PHY_INTERFACE_MODE_RMII:
		value = pmcsetr->eth1_sel_rmii | pmcsetr->eth2_sel_rmii;
		if (rate == ETH_CK_F_50M && (eth_clk_sel_reg || ext_phyclk))
			value |= pmcsetr->eth1_ref_clk_sel | pmcsetr->eth2_ref_clk_sel;
		log_debug("PHY_INTERFACE_MODE_RMII\n");
		break;
	case PHY_INTERFACE_MODE_RGMII:
	case PHY_INTERFACE_MODE_RGMII_ID:
	case PHY_INTERFACE_MODE_RGMII_RXID:
	case PHY_INTERFACE_MODE_RGMII_TXID:
		value = pmcsetr->eth1_sel_rgmii | pmcsetr->eth2_sel_rgmii;
		if (rate == ETH_CK_F_125M && (eth_clk_sel_reg || ext_phyclk))
			value |= pmcsetr->eth1_clk_sel | pmcsetr->eth2_clk_sel;
		log_debug("PHY_INTERFACE_MODE_RGMII\n");
		break;
	default:
		log_debug("Do not manage %d interface\n",
			  interface_type);
		/* Do not manage others interfaces */
		return -EINVAL;
	}

	/* Need to update PMCCLRR (clear register) */
	regmap_write(regmap, pmcsetr->syscfg_clr_off, regmap_mask);

	ret = regmap_update_bits(regmap, SYSCFG_PMCSETR, regmap_mask, value);

	return ret;
}

const char *env_ext4_get_intf(void)
{
	u32 bootmode = get_bootmode();

	switch (bootmode & TAMP_BOOT_DEVICE_MASK) {
	case BOOT_FLASH_SD:
	case BOOT_FLASH_EMMC:
		return "mmc";
	default:
		return "";
	}
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

const char *env_ext4_get_dev_part(void)
{
	static char *const env_dev_part =
#ifdef CONFIG_ENV_EXT4_DEVICE_AND_PART
		CONFIG_ENV_EXT4_DEVICE_AND_PART;
#else
		"";
#endif
	static char *const dev_part[] = {"0:auto", "1:auto", "2:auto"};

	if (strlen(env_dev_part) > 0)
		return env_dev_part;

	return dev_part[mmc_get_boot()];
}

int mmc_get_env_dev(void)
{
	const int mmc_env_dev = CONFIG_IS_ENABLED(ENV_IS_IN_MMC, (CONFIG_SYS_MMC_ENV_DEV), (-1));

	if (mmc_env_dev >= 0)
		return mmc_env_dev;

	/* use boot instance to select the correct mmc device identifier */
	return mmc_get_boot();
}

#if defined(CONFIG_OF_BOARD_SETUP)

void stm32mp13x_dk_fdt_update(void *new_blob)
{
}

int ft_board_setup(void *blob, struct bd_info *bd)
{
	fdt_fixup_ccmp1(blob);

	static const struct node_info nodes[] = {
		{ "st,stm32f469-qspi",		MTD_DEV_TYPE_NOR,  },
		{ "st,stm32f469-qspi",		MTD_DEV_TYPE_SPINAND},
		{ "st,stm32mp15-fmc2",		MTD_DEV_TYPE_NAND, },
		{ "st,stm32mp1-fmc2-nfc",	MTD_DEV_TYPE_NAND, },
	};
	char *boot_device;

	/* Check the boot-source and don't update MTD for serial or usb boot */
	boot_device = env_get("boot_device");
	if (!boot_device ||
	    (strcmp(boot_device, "serial") && strcmp(boot_device, "usb")))
		if (IS_ENABLED(CONFIG_FDT_FIXUP_PARTITIONS))
			fdt_fixup_mtdparts(blob, nodes, ARRAY_SIZE(nodes));

	if (CONFIG_IS_ENABLED(FDT_SIMPLEFB))
		fdt_simplefb_enable_and_mem_rsv(blob);

	return 0;
}
#endif

static void board_copro_image_process(ulong fw_image, size_t fw_size)
{
	int ret, id = 0; /* Copro id fixed to 0 as only one coproc on mp1 */

	if (!rproc_is_initialized())
		if (rproc_init()) {
			log_err("Remote Processor %d initialization failed\n",
				id);
			return;
		}

	ret = rproc_load(id, fw_image, fw_size);
	log_err("Load Remote Processor %d with data@addr=0x%08lx %u bytes:%s\n",
		id, fw_image, fw_size, ret ? " Failed!" : " Success!");

	if (!ret)
		rproc_start(id);
}

U_BOOT_FIT_LOADABLE_HANDLER(IH_TYPE_COPRO, board_copro_image_process);
