// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright 2019 NXP
 *
 */
#include <common.h>
#include <dm.h>
#include <dm/device_compat.h>
#include <env.h>
#include <linux/err.h>
#include <malloc.h>
#include <video.h>
#include <display.h>

#include <asm/cache.h>
#include <asm/arch/clock.h>
#include <asm/arch/imx-regs.h>
#include <asm/arch/sys_proto.h>
#include <asm/io.h>
#include <panel.h>
#include <video_bridge.h>
#include <video_link.h>
#include <clk.h>

#include <firmware/imx/sci/sci.h>
#include <imxdpuv1.h>
#include <imxdpuv1_registers.h>
#include <imxdpuv1_events.h>
#include <power-domain.h>
#include <asm/arch/lpcg.h>

#define FLAG_COMBO	BIT(1)

struct imx8_dc_priv {
	/*struct udevice *bridge;*/
	struct udevice *panel;
	struct udevice *disp_dev;
	struct imxdpuv1_videomode mode;

	u32 gpixfmt;
	u32 dpu_id;
	u32 disp_id;
};

static int imx8_dc_soc_setup(struct udevice *dev, sc_pm_clock_rate_t pixel_clock)
{
	int err, div = 0;
	sc_rsrc_t dc_rsrc, pll_rsrc;
	sc_pm_clock_rate_t pll_clk;
	const int max_div = 255;
	const sc_pm_clock_rate_t min_pll_clk = 650000000,
		max_pll_clk = 1300000000;
	const char *pll1_pd_name;
	u32 dc_lpcg;
	struct imx8_dc_priv *priv = dev_get_priv(dev);

	int dc_id = priv->dpu_id;
	int disp_id = priv->disp_id;
	sc_pm_clk_t misc_clk;
	sc_ctrl_t link_addr, link_enable, link_valid, sync;
	struct power_domain pd;
	int ret;

	debug("%s, dc_id %d\n", __func__, dc_id);

	if (dc_id == 0) {
		dc_rsrc = SC_R_DC_0;
		if (disp_id == 0)
			pll_rsrc = SC_R_DC_0_PLL_0;
		else
			pll_rsrc = SC_R_DC_0_PLL_1;
		pll1_pd_name = "dc0_pll1";
		dc_lpcg = DC_0_LPCG;
	} else {
		dc_rsrc = SC_R_DC_1;
		if (disp_id == 0)
			pll_rsrc = SC_R_DC_1_PLL_0;
		else
			pll_rsrc = SC_R_DC_1_PLL_1;
		pll1_pd_name = "dc1_pll1";
		dc_lpcg = DC_1_LPCG;
	}

	if (disp_id == 0) {
		misc_clk = SC_PM_CLK_MISC0;
		link_addr = SC_C_PXL_LINK_MST1_ADDR;
		link_enable = SC_C_PXL_LINK_MST1_ENB;
		link_valid = SC_C_PXL_LINK_MST1_VLD;
		sync = SC_C_SYNC_CTRL0;
	} else {
		misc_clk = SC_PM_CLK_MISC1;
		link_addr = SC_C_PXL_LINK_MST2_ADDR;
		link_enable = SC_C_PXL_LINK_MST2_ENB;
		link_valid = SC_C_PXL_LINK_MST2_VLD;
		sync = SC_C_SYNC_CTRL1;
	}

	if (!power_domain_lookup_name(pll1_pd_name, &pd)) {
		ret = power_domain_on(&pd);
		if (ret) {
			printf("%s Power up failed! (error = %d)\n", pll1_pd_name, ret);
			return -EIO;
		}
	} else {
		printf("%s lookup failed!\n", pll1_pd_name);
		return -EIO;
	}

	/* find an even divisor for PLL greater than PLL minimum */
	do {
		div += 2;
		if (div > max_div)
			break;
		pll_clk = pixel_clock * div;
		if (pll_clk > max_pll_clk)
			pll_clk = max_pll_clk;
	} while (pll_clk < min_pll_clk);

	debug("\n dc_id %d disp_id %d pll_clk %d pixel_clock %d\n",
	      dc_id, disp_id, pll_clk, pixel_clock);

	err = sc_pm_set_clock_rate(-1, pll_rsrc, SC_PM_CLK_PLL, &pll_clk);
	if (err) {
		printf("PLL%d set clock rate failed! (error = %d)\n",
		       disp_id, err);
		return -EIO;
	}

	err = sc_pm_set_clock_parent(-1, dc_rsrc, misc_clk,
				     (misc_clk == SC_PM_CLK_MISC0) ? 2 : 3);
	if (err) {
		printf("DISP%d set clock parent failed! (error = %d)\n",
		       disp_id, err);
		return -EIO;
	}

	err = sc_pm_set_clock_rate(-1, dc_rsrc, misc_clk, &pixel_clock);
	if (err) {
		printf("DISP%d set clock rate failed! (error = %d)\n",
		       disp_id, err);
		return -EIO;
	}

	err = sc_pm_clock_enable(-1, pll_rsrc, SC_PM_CLK_PLL, true, false);
	if (err) {
		printf("PLL%d clock enable failed! (error = %d)\n",
		       disp_id, err);
		return -EIO;
	}

	err = sc_pm_clock_enable(-1, dc_rsrc, misc_clk, true, false);
	if (err) {
		printf("DISP%d clock enable failed! (error = %d)\n",
		       disp_id, err);
		return -EIO;
	}

	lpcg_clock_on(dc_lpcg, disp_id);
	while (!lpcg_is_clock_on(dc_lpcg, disp_id))
		;

	err = sc_misc_set_control(-1, dc_rsrc, SC_C_MODE, 0);
	if (err) {
		printf("DC%d Set control mode failed! (error = %d)\n",
		       dc_rsrc, err);
		return -EIO;
	}

	err = sc_misc_set_control(-1, dc_rsrc, link_addr, 0);
	if (err) {
		printf("DC Set control _MST%d_ADDR failed! (error = %d)\n",
		       disp_id + 1, err);
		return -EIO;
	}

	err = sc_misc_set_control(-1, dc_rsrc, link_enable, 1);
	if (err) {
		printf("DC Set control _MST%d_ENB failed! (error = %d)\n",
		       disp_id + 1, err);
		return -EIO;
	}

	err = sc_misc_set_control(-1, dc_rsrc, link_valid, 1);
	if (err) {
		printf("DC Set control _MST%d_VLD failed! (error = %d)\n",
		       disp_id + 1, err);
		return -EIO;
	}

	err = sc_misc_set_control(-1, dc_rsrc, sync, 1);
	if (err) {
		printf("DC Set control _SYNC_CTRL%d failed! (error = %d)\n",
		       disp_id, err);
		return -EIO;
	}

	return 0;
}

static int imx8_dc_video_init(struct udevice *dev)
{
	imxdpuv1_channel_params_t channel;
	imxdpuv1_layer_t layer;
	struct imx8_dc_priv *priv = dev_get_priv(dev);
	struct video_uc_plat *plat = dev_get_uclass_plat(dev);

	int8_t imxdpuv1_id = priv->dpu_id;

	debug("%s\n", __func__);

	if (imxdpuv1_id != 0 || (imxdpuv1_id == 1 && !is_imx8qm())) {
		printf("%s(): invalid imxdpuv1_id %d", __func__, imxdpuv1_id);
		return -ENODEV;
	}

	imxdpuv1_init(imxdpuv1_id);
	imxdpuv1_disp_enable_frame_gen(imxdpuv1_id, 0, IMXDPUV1_FALSE);
	imxdpuv1_disp_enable_frame_gen(imxdpuv1_id, 1, IMXDPUV1_FALSE);

	imxdpuv1_disp_setup_frame_gen(imxdpuv1_id, priv->disp_id,
		(const struct imxdpuv1_videomode *)&priv->mode,
		0x3ff, 0, 0, 1, IMXDPUV1_DISABLE);
	imxdpuv1_disp_init(imxdpuv1_id, priv->disp_id);
	imxdpuv1_disp_setup_constframe(imxdpuv1_id,
		priv->disp_id, 0, 0, 0xff, 0); /* blue */

	if (priv->disp_id == 0)
		channel.common.chan = IMXDPUV1_CHAN_VIDEO_0;
	else
		channel.common.chan = IMXDPUV1_CHAN_VIDEO_1;
	channel.common.src_pixel_fmt = priv->gpixfmt;
	channel.common.dest_pixel_fmt = priv->gpixfmt;
	channel.common.src_width = priv->mode.hlen;
	channel.common.src_height = priv->mode.vlen;

	channel.common.clip_width = 0;
	channel.common.clip_height = 0;
	channel.common.clip_top = 0;
	channel.common.clip_left = 0;

	channel.common.dest_width = priv->mode.hlen;
	channel.common.dest_height = priv->mode.vlen;
	channel.common.dest_top = 0;
	channel.common.dest_left = 0;
	channel.common.stride =
		priv->mode.hlen * imxdpuv1_bytes_per_pixel(IMXDPUV1_PIX_FMT_BGRA32);
	channel.common.disp_id = priv->disp_id;
	channel.common.const_color = 0;
	channel.common.use_global_alpha = 0;
	channel.common.use_local_alpha = 0;
	imxdpuv1_init_channel(imxdpuv1_id, &channel);

	imxdpuv1_init_channel_buffer(imxdpuv1_id,
		channel.common.chan,
		priv->mode.hlen * imxdpuv1_bytes_per_pixel(IMXDPUV1_PIX_FMT_RGB32),
		IMXDPUV1_ROTATE_NONE,
		(dma_addr_t)plat->base,
		0,
		0);

	layer.enable    = IMXDPUV1_TRUE;
	layer.secondary = get_channel_blk(channel.common.chan);

	if (priv->disp_id == 0) {
		layer.stream    = IMXDPUV1_DISPLAY_STREAM_0;
		layer.primary   = IMXDPUV1_ID_CONSTFRAME0;
	} else {
		layer.stream    = IMXDPUV1_DISPLAY_STREAM_1;
		layer.primary   = IMXDPUV1_ID_CONSTFRAME1;
	}

	imxdpuv1_disp_setup_layer(
		imxdpuv1_id, &layer, IMXDPUV1_LAYER_0, 1);
	imxdpuv1_disp_set_layer_global_alpha(
		imxdpuv1_id, IMXDPUV1_LAYER_0, 0xff);

	imxdpuv1_disp_set_layer_position(
		imxdpuv1_id, IMXDPUV1_LAYER_0, 0, 0);
	imxdpuv1_disp_set_chan_position(
		imxdpuv1_id, channel.common.chan, 0, 0);

	imxdpuv1_disp_enable_frame_gen(imxdpuv1_id, priv->disp_id, IMXDPUV1_ENABLE);

	debug("IMXDPU display start ...\n");

	return 0;
}

static int imx8_dc_get_timings_from_display(struct udevice *dev,
					   struct display_timing *timings)
{
	struct imx8_dc_priv *priv = dev_get_priv(dev);
	int err;

	priv->disp_dev = video_link_get_next_device(dev);
	if (!priv->disp_dev ||
		device_get_uclass_id(priv->disp_dev) != UCLASS_DISPLAY) {

		printf("fail to find display device\n");
		return -ENODEV;
	}

	debug("disp_dev %s\n", priv->disp_dev->name);

	err = video_link_get_display_timings(timings);
	if (err)
		return err;

	return 0;
}

static int imx8_dc_probe(struct udevice *dev)
{
	struct video_uc_plat *plat = dev_get_uclass_plat(dev);
	struct video_priv *uc_priv = dev_get_uclass_priv(dev);
	struct imx8_dc_priv *priv = dev_get_priv(dev);
	ulong flag = dev_get_driver_data(dev);

	struct display_timing timings;
	u32 fb_start, fb_end;
	int ret;

	debug("%s() plat: base 0x%lx, size 0x%x\n",
	       __func__, plat->base, plat->size);

	priv->dpu_id = dev_seq(dev);

	ret = imx8_dc_get_timings_from_display(dev, &timings);
	if (ret)
		return ret;

	priv->mode.pixelclock = timings.pixelclock.typ;
	priv->mode.hlen = timings.hactive.typ;
	priv->mode.hbp = timings.hback_porch.typ;
	priv->mode.hfp = timings.hfront_porch.typ;

	priv->mode.vlen = timings.vactive.typ;
	priv->mode.vbp = timings.vback_porch.typ;
	priv->mode.vfp = timings.vfront_porch.typ;

	priv->mode.hsync = timings.hsync_len.typ;
	priv->mode.vsync = timings.vsync_len.typ;
	priv->mode.flags = IMXDPUV1_MODE_FLAGS_HSYNC_POL | IMXDPUV1_MODE_FLAGS_VSYNC_POL | IMXDPUV1_MODE_FLAGS_DE_POL;

	priv->gpixfmt = IMXDPUV1_PIX_FMT_BGRA32;

	if (flag & FLAG_COMBO) /* QXP has one DC which contains 2 LVDS/MIPI_DSI combo */
		priv->disp_id = dev_seq(priv->disp_dev->parent);
	else
		priv->disp_id = 1; /* QM has two DCs each contains one LVDS as secondary display output */
	imx8_dc_soc_setup(dev, priv->mode.pixelclock);

	debug("dpu %u, disp_id %u, pixelclock %u, hlen %u, vlen %u\n",
		priv->dpu_id, priv->disp_id, priv->mode.pixelclock, priv->mode.hlen, priv->mode.vlen);


	display_enable(priv->disp_dev, 32, NULL);


	ret = imx8_dc_video_init(dev);
	if (ret) {
		dev_err(dev, "imx8_dc_video_init fail %d\n", ret);
		return ret;
	}

	uc_priv->bpix = VIDEO_BPP32;
	uc_priv->xsize = priv->mode.hlen;
	uc_priv->ysize = priv->mode.vlen;

	/* Enable dcache for the frame buffer */
	fb_start = plat->base & ~(MMU_SECTION_SIZE - 1);
	fb_end = plat->base + plat->size;
	fb_end = ALIGN(fb_end, 1 << MMU_SECTION_SHIFT);
	mmu_set_region_dcache_behaviour(fb_start, fb_end - fb_start,
					DCACHE_WRITEBACK);
	video_set_flush_dcache(dev, true);

	return ret;
}

static int imx8_dc_bind(struct udevice *dev)
{
	struct video_uc_plat *plat = dev_get_uclass_plat(dev);

	/* Max size supported by LCDIF, because in bind, we can't probe panel */
	plat->size = 1920 * 1080 *4;

	return 0;
}

static int imx8_dc_remove(struct udevice *dev)
{
	struct imx8_dc_priv *priv = dev_get_priv(dev);

	debug("%s\n", __func__);

	imxdpuv1_disp_enable_frame_gen(priv->dpu_id,
		priv->disp_id, IMXDPUV1_DISABLE);

	return 0;
}

static const struct udevice_id imx8_dc_ids[] = {
	{ .compatible = "fsl,imx8qm-dpu" },
	{ .compatible = "fsl,imx8qxp-dpu", .data = FLAG_COMBO, },
	{ /* sentinel */ }
};

U_BOOT_DRIVER(imx8_dc) = {
	.name	= "imx8_dc",
	.id	= UCLASS_VIDEO,
	.of_match = imx8_dc_ids,
	.bind	= imx8_dc_bind,
	.probe	= imx8_dc_probe,
	.remove = imx8_dc_remove,
	.flags	= DM_FLAG_PRE_RELOC,
	.priv_auto	= sizeof(struct imx8_dc_priv),
};
