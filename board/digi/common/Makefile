#
# Copyright 2015-2022, Digi International Inc.
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.

# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
#
# SPDX-License-Identifier:      GPL-2.0+
#

ifndef CONFIG_SPL_BUILD
$(if $(CONFIG_CMD_BOOTSTREAM), $(shell mkdir -p $(obj)cmd_bootstream))
obj-$(CONFIG_CMD_BOOTSTREAM) += cmd_bootstream/bch.o \
				cmd_bootstream/ncb.o \
				cmd_bootstream/cmd_bootstream.o \
				cmd_bootstream/mxsboot.o
obj-$(CONFIG_MXS_OTP) += cmd_mxsotp.o
obj-y += carrier_board.o
obj-$(CONFIG_AUTO_BOOTSCRIPT) += helper.o
obj-$(CONFIG_CMD_UPDATE_MMC) += helper.o helper_mmc.o
obj-$(CONFIG_CMD_UPDATE_NAND) += helper.o
obj-$(CONFIG_CMD_DBOOT) += helper.o
obj-$(CONFIG_CMD_DIGI_PMIC) += cmd_pmic.o
obj-$(CONFIG_MCA_TAMPER) += tamper.o
ifdef CONFIG_HAS_TRUSTFENCE
obj-y += trustfence/boot.o trustfence/encryption.o
obj-$(CONFIG_IMX_HAB) += trustfence/hab.o
obj-$(CONFIG_AHAB_BOOT) += trustfence/ahab.o
obj-$(CONFIG_AUTH_ARTIFACTS) += trustfence/auth.o
obj-$(CONFIG_ENV_ENCRYPT) += trustfence/env.o
obj-$(CONFIG_OPTEE_ENV_ENCRYPT) += trustfence/aes_tee.o
obj-$(CONFIG_TRUSTFENCE_JTAG) += trustfence/jtag.o
endif
endif
obj-$(CONFIG_HAS_HWID) += hwid.o
obj-$(CONFIG_MCA) += mca.o
ifdef CONFIG_HAS_TRUSTFENCE
obj-$(CONFIG_CONSOLE_DISABLE) += trustfence/console.o
endif
