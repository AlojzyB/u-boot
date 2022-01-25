/*
 * (C) Copyright 2018 Digi International, Inc.
 *
 * See file CREDITS for list of people who contributed to this
 * project.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston,
 * MA 02111-1307 USA
 */


 #include <common.h>
 #include <linux/errno.h>
 #include <fuse.h>
 #include "hwid.h"

extern int hwid_word_lengths[CONFIG_HWID_WORDS_NUMBER];

__weak int board_read_hwid(struct digi_hwid *hwid)
{
	u32 bank = CONFIG_HWID_BANK;
	u32 word = CONFIG_HWID_START_WORD;
	u32 cnt = CONFIG_HWID_WORDS_NUMBER;
	u32 fuseword;
	int ret, i;

	for (i = 0; i < cnt; i++, word++) {
		ret = fuse_read(bank, word, &fuseword);
		((u32 *)hwid)[i] = fuseword;
		if (ret)
			return ret;
	}

	return 0;
}

__weak int board_sense_hwid(struct digi_hwid *hwid)
{
	u32 bank = CONFIG_HWID_BANK;
	u32 word = CONFIG_HWID_START_WORD;
	u32 cnt = CONFIG_HWID_WORDS_NUMBER;
	u32 fuseword;
	int ret, i;

	for (i = 0; i < cnt; i++, word++) {
		ret = fuse_sense(bank, word, &fuseword);
		((u32 *)hwid)[i] = fuseword;
		if (ret)
			return ret;
	}

	return 0;
}

__weak void board_update_hwid(bool is_fuse)
{
	/* Do nothing */
}

__weak int board_prog_hwid(const struct digi_hwid *hwid)
{
	u32 bank = CONFIG_HWID_BANK;
	u32 word = CONFIG_HWID_START_WORD;
	u32 cnt = CONFIG_HWID_WORDS_NUMBER;
	u32 fuseword;
	int ret, i;

	for (i = 0; i < cnt; i++, word++) {
		fuseword = ((u32 *)hwid)[i];
		ret = fuse_prog(bank, word, fuseword);
		if (ret)
			return ret;
	}

	/* Trigger a HWID-related variables update (from fuses)*/
	board_update_hwid(true);
	return 0;
}

__weak int board_override_hwid(const struct digi_hwid *hwid)
{
	u32 bank = CONFIG_HWID_BANK;
	u32 word = CONFIG_HWID_START_WORD;
	u32 cnt = CONFIG_HWID_WORDS_NUMBER;
	u32 fuseword;
	int ret, i;

	for (i = 0; i < cnt; i++, word++) {
		fuseword = ((u32 *)hwid)[i];
		ret = fuse_override(bank, word, fuseword);
		if (ret)
			return ret;
	}

	/* Trigger a HWID-related variables update (from shadow registers)*/
	board_update_hwid(false);
	return 0;
}

#ifndef CONFIG_CC8X
__weak int board_lock_hwid(void)
{
	return fuse_prog(OCOTP_LOCK_BANK, OCOTP_LOCK_WORD,
			CONFIG_HWID_LOCK_FUSE);
}
#endif

__weak void print_hwid_hex(struct digi_hwid *hwid)
{
	int i;

	for (i = CONFIG_HWID_WORDS_NUMBER - 1; i >= 0; i--)
		printf(" %.*x", hwid_word_lengths[i], ((u32 *)hwid)[i]);

	printf("\n");
}
