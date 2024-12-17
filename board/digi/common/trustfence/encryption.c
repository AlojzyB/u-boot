/*
 * Copyright (C) 2024, Digi International Inc.
 *
 * SPDX-License-Identifier: GPL-2.0+
 */

#include <common.h>
#include <env.h>

#include "encryption.h"

#define BLOB_DEK_OFFSET		0x100

__weak int get_dek_blob(ulong addr, u32 *size)
{
	return 1;
}

__weak int get_dek_blob_offset(ulong addr, u32 *offset)
{
	return -1;
}

__weak int get_dek_blob_size(ulong addr, u32 *size)
{
	return -1;
}

/*
 * For secure OS, we want to have the DEK blob in a common absolute
 * memory address, so that there are no dependencies between the CSF
 * appended to the uImage and the U-Boot image size.
 * This copies the DEK blob into $loadaddr - BLOB_DEK_OFFSET. That is the
 * smallest negative offset that guarantees that the DEK blob fits and that it
 * is properly aligned.
 */
void copy_dek(void)
{
	ulong loadaddr = env_get_ulong("loadaddr", 16, CONFIG_SYS_LOAD_ADDR);
	ulong dek_blob_dst = loadaddr - BLOB_DEK_OFFSET;
	u32 dek_size;

	get_dek_blob(dek_blob_dst, &dek_size);
}

int is_uboot_encrypted(void) {
	char dek_blob[MAX_DEK_BLOB_SIZE];
	u32 dek_blob_size;

	/* U-Boot is encrypted if and only if get_dek_blob does not fail */
	return !get_dek_blob((ulong)dek_blob, &dek_blob_size);
}
