/*
 * Copyright (C) 2024, Digi International Inc.
 *
 * SPDX-License-Identifier: GPL-2.0+
 */

#include <common.h>
#include <env.h>
#include <fsl_sec.h>
#include <asm/mach-imx/hab.h>

#include "encryption.h"

#define UBOOT_HEADER_SIZE	0xC00
#define UBOOT_START_ADDR	(CONFIG_TEXT_BASE - UBOOT_HEADER_SIZE)

#define BLOB_DEK_OFFSET		0x100

/*
 * If CONFIG_CSF_SIZE is undefined, assume 0x4000. This value will be used
 * in the signing script.
 */
#ifndef CONFIG_CSF_SIZE
#define CONFIG_CSF_SIZE 0x4000
#endif

/*
 * Copy the DEK blob used by the current U-Boot image into a buffer. Also
 * get its size in the last out parameter.
 * Possible DEK key sizes are 128, 192 and 256 bits.
 * DEK blobs have an overhead of 56 bytes.
 * Hence, possible DEK blob sizes are 72, 80 and 88 bytes.
 *
 * The output buffer should be at least MAX_DEK_BLOB_SIZE (88) bytes long to
 * prevent out of boundary access.
 *
 * Returns 0 if the DEK blob was found, 1 otherwise.
 */
 /* TODO: also CONFIG_CC6 but still not migrated */
#if defined(CONFIG_CC6UL)
__weak int get_dek_blob(ulong addr, u32 *size)
{
	struct ivt *ivt = (struct ivt *)UBOOT_START_ADDR;

	/* Verify the pointer is pointing at an actual IVT table */
	if ((ivt->hdr.magic != IVT_HEADER_MAGIC) ||
	    (be16_to_cpu(ivt->hdr.length) != IVT_TOTAL_LENGTH))
		return 1;

	if (ivt->csf) {
		int blob_size = MAX_DEK_BLOB_SIZE;
		uint8_t *dek_blob = (uint8_t *)(uintptr_t)(ivt->csf +
				    CONFIG_CSF_SIZE - blob_size);

		/*
		 * Several DEK sizes can be used.
		 * Determine the size and the start of the DEK blob by looking
		 * for its header.
		 */
		while (*dek_blob != HDR_TAG && blob_size > 0) {
			dek_blob += 8;
			blob_size -= 8;
		}

		if (blob_size > 0) {
			*size = blob_size;
			memcpy((void *)addr, (void *)dek_blob, blob_size);
			return 0;
		}
	}

	return 1;
}
#else
__weak int get_dek_blob(ulong addr, u32 *size)
{
	return 1;
}
#endif

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

void copy_spl_dek(void)
{
	ulong loadaddr = env_get_ulong("loadaddr", 16, CONFIG_SYS_LOAD_ADDR);
	ulong dek_blob_dst = loadaddr - (2 * BLOB_DEK_OFFSET);

	get_dek_blob(dek_blob_dst, NULL);
}

int is_uboot_encrypted(void) {
	char dek_blob[MAX_DEK_BLOB_SIZE];
	u32 dek_blob_size;

	/* U-Boot is encrypted if and only if get_dek_blob does not fail */
	return !get_dek_blob((ulong)dek_blob, &dek_blob_size);
}
