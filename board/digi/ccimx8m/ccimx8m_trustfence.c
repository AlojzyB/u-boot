/*
 * Copyright (C) 2024, Digi International Inc.
 *
 * SPDX-License-Identifier: GPL-2.0+
 */

#include <common.h>
#include <asm/mach-imx/hab.h>

#include "../common/trustfence.h"

#define SPL_IVT_HEADER_SIZE	0x40

/* The Blob Address is a fixed address defined in imx-mkimage
 * project in iMX8M/soc.mak file
 */
#define DEK_BLOB_LOAD_ADDR	0x40400000

#define HAB_AUTH_BLOB_TAG	0x81
#define HAB_VERSION		0x43

#define FIT_DEK_BLOB_SIZE	96

/*
 * Return the offset where the DEK blob must be placed for:
 * - offset[0] -> SPL
 * - offset[1] -> U-Boot
 *
 * SPL DEK blob will be directly appended to the CSF block.
 * U-Boot DEK blob will be inserted in the dummy DEK location
 * of the U-Boot image.
 */
int get_dek_blob_offset(ulong addr, ulong size, u32 *offset)
{
	struct ivt *ivt = (struct ivt *)(CONFIG_SPL_TEXT_BASE - SPL_IVT_HEADER_SIZE);

	/* Verify the pointer is pointing at an actual IVT table */
	if ((ivt->hdr.magic != IVT_HEADER_MAGIC) ||
	   (be16_to_cpu(ivt->hdr.length) != IVT_TOTAL_LENGTH))
		return 1;

	if (!ivt->csf)
		return 1

	offset[0] = ivt->csf - (CONFIG_SPL_TEXT_BASE - SPL_IVT_HEADER_SIZE) + CONFIG_CSF_SIZE;
	offset[1] = size - FIT_DEK_BLOB_SIZE;

	return 0;
}

int get_dek_blob_size(ulong addr, u32 *size)
{
	char *address = (char *)addr;

	if (address[3] != HAB_VERSION || address[0] != HAB_AUTH_BLOB_TAG) {
		debug("Tag does not match as expected\n");
		return -EINVAL;
	}

	*size = address[2];
	debug("DEK blob size is 0x%04x\n", *size);

	return 0;
}

int get_dek_blob(ulong addr, u32 *size)
{
	/* Get DEK offset */
	char *dek_blob_src = (void*)(DEK_BLOB_LOAD_ADDR);
	u32 dek_blob_size;

	/* Get Dek blob */
	if (get_dek_blob_size((char *)dek_blob_src, &dek_blob_size))
		return 1;

	memcpy((void *)addr, dek_blob_src, dek_blob_size);
	*size = dek_blob_size;

	return 0;
}
