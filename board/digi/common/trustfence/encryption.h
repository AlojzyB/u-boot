/*
 * Copyright (C) 2025, Digi International Inc.
 *
 * SPDX-License-Identifier: GPL-2.0+
 */

#ifndef TF_ENCRYPTION_H
#define TF_ENCRYPTION_H

/* Header (8) + BKEK (32) + MAC (16) + MAX_KEY_SIZE (256 bits) */
#define MAX_DEK_BLOB_SIZE	(8 + 32 + 16 + (256 / 8))

#ifdef CONFIG_IMX_HAB
#ifdef CONFIG_ARCH_IMX8M
int get_dek_blob_offset(char *address, u32 *offset);
int get_dek_blob_size(char *address, u32 *size);
#endif
int get_dek_blob(ulong addr, u32 *size);
void copy_dek(void);
void copy_spl_dek(void);
#endif /* CONFIG_IMX_HAB */

int is_uboot_encrypted(void);

#endif /* TF_ENCRYPTION_H */
