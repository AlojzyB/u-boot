/*
 * Copyright (C) 2025, Digi International Inc.
 *
 * SPDX-License-Identifier: GPL-2.0+
 */

#ifndef TF_ENCRYPTION_H
#define TF_ENCRYPTION_H

/* Header (8) + BKEK (32) + MAC (16) + MAX_KEY_SIZE (256 bits) */
#define MAX_DEK_BLOB_SIZE	(8 + 32 + 16 + (256 / 8))

int is_uboot_encrypted(void);

#endif /* TF_ENCRYPTION_H */
