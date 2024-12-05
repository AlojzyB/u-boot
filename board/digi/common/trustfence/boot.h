/*
 * Copyright (C) 2025, Digi International Inc.
 *
 * SPDX-License-Identifier: GPL-2.0+
 */

#ifndef TF_BOOT_H
#define TF_BOOT_H

int fuse_check_srk(void);
int fuse_prog_srk(u32 addr, u32 size);
#if defined(CONFIG_IMX_HAB)
int revoke_key_index(int i);
#endif
#if defined(CONFIG_AHAB_BOOT)
int revoke_keys(void);
#endif
int sense_key_status(u32 *val);
int close_device(int confirmed);
void fdt_fixup_trustfence(void *fdt);
int trustfence_status(void);

#endif /* TF_BOOT_H */
