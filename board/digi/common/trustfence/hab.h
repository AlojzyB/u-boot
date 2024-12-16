/*
 * Copyright (C) 2025, Digi International Inc.
 *
 * SPDX-License-Identifier: GPL-2.0+
 */

#ifndef TF_HAB_H
#define TF_HAB_H

void hab_verification(void);
int get_dek_blob_offset(ulong addr, u32 *offset);
int get_dek_blob_size(ulong addr, u32 *size);
int get_dek_blob(ulong addr, u32 *size);
void copy_dek(void);
void copy_spl_dek(void);
int revoke_key_index(int i);

#endif /* TF_HAB_H */
