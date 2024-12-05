/*
 *  Copyright (C) 2016-2025, Digi International Inc.
 *  All rights reserved.
 *
 *  This program is free software; you can redistribute it and/or modify it
 *  under the terms of the GNU General Public License version2  as published by
 *  the Free Software Foundation.
*/

#ifndef TRUSTFENCE_H
#define TRUSTFENCE_H

#ifdef CONFIG_HAS_TRUSTFENCE

int is_uboot_encrypted(void);
void copy_dek(void);
void copy_spl_dek(void);

#ifdef CONFIG_CONSOLE_DISABLE
#include "trustfence/console.h"
#endif
#ifdef CONFIG_TRUSTFENCE_JTAG
#include "trustfence/jtag.h"
#endif
#endif /* CONFIG_HAS_TRUSTFENCE */

void fdt_fixup_trustfence(void *fdt);

/* platform specific Trustfence support*/
int trustfence_status(void);

#endif /* TRUSTFENCE_H */
