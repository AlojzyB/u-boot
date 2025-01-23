/*
 * Copyright (C) 2025, Digi International Inc.
 *
 * SPDX-License-Identifier: GPL-2.0+
 */

#ifndef TF_CONSOLE_H
#define TF_CONSOLE_H

#ifdef CONFIG_CONSOLE_ENABLE_GPIO
int console_enable_gpio(const char *name);
#endif
#ifdef CONFIG_CONSOLE_ENABLE_PASSPHRASE
int console_enable_passphrase(void);
#endif

#endif /* TF_CONSOLE_H */
