/*
 * Copyright 2024 Digi International Inc
 *
 * SPDX-License-Identifier: GPL-2.0+
 */

#ifndef TF_ENV_H
#define TF_ENV_H

#include <env_internal.h>

#ifdef CONFIG_CAAM_ENV_ENCRYPT
void setup_caam(void);
#endif

int env_crypt(env_t *env, const int enc);

#endif /* TF_ENV_H */
