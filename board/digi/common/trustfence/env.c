/*
 * Copyright 2024 Digi International Inc
 *
 * SPDX-License-Identifier: GPL-2.0+
 */

#include <dm.h>
#include <errno.h>
#include <fuse.h>
#include <linux/kernel.h>
#include <memalign.h>
#include <uboot_aes.h>
#include <u-boot/md5.h>

#ifdef CONFIG_CAAM_ENV_ENCRYPT
#include <fsl_sec.h>
#endif

#ifdef CONFIG_OPTEE_ENV_ENCRYPT
#include "aes_tee.h"
#endif

#include "boot.h"
#include "env.h"

/*
 * We use the key modifier as initialization vector (IV) for AES,
 * so make it AES block length size. It also matches the MD5 hash
 * size (16) we use to compose the key modifier.
 */
#define KEY_MODIFIER_SIZE	AES_BLOCK_LENGTH

static int get_trustfence_key_modifier(unsigned char keymod[KEY_MODIFIER_SIZE])
{
	u32 ocotp_hwid[CONFIG_HWID_WORDS_NUMBER];
	int i, ret;

	for (i = 0; i < CONFIG_HWID_WORDS_NUMBER; i++) {
		ret = fuse_read(CONFIG_HWID_BANK,
				CONFIG_HWID_START_WORD + i, &ocotp_hwid[i]);
		if (ret)
			return ret;
	}
	md5((unsigned char *)(&ocotp_hwid), sizeof(ocotp_hwid), keymod);

	return ret;
}

#ifdef CONFIG_CAAM_ENV_ENCRYPT
void setup_caam(void)
{
	struct udevice *dev;
	int ret =
	    uclass_get_device_by_driver(UCLASS_MISC, DM_DRIVER_GET(caam_jr),
					&dev);
	if (ret)
		printf("Failed to initialize caam_jr: %d\n", ret);
}

int env_crypt(env_t * env, const int enc)
{
	unsigned char *data = env->data;
	int ret = 0;
	uint8_t *src_ptr, *dst_ptr, *key_mod;

	if (!trustfence_is_closed())
		return 0;

	/* Buffers must be aligned */
	key_mod = memalign(ARCH_DMA_MINALIGN, KEY_MODIFIER_SIZE);
	if (!key_mod) {
		debug("Not enough memory to encrypt the environment\n");
		return -ENOMEM;
	}
	ret = get_trustfence_key_modifier(key_mod);
	if (ret)
		goto freekm;

	src_ptr = memalign(ARCH_DMA_MINALIGN, ENV_SIZE);
	if (!src_ptr) {
		debug("Not enough memory to encrypt the environment\n");
		ret = -ENOMEM;
		goto freekm;
	}
	dst_ptr = memalign(ARCH_DMA_MINALIGN, ENV_SIZE);
	if (!dst_ptr) {
		debug("Not enough memory to encrypt the environment\n");
		ret = -ENOMEM;
		goto freesrc;
	}
	memcpy(src_ptr, data, ENV_SIZE);

	if (enc) {
		printf("Encrypting... ");
		ret = blob_encap(key_mod, src_ptr, dst_ptr, ENV_SIZE - BLOB_OVERHEAD, 0);
	} else {
		printf("Decrypting... ");
		ret = blob_decap(key_mod, src_ptr, dst_ptr, ENV_SIZE - BLOB_OVERHEAD, 0);
	}

	if (ret)
		goto err;

	memcpy(data, dst_ptr, ENV_SIZE);

err:
	free(dst_ptr);
freesrc:
	free(src_ptr);
freekm:
	free(key_mod);

	return ret;
}
#endif

#ifdef CONFIG_OPTEE_ENV_ENCRYPT
int env_crypt(env_t * env, const int enc)
{
	uint8_t *data = env->data;
	uint8_t *key_mod;
	int ret = 0;

	if (!trustfence_is_closed())
		return 0;

	key_mod = memalign(ARCH_DMA_MINALIGN, KEY_MODIFIER_SIZE);
	if (!key_mod) {
		debug("Not enough memory for key modifier\n");
		return -ENOMEM;
	}
	ret = get_trustfence_key_modifier(key_mod);
	if (ret)
		goto freekm;

	printf("%s", enc ? "Encrypting... " : "Decrypting... ");
	ret = optee_crypt_data(enc, key_mod, data, ENV_SIZE);

freekm:
	free(key_mod);

	return ret;
}
#endif
