// SPDX-License-Identifier: GPL-2.0+
/*
 * (C) Copyright 2000-2010
 * Wolfgang Denk, DENX Software Engineering, wd@denx.de.
 *
 * (C) Copyright 2001 Sysgo Real-Time Solutions, GmbH <www.elinos.com>
 * Andreas Heppel <aheppel@sysgo.de>
 */

#include <common.h>
#include <bootstage.h>
#include <command.h>
#include <env.h>
#include <env_internal.h>
#include <log.h>
#include <sort.h>
#include <asm/global_data.h>
#include <linux/stddef.h>
#include <search.h>
#include <errno.h>
#include <malloc.h>
#include <u-boot/crc.h>
#include <dm/ofnode.h>
#include <net.h>
#include <watchdog.h>

DECLARE_GLOBAL_DATA_PTR;

/************************************************************************
 * Default settings to be used when no valid environment is found
 */
#include <env_default.h>

struct hsearch_data env_htab = {
	.change_ok = env_flags_validate,
};

/*
 * This env_set() function is defined in cmd/nvedit.c, since it calls
 * _do_env_set(), whis is a static function in that file.
 *
 * int env_set(const char *varname, const char *varvalue);
 */

/**
 * Set an environment variable to an integer value
 *
 * @param varname	Environment variable to set
 * @param value		Value to set it to
 * Return: 0 if ok, 1 on error
 */
int env_set_ulong(const char *varname, ulong value)
{
	/* TODO: this should be unsigned */
	char *str = simple_itoa(value);

	return env_set(varname, str);
}

/**
 * Set an environment variable to an value in hex
 *
 * @param varname	Environment variable to set
 * @param value		Value to set it to
 * Return: 0 if ok, 1 on error
 */
int env_set_hex(const char *varname, ulong value)
{
	char str[17];

	sprintf(str, "%lx", value);
	return env_set(varname, str);
}

ulong env_get_hex(const char *varname, ulong default_val)
{
	const char *s;
	ulong value;
	char *endp;

	s = env_get(varname);
	if (s)
		value = hextoul(s, &endp);
	if (!s || endp == s)
		return default_val;

	return value;
}

int eth_env_get_enetaddr(const char *name, uint8_t *enetaddr)
{
	string_to_enetaddr(env_get(name), enetaddr);
	return is_valid_ethaddr(enetaddr);
}

int eth_env_set_enetaddr(const char *name, const uint8_t *enetaddr)
{
	char buf[ARP_HLEN_ASCII + 1];

	if (eth_env_get_enetaddr(name, (uint8_t *)buf))
		return -EEXIST;

	sprintf(buf, "%pM", enetaddr);

	return env_set(name, buf);
}

/*
 * Look up variable from environment,
 * return address of storage for that variable,
 * or NULL if not found
 */
char *env_get(const char *name)
{
	if (gd->flags & GD_FLG_ENV_READY) { /* after import into hashtable */
		struct env_entry e, *ep;

		schedule();

		e.key	= name;
		e.data	= NULL;
		hsearch_r(e, ENV_FIND, &ep, &env_htab, 0);

		return ep ? ep->data : NULL;
	}

	/* restricted capabilities before import */
	if (env_get_f(name, (char *)(gd->env_buf), sizeof(gd->env_buf)) >= 0)
		return (char *)(gd->env_buf);

	return NULL;
}

/*
 * Like env_get, but prints an error if envvar isn't defined in the
 * environment.  It always returns what env_get does, so it can be used in
 * place of env_get without changing error handling otherwise.
 */
char *from_env(const char *envvar)
{
	char *ret;

	ret = env_get(envvar);

	if (!ret)
		printf("missing environment variable: %s\n", envvar);

	return ret;
}

static int env_get_from_linear(const char *env, const char *name, char *buf,
			       unsigned len)
{
	const char *p, *end;
	size_t name_len;

	if (name == NULL || *name == '\0')
		return -1;

	name_len = strlen(name);

	for (p = env; *p != '\0'; p = end + 1) {
		const char *value;
		unsigned res;

		for (end = p; *end != '\0'; ++end)
			if (end - env >= CONFIG_ENV_SIZE)
				return -1;

		if (strncmp(name, p, name_len) || p[name_len] != '=')
			continue;
		value = &p[name_len + 1];

		res = end - value;
		memcpy(buf, value, min(len, res + 1));

		if (len <= res) {
			buf[len - 1] = '\0';
			printf("env_buf [%u bytes] too small for value of \"%s\"\n",
			       len, name);
		}

		return res;
	}

	return -1;
}

/*
 * Look up variable from environment for restricted C runtime env.
 */
int env_get_f(const char *name, char *buf, unsigned len)
{
	const char *env;

	if (gd->env_valid == ENV_INVALID)
		env = default_environment;
	else
		env = (const char *)gd->env_addr;

	return env_get_from_linear(env, name, buf, len);
}

/**
 * Decode the integer value of an environment variable and return it.
 *
 * @param name		Name of environment variable
 * @param base		Number base to use (normally 10, or 16 for hex)
 * @param default_val	Default value to return if the variable is not
 *			found
 * Return: the decoded value, or default_val if not found
 */
ulong env_get_ulong(const char *name, int base, ulong default_val)
{
	/*
	 * We can use env_get() here, even before relocation, since the
	 * environment variable value is an integer and thus short.
	 */
	const char *str = env_get(name);

	return str ? simple_strtoul(str, NULL, base) : default_val;
}

/*
 * Read an environment variable as a boolean
 * Return -1 if variable does not exist (default to true)
 */
int env_get_yesno(const char *var)
{
	char *s = env_get(var);

	if (s == NULL)
		return -1;
	return (*s == '1' || *s == 'y' || *s == 'Y' || *s == 't' || *s == 'T') ?
		1 : 0;
}

bool env_get_autostart(void)
{
	return env_get_yesno("autostart") == 1;
}

/*
 * Look up the variable from the default environment
 */
char *env_get_default(const char *name)
{
	if (env_get_from_linear(default_environment, name,
				(char *)(gd->env_buf),
				sizeof(gd->env_buf)) >= 0)
		return (char *)(gd->env_buf);

	return NULL;
}

__weak void platform_default_environment(void)
{
	return;
}

void env_set_default(const char *s, int flags)
{
	if (s) {
		if ((flags & H_INTERACTIVE) == 0) {
			printf("*** Warning - %s, "
				"using default environment\n\n", s);
		} else {
			puts(s);
		}
	} else {
		debug("Using default environment\n");
	}

	flags |= H_DEFAULT;
	if (himport_r(&env_htab, default_environment,
			sizeof(default_environment), '\0', flags, 0,
			0, NULL) == 0) {
		pr_err("## Error: Environment import failed: errno = %d\n",
		       errno);
		return;
	}

	/* Platform-specific actions on default environment */
	platform_default_environment();

	gd->flags |= GD_FLG_ENV_READY;
	gd->flags |= GD_FLG_ENV_DEFAULT;
}


/* [re]set individual variables to their value in the default environment */
int env_set_default_vars(int nvars, char * const vars[], int flags)
{
	/*
	 * Special use-case: import from default environment
	 * (and use \0 as a separator)
	 */
	flags |= H_NOCLEAR | H_DEFAULT;
	return himport_r(&env_htab, default_environment,
				sizeof(default_environment), '\0',
				flags, 0, nvars, vars);
}

#ifdef CONFIG_ENV_AES_CAAM_KEY
#include <fuse.h>
#include <u-boot/md5.h>
#include <asm/mach-imx/hab.h>
#include "../board/digi/common/trustfence.h"
#if defined(CONFIG_ARCH_MX6) || defined(CONFIG_ARCH_MX7) || \
	defined(CONFIG_ARCH_MX7ULP) || defined(CONFIG_ARCH_IMX8M)
#include <fsl_sec.h>
#include <asm/arch/clock.h>

static int env_aes_cbc_crypt(env_t *env, const int enc)
{
	unsigned char *data = env->data;
	int ret = 0;
	uint8_t *src_ptr, *dst_ptr, *key_mod;

	if (!imx_hab_is_enabled())
		return 0;

	/* Buffers must be aligned */
	key_mod = memalign(ARCH_DMA_MINALIGN, KEY_MODIFER_SIZE);
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

	hab_caam_clock_enable(1);

	u32 out_jr_size = sec_in32(CONFIG_SYS_FSL_JR0_ADDR +
				   FSL_CAAM_ORSR_JRa_OFFSET);
	if (out_jr_size != FSL_CAAM_MAX_JR_SIZE)
		sec_init();

	if (enc)
		ret = blob_encap(key_mod, src_ptr, dst_ptr, ENV_SIZE - BLOB_OVERHEAD, 0);
	else
		ret = blob_decap(key_mod, src_ptr, dst_ptr, ENV_SIZE - BLOB_OVERHEAD, 0);

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
#else /* CONFIG_ARCH_IMX8 */
#include <fsl_caam.h>

static int env_aes_cbc_crypt(env_t *env, const int enc)
{
	unsigned char *data = env->data;
	unsigned char *buffer;
	int ret = 0;
	unsigned char key_modifier[KEY_MODIFER_SIZE] = {0};

	if (!imx_hab_is_enabled())
		return 0;

	ret = get_trustfence_key_modifier(key_modifier);
	if (ret)
		return ret;

	caam_open();
	buffer = malloc(ENV_SIZE);
	if (!buffer) {
		debug("Not enough memory for en/de-cryption buffer");
		return -ENOMEM;
	}

	if (enc)
		ret = caam_gen_blob((ulong)data, (ulong)buffer, key_modifier, ENV_SIZE - BLOB_OVERHEAD);
	else
		ret = caam_decap_blob((ulong)buffer, (ulong)data, key_modifier, ENV_SIZE - BLOB_OVERHEAD);

	if (ret)
		goto err;

	memcpy(data, buffer, ENV_SIZE);

err:
	free(buffer);
	return ret;
}
#endif /* CONFIG_ARCH_IMX8 */
#else
static inline int env_aes_cbc_crypt(env_t *env, const int enc)
{
	return 0;
}
#endif /* CONFIG_ENV_AES_CAAM_KEY */

/*
 * Check if CRC is valid and (if yes) import the environment.
 * Note that "buf" may or may not be aligned.
 */
int env_import(const char *buf, int check, int flags)
{
	env_t *ep = (env_t *)buf;
	int ret;

	if (check) {
		uint32_t crc;

		memcpy(&crc, &ep->crc, sizeof(crc));

		if (crc32(0, ep->data, ENV_SIZE) != crc) {
			env_set_default("bad CRC", 0);
			return -ENOMSG; /* needed for env_load() */
		}
	}

	/* Decrypt the env if desired. */
	ret = env_aes_cbc_crypt(ep, 0);
	if (ret) {
#ifdef CONFIG_ENV_AES_CAAM_KEY
		if (himport_r(&env_htab, (char *)ep->data, ENV_SIZE,
				'\0', 0, 0, 0, NULL)) {
			printf("Environment is unencrypted!\n");
			printf("Resetting to defaults (read-only variables like MAC addresses will be kept).\n");
			gd->flags |= GD_FLG_ENV_READY;
			run_command("env default -a", 0);
			return 0;
		}
#endif
		pr_err("Failed to decrypt env!\n");
		env_set_default("!import failed", 0);
		return ret;
	} else {
		if (himport_r(&env_htab, (char *)ep->data, ENV_SIZE, '\0', 0, 0,
			0, NULL)) {
			gd->flags |= GD_FLG_ENV_READY;
			return 0;
		}
	}

	pr_err("Cannot import environment: errno = %d\n", errno);

	env_set_default("import failed", 0);

	return -EIO;
}

#ifdef CONFIG_SYS_REDUNDAND_ENVIRONMENT
static unsigned char env_flags;

int env_check_redund(const char *buf1, int buf1_read_fail,
		     const char *buf2, int buf2_read_fail)
{
	int crc1_ok = 0, crc2_ok = 0;
	env_t *tmp_env1, *tmp_env2;

	tmp_env1 = (env_t *)buf1;
	tmp_env2 = (env_t *)buf2;

	if (buf1_read_fail && buf2_read_fail) {
		puts("*** Error - No Valid Environment Area found\n");
		return -EIO;
	} else if (buf1_read_fail || buf2_read_fail) {
		puts("*** Warning - some problems detected ");
		puts("reading environment; recovered successfully\n");
	}

	if (!buf1_read_fail)
		crc1_ok = crc32(0, tmp_env1->data, ENV_SIZE) ==
				tmp_env1->crc;
	if (!buf2_read_fail)
		crc2_ok = crc32(0, tmp_env2->data, ENV_SIZE) ==
				tmp_env2->crc;

	if (!crc1_ok && !crc2_ok) {
		return -ENOMSG; /* needed for env_load() */
	} else if (crc1_ok && !crc2_ok) {
		gd->env_valid = ENV_VALID;
	} else if (!crc1_ok && crc2_ok) {
		gd->env_valid = ENV_REDUND;
	} else {
		/* both ok - check serial */
		if (tmp_env1->flags == 255 && tmp_env2->flags == 0)
			gd->env_valid = ENV_REDUND;
		else if (tmp_env2->flags == 255 && tmp_env1->flags == 0)
			gd->env_valid = ENV_VALID;
		else if (tmp_env1->flags > tmp_env2->flags)
			gd->env_valid = ENV_VALID;
		else if (tmp_env2->flags > tmp_env1->flags)
			gd->env_valid = ENV_REDUND;
		else /* flags are equal - almost impossible */
			gd->env_valid = ENV_VALID;
	}

	return 0;
}

int env_import_redund(const char *buf1, int buf1_read_fail,
		      const char *buf2, int buf2_read_fail,
		      int flags)
{
	env_t *ep;
	int ret;

	ret = env_check_redund(buf1, buf1_read_fail, buf2, buf2_read_fail);

	if (ret == -EIO) {
		env_set_default("bad env area", 0);
		return -EIO;
	} else if (ret == -ENOMSG) {
#if defined(OLD_ENV_OFFSET_LOCATIONS)
		static int old_env_tries = OLD_ENV_OFFSET_LOCATIONS;

		/*
		 * Return error but don't reset the environment yet.
		 * We'll try to restore it from the old location.
		 */
		if (old_env_tries) {
			old_env_tries--;
			return -ENOMSG;
		}
#endif
		env_set_default("bad CRC", 0);
		return -ENOMSG;
	}

	if (gd->env_valid == ENV_VALID)
		ep = (env_t *)buf1;
	else
		ep = (env_t *)buf2;

	env_flags = ep->flags;

	return env_import((char *)ep, 0, flags);
}
#endif /* CONFIG_SYS_REDUNDAND_ENVIRONMENT */

/* Export the environment and generate CRC for it. */
int env_export(env_t *env_out)
{
	char *res;
	ssize_t	len;
#ifdef CONFIG_ENV_AES_CAAM_KEY
	int ret;
#endif

	res = (char *)env_out->data;
	len = hexport_r(&env_htab, '\0', 0, &res, ENV_SIZE, 0, NULL);
	if (len < 0) {
		pr_err("Cannot export environment: errno = %d\n", errno);
		return 1;
	}

	/* Encrypt the env if desired. */
#ifdef CONFIG_ENV_AES_CAAM_KEY
	ret = env_aes_cbc_crypt(env_out, 1);
	if (ret)
		return ret;
#endif

	env_out->crc = crc32(0, env_out->data, ENV_SIZE);

#ifdef CONFIG_SYS_REDUNDAND_ENVIRONMENT
	env_out->flags = ++env_flags; /* increase the serial */
#endif

	return 0;
}

void env_relocate(void)
{
#if defined(CONFIG_NEEDS_MANUAL_RELOC)
	env_reloc();
	env_fix_drivers();
	env_htab.change_ok += gd->reloc_off;
#endif
	if (gd->env_valid == ENV_INVALID) {
#if defined(CONFIG_ENV_IS_NOWHERE) || defined(CONFIG_SPL_BUILD)
		/* Environment not changable */
		env_set_default(NULL, 0);
#else
		bootstage_error(BOOTSTAGE_ID_NET_CHECKSUM);
		env_set_default("bad CRC", 0);
#endif
	} else {
		env_load();
	}
}

#ifdef CONFIG_AUTO_COMPLETE
int env_complete(char *var, int maxv, char *cmdv[], int bufsz, char *buf,
		 bool dollar_comp)
{
	struct env_entry *match;
	int found, idx;

	if (dollar_comp) {
		/*
		 * When doing $ completion, the first character should
		 * obviously be a '$'.
		 */
		if (var[0] != '$')
			return 0;

		var++;

		/*
		 * The second one, if present, should be a '{', as some
		 * configuration of the u-boot shell expand ${var} but not
		 * $var.
		 */
		if (var[0] == '{')
			var++;
		else if (var[0] != '\0')
			return 0;
	}

	idx = 0;
	found = 0;
	cmdv[0] = NULL;


	while ((idx = hmatch_r(var, idx, &match, &env_htab))) {
		int vallen = strlen(match->key) + 1;

		if (found >= maxv - 2 ||
		    bufsz < vallen + (dollar_comp ? 3 : 0))
			break;

		cmdv[found++] = buf;

		/* Add the '${' prefix to each var when doing $ completion. */
		if (dollar_comp) {
			strcpy(buf, "${");
			buf += 2;
			bufsz -= 3;
		}

		memcpy(buf, match->key, vallen);
		buf += vallen;
		bufsz -= vallen;

		if (dollar_comp) {
			/*
			 * This one is a bit odd: vallen already contains the
			 * '\0' character but we need to add the '}' suffix,
			 * hence the buf - 1 here. strcpy() will add the '\0'
			 * character just after '}'. buf is then incremented
			 * to account for the extra '}' we just added.
			 */
			strcpy(buf - 1, "}");
			buf++;
		}
	}

	qsort(cmdv, found, sizeof(cmdv[0]), strcmp_compar);

	if (idx)
		cmdv[found++] = dollar_comp ? "${...}" : "...";

	cmdv[found] = NULL;
	return found;
}
#endif

#ifdef CONFIG_ENV_IMPORT_FDT
void env_import_fdt(void)
{
	const char *path;
	struct ofprop prop;
	ofnode node;
	int res;

	path = env_get("env_fdt_path");
	if (!path || !path[0])
		return;

	node = ofnode_path(path);
	if (!ofnode_valid(node)) {
		printf("Warning: device tree node '%s' not found\n", path);
		return;
	}

	for (res = ofnode_first_property(node, &prop);
	     !res;
	     res = ofnode_next_property(&prop)) {
		const char *name, *val;

		val = ofprop_get_property(&prop, &name, NULL);
		env_set(name, val);
	}
}
#endif
