/*
 * Copyright (C) 2016-2024, Digi International Inc.
 *
 * See file CREDITS for list of people who contributed to this
 * project.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston,
 * MA 02111-1307 USA
 */

#include <common.h>
#include <command.h>
#include <fuse.h>
#include <asm/mach-imx/hab.h>
#include <memalign.h>

#include "../board/digi/common/helper.h"
#include "../board/digi/common/trustfence.h"

#define ALIGN_UP(x, a) (((x) + (a - 1)) & ~(a - 1))
#define DMA_ALIGN_UP(x) ALIGN_UP(x, ARCH_DMA_MINALIGN)

static int do_trustfence(struct cmd_tbl *cmdtp, int flag, int argc, char *const argv[])
{
	const char *op;
	int confirmed = argc >= 3 && !strcmp(argv[2], "-y");
	u32 val[2], addr;
	int ret = -1;
	struct load_fw fwinfo;

	if (argc < 2)
		return CMD_RET_USAGE;

	memset(&fwinfo, 0, sizeof(fwinfo));

	op = argv[1];
	argc -= 2 + confirmed;
	argv += 2 + confirmed;

	if (!strcmp(op, "prog_srk")) {
		if (argc < 2)
			return CMD_RET_USAGE;

		if (!confirmed && !confirm_prog())
			return CMD_RET_FAILURE;

		ret = fuse_check_srk();
		if (ret == 0) {
			puts("SRK efuses are already burned!\n");
			return CMD_RET_FAILURE;
		} else if (ret < 0) {
			goto err;
		}

		if (strtou32(argv[0], 16, &addr))
			return CMD_RET_USAGE;

		if (strtou32(argv[1], 16, &val[0]))
			return CMD_RET_USAGE;

		puts("Programming SRK efuses... ");
		fuse_allow_prog(true);
		ret = fuse_prog_srk(addr, val[0]);
		fuse_allow_prog(false);
		if (ret)
			goto err;
		puts("[OK]\n");
	} else if (!strcmp(op, "close")) {
		puts("Checking SRK bank...\n");
		ret = fuse_check_srk();
		if (ret > 0) {
			puts("[ERROR] Burn the SRK OTP bits before "
			     "closing the device.\n");
			return CMD_RET_FAILURE;
		} else if (ret < 0) {
			goto err;
		} else {
			puts("[OK]\n\n");
		}

		if (close_device(confirmed))
			goto err;
		puts("[OK]\n");
	} else if (!strcmp(op, "revoke")) {
#if defined(CONFIG_IMX_HAB)
		if (argc < 1)
			return CMD_RET_USAGE;

		if (strtou32(argv[0], 16, &val[0]))
			return CMD_RET_FAILURE;

		if (val[0] == CONFIG_TRUSTFENCE_SRK_N_REVOKE_KEYS) {
			puts("Last key cannot be revoked.\n");
			return CMD_RET_FAILURE;
		} else if (val[0] > CONFIG_TRUSTFENCE_SRK_N_REVOKE_KEYS) {
			puts("Invalid key index.\n");
			return CMD_RET_FAILURE;
		}

		if (!confirmed && !confirm_prog())
			return CMD_RET_FAILURE;

		printf("Revoking key index %d...", val[0]);
		if (revoke_key_index(val[0]))
			goto err;
		puts("[OK]\n");
#elif defined(CONFIG_AHAB_BOOT)
		u32 revoke_mask = 0;
		if (get_srk_revoke_mask(&revoke_mask) != CMD_RET_SUCCESS) {
			printf("Failed to get revoke mask.\n");
			return CMD_RET_FAILURE;
		}

		if (revoke_mask) {
			printf("Following keys will be permanently revoked:\n");
			for (int i = 0; i <= CONFIG_TRUSTFENCE_SRK_N_REVOKE_KEYS; i++) {
				if (revoke_mask & (1 << i))
					printf("   Key %d\n", i);
			}
			if (revoke_mask & (1 << CONFIG_TRUSTFENCE_SRK_N_REVOKE_KEYS)) {
				puts("Key 3 cannot be revoked. Abort.\n");
				return CMD_RET_FAILURE;
			}
		} else {
			printf("No Keys to be revoked.\n");
			return CMD_RET_FAILURE;
		}

		if (!confirmed && !confirm_prog())
			return CMD_RET_FAILURE;

		printf("Revoking keys...");
		if (revoke_keys())
			goto err;
		puts("[OK]\n");
		if (!sense_key_status(&val[0])) {
			for (int i = 0; i < CONFIG_TRUSTFENCE_SRK_N_REVOKE_KEYS; i++) {
				if (val[0] & (1 << i))
					printf("   Key %d revoked\n", i);
			}
		}
#else
		printf("Command not implemented\n");
#endif
	} else if (!strcmp(op, "status")) {
		printf("* SRK fuses:\t\t");
		ret = fuse_check_srk();
		if (ret > 0) {
			printf("[NOT PROGRAMMED]\n");
		} else if (ret == 0) {
			puts("[PROGRAMMED]\n");
			/* Only show revocation status if the SRK fuses are programmed */
			if (!sense_key_status(&val[0])) {
				for (int i = 0; i <= CONFIG_TRUSTFENCE_SRK_N_REVOKE_KEYS; i++) {
					printf("   Key %d:\t\t", i);
					printf((val[0] & (1 << i) ? "[REVOKED]\n" : "[OK]\n"));
				}
			}
		} else {
			puts("[ERROR]\n");
		}

		printf("* Secure boot:\t\t%s", imx_hab_is_enabled() ?
		       "[CLOSED]\n" : "[OPEN]\n");
		trustfence_status();
#ifdef CONFIG_TRUSTFENCE_UPDATE
	} else if (!strcmp(op, "update")) {
		char cmd_buf[CONFIG_SYS_CBSIZE];
		unsigned long loadaddr = env_get_ulong("loadaddr", 16,
						      CONFIG_SYS_LOAD_ADDR);
		unsigned long uboot_size;
		unsigned long dek_size;
		unsigned long dek_blob_src;
		unsigned long dek_blob_dst;
		unsigned long dek_blob_final_dst;
		unsigned long uboot_start;
		u32 dek_blob_size;
#ifdef CONFIG_AHAB_BOOT
		u32 dek_blob_offset[2];
		unsigned long dek_blob_spl_final_dst;
#endif
#ifdef CONFIG_ARCH_IMX8M
		u32 dek_blob_spl_offset;
		unsigned long dek_blob_spl_final_dst;
		unsigned long fit_dek_blob_size = 96;
#endif
		int generate_dek_blob;
		uint8_t *buffer = NULL;

		argv -= 2 + confirmed;
		argc += 2 + confirmed;

		if (argc < 3)
			return CMD_RET_USAGE;

		/* Get source of firmware file */
		if (get_source(argc, argv, &fwinfo))
			return CMD_RET_FAILURE;

		if (!(
			(fwinfo.src == SRC_MMC && argc >= 5 ) ||
			((fwinfo.src == SRC_TFTP || fwinfo.src == SRC_NFS) && argc >= 4) ||
			(fwinfo.src == SRC_RAM && argc >= 4)
		   ))
			return CMD_RET_USAGE;

		if (fwinfo.src != SRC_RAM) {
			/* If not in RAM, load artifacts to RAM */

			printf("\nLoading encrypted U-Boot image...\n");
			/* Load firmware file to RAM */
			strcpy(fwinfo.loadaddr, "$loadaddr");
			strncpy(fwinfo.filename,
				(fwinfo.src == SRC_MMC) ? argv[4] : argv[3],
				sizeof(fwinfo.filename));
			ret = load_firmware(&fwinfo, NULL);
			if (ret == LDFW_ERROR) {
				printf("Error loading firmware file to RAM\n");
				return CMD_RET_FAILURE;
			}

			uboot_size = env_get_ulong("filesize", 16, 0);
#ifdef CONFIG_AHAB_BOOT
			/* DEK blob will be placed into the Signature Block */
			ret = get_dek_blob_offset(loadaddr, dek_blob_offset);
			if (ret != 0) {
				printf("Error getting the DEK Blob offset (%d)\n", ret);
				return CMD_RET_FAILURE;
			}
			dek_blob_spl_final_dst = loadaddr + dek_blob_offset[0];
			dek_blob_final_dst = loadaddr + dek_blob_offset[1];
#else
#ifdef CONFIG_ARCH_IMX8M
			ret = get_dek_blob_offset((void *)loadaddr, &dek_blob_spl_offset);
			if (ret != 0) {
				printf("Error getting the DEK Blob offset (%d)\n", ret);
				return CMD_RET_FAILURE;
			}
			/* Get SPL dek blob memory locations */
			dek_blob_spl_final_dst = loadaddr + dek_blob_spl_offset;
			/* DEK blob will be inserted in the dummy DEK location of the U-Boot image */
			dek_blob_final_dst = loadaddr + uboot_size - fit_dek_blob_size;
#else
			/* DEK blob will be directly appended to the U-Boot image */
			dek_blob_final_dst = loadaddr + uboot_size;
#endif // CONFIG_ARCH_IMX8M
#endif
			/*
			 * for the DEK blob source (DEK in plain text) we use the
			 * first 0x100 aligned memory address
			 */
			dek_blob_src = ((loadaddr + uboot_size) & 0xFFFFFF00) + 0x100;

			/*
			 * DEK destination also needs to be 0x100 aligned. Leave
			 * 0x400 = 1KiB to fit the DEK source
			 */
			dek_blob_dst = dek_blob_src + 0x400;

			debug("loadaddr:           0x%lx\n", loadaddr);
			debug("uboot_size:         0x%lx\n", uboot_size);
			debug("dek_blob_src:       0x%lx\n", dek_blob_src);
			debug("dek_blob_dst:       0x%lx\n", dek_blob_dst);
			debug("dek_blob_final_dst: 0x%lx\n", dek_blob_final_dst);
			debug("U-Boot:             [0x%lx,\t0x%lx]\n", loadaddr, loadaddr + uboot_size);

			printf("\nLoading Data Encryption Key...\n");
			if ((fwinfo.src == SRC_TFTP || fwinfo.src == SRC_NAND) &&
			    argc >= 5) {
				sprintf(cmd_buf, "%s 0x%lx %s", argv[2], dek_blob_src,
					argv[4]);
				generate_dek_blob = 1;
			} else if (fwinfo.src == SRC_MMC && argc >= 6) {
				sprintf(cmd_buf, "load mmc %s 0x%lx %s", argv[3],
					dek_blob_src, argv[5]);
				generate_dek_blob = 1;
			} else {
				generate_dek_blob = 0;
			}

			/* To generate the DEK blob, first load the DEK to RAM */
			if (generate_dek_blob) {
				debug("\tCommand: %s\n", cmd_buf);
				if (run_command(cmd_buf, 0))
					return CMD_RET_FAILURE;
				dek_size = env_get_ulong("filesize", 16, 0);
			}
		} else {
			/*
			 * If artifacts are in RAM, set up an aligned
			 * buffer to work with them.
			 */
			uboot_start = simple_strtoul(argv[3], NULL, 16);
			uboot_size = simple_strtoul(argv[4], NULL, 16);
			unsigned long dek_start = argc > 5 ? simple_strtoul(argv[5], NULL, 16) : 0;
			dek_size = argc > 6 ? simple_strtoul(argv[6], NULL, 16) : 0;

			/*
			 * This buffer will hold U-Boot, DEK and DEK blob. As
			 * this function progresses, it will hold the
			 * following:
			 *
			 * | <U-Boot> | <DEK> | <blank>
			 * | <U-Boot> | <DEK> | <DEK blob>
			 * | <U-Boot> <DEK-blob>
			 *
			 * Note: '|' represents the start of a
			 * DMA-aligned region.
			 */
			buffer = malloc_cache_aligned(DMA_ALIGN_UP(uboot_size) + 2 * DMA_ALIGN_UP(MAX_DEK_BLOB_SIZE));
			if (!buffer) {
				printf("Out of memory!\n");
				return CMD_RET_FAILURE;
			}

			dek_blob_src = (uintptr_t) (buffer + DMA_ALIGN_UP(uboot_size));
			dek_blob_dst = (uintptr_t) (buffer + DMA_ALIGN_UP(uboot_size) + DMA_ALIGN_UP(MAX_DEK_BLOB_SIZE));
#ifdef CONFIG_AHAB_BOOT
			/* DEK blob will be placed into the Signature Block */
			ret = get_dek_blob_offset(uboot_start, dek_blob_offset);
			if (ret != 0) {
				printf("Error getting the DEK Blob offset (%d)\n", ret);
				return CMD_RET_FAILURE;
			}
			dek_blob_spl_final_dst = (uintptr_t) (buffer + dek_blob_offset[0]);
			dek_blob_final_dst = (uintptr_t) (buffer + dek_blob_offset[1]);
#else
#ifdef CONFIG_SPL
			/* DEK blob will be directly inserted into the U-Boot image */
			ret = get_dek_blob_offset((void *)uboot_start, &dek_blob_spl_offset);
			if (ret != 0) {
				printf("Error getting the SPL DEK Blob offset (%d)\n", ret);
				return CMD_RET_FAILURE;
			}
			dek_blob_spl_final_dst = (uintptr_t) (buffer + dek_blob_spl_offset);
			/* DEK blob will be added to SPL dek blob location */
                        dek_blob_final_dst = (uintptr_t) (buffer + uboot_size - fit_dek_blob_size);
			debug("Buffer:             [0x%p,\t0x%p]\n", buffer, buffer + DMA_ALIGN_UP(uboot_size) + 4 * DMA_ALIGN_UP(MAX_DEK_BLOB_SIZE));
#else
			/* DEK blob will be directly appended to the U-Boot image */
			dek_blob_final_dst = (uintptr_t) (buffer + uboot_size);
			debug("Buffer:             [0x%p,\t0x%p]\n", buffer, buffer + DMA_ALIGN_UP(uboot_size) + 2 * DMA_ALIGN_UP(MAX_DEK_BLOB_SIZE));
#endif // CONFIG_SPL
#endif
			debug("dek_blob_src:       0x%lx\n", dek_blob_src);
			debug("dek_blob_dst:       0x%lx\n", dek_blob_dst);
			debug("dek_blob_final_dst: 0x%lx\n", dek_blob_final_dst);
			debug("ARCH_DMA_MINALIGN:  0x%x\n", ARCH_DMA_MINALIGN);
			debug("dma_(dek_blob):     0x%x\n", DMA_ALIGN_UP(MAX_DEK_BLOB_SIZE));
			debug("U-Boot:             [0x%p,\t0x%p]\n", buffer, buffer + uboot_size);

			memcpy(buffer, (void *)uboot_start, uboot_size);

			if (dek_start > 0 && dek_size > 0) {
				memcpy((void *)dek_blob_src, (void *)dek_start, dek_size);
				generate_dek_blob = 1;
			} else {
				generate_dek_blob = 0;
			}

			loadaddr = (uintptr_t) buffer;
		}

		/*
		 * The following if-else block is in charge of appending the
		 * DEK blob to 'dek_blob_final_dst'.
		 */
		if (generate_dek_blob) {
			/*
			 * If generate_dek_blob, then the DEK blob is generated from
			 * the DEK (at dek_blob_src) and then copied into its final
			 * destination.
			 */
			printf("\nGenerating DEK blob...\n");
			/* dek_blob takes size in bits */
			sprintf(cmd_buf, "dek_blob 0x%lx 0x%lx 0x%lx",
				dek_blob_src, dek_blob_dst, dek_size * 8);
			debug("\tCommand: %s\n", cmd_buf);
			if (run_command(cmd_buf, 0)) {
				ret = CMD_RET_FAILURE;
				goto tf_update_out;
			}

#ifdef CONFIG_AHAB_BOOT
			get_dek_blob_size(dek_blob_dst, &dek_blob_size);
#else
			/*
			 * Set dek_size to the size of the DEK blob, that is:
			 * header (8 bytes) + random AES-256 key (32 bytes)
			 * + DEK ('dek_size' bytes) + MAC (16 bytes)
			 */
			dek_blob_size = 8 + 32 + dek_size + 16;
#endif
			/* Copy DEK blob to its final destination */
                        memcpy((void *)dek_blob_final_dst, (void *)dek_blob_dst,
                                dek_blob_size);
#if defined(CONFIG_SPL)
			/* Copy SPL DEK blob to its final destination */
			memcpy((void *)dek_blob_spl_final_dst, (void *)dek_blob_dst,
				dek_blob_size);
#endif
		} else {
			/* If !generate_dek_blob, then the DEK blob from the running
			 * U-Boot is recovered and copied into its final
			 * destination. (This fails if the running U-Boot does not
			 * include a DEK)
			 */
#if defined(CONFIG_SPL)
			if (get_dek_blob(dek_blob_spl_final_dst, &dek_blob_size)) {
				printf("Current U-Boot does not contain an SPL DEK, and a new SPL DEK was not provided\n");
				ret = CMD_RET_FAILURE;
				goto tf_update_out;
			}
#endif
			if (get_dek_blob(dek_blob_final_dst, &dek_blob_size)) {
				printf("Current U-Boot does not contain a DEK, and a new DEK was not provided\n");
				ret = CMD_RET_FAILURE;
				goto tf_update_out;
			}
			printf("Using current DEK\n");
		}

		printf("\nFlashing U-Boot partition...\n");
#ifdef CONFIG_AHAB_BOOT
		sprintf(cmd_buf, "update uboot ram 0x%lx 0x%lx",
			loadaddr, uboot_size);
#else
#ifdef CONFIG_SPL
		sprintf(cmd_buf, "update uboot ram 0x%lx 0x%lx",
                        loadaddr,
                        uboot_size);
#else
		sprintf(cmd_buf, "update uboot ram 0x%lx 0x%lx",
			loadaddr,
			dek_blob_final_dst + dek_blob_size - loadaddr);
#endif // CONFIG_SPL
#endif
		debug("\tCommand: %s\n", cmd_buf);
		env_set("forced_update", "y");
		ret = run_command(cmd_buf, 0);
		env_set("forced_update", "n");

tf_update_out:
		free(buffer);
		if (ret) {
			printf("Operation failed!\n");
			return CMD_RET_FAILURE;
		}
#endif /* CONFIG_TRUSTFENCE_UPDATE */
#ifdef CONFIG_TRUSTFENCE_JTAG
	} else if (!strcmp(op, "jtag")) {
		char jtag_op[15];
		int i;
		u32 bank = CONFIG_TRUSTFENCE_JTAG_MODE_BANK;
		u32 word = CONFIG_TRUSTFENCE_JTAG_MODE_START_WORD;
		if (!strcmp(argv[0], "read")) {
			printf("Reading Secure JTAG mode: ");
			ret = fuse_read(bank, word, &val[0]);
			if (ret)
				goto err;
			board_print_trustfence_jtag_mode(val);
		} else if (!strcmp(argv[0], "read_key")) {
			bank = CONFIG_TRUSTFENCE_JTAG_KEY_BANK;
			word = CONFIG_TRUSTFENCE_JTAG_KEY_START_WORD;
			printf("Reading response key: ");
			for (i = 0; i < CONFIG_TRUSTFENCE_JTAG_KEY_WORDS_NUMBER; i++, word++) {
				ret = fuse_read(bank, word, &val[i]);
				if (ret)
					goto err;
			}
			board_print_trustfence_jtag_key(val);
		} else if (!strcmp(argv[0], "prog")) {
			if (!confirmed && !confirm_prog())
				return CMD_RET_FAILURE;

			if (argc < 1)
				return CMD_RET_USAGE;

			snprintf(jtag_op, sizeof(jtag_op), "%s", argv[1]);

			printf("Programming Secure JTAG mode... ");
			if (!strcmp(jtag_op, "secure")) {
				ret = fuse_prog(bank, word, TRUSTFENCE_JTAG_ENABLE_SECURE_JTAG_MODE);
			} else if (!strcmp(jtag_op, "disable-debug")) {
				ret = fuse_prog(bank, word, TRUSTFENCE_JTAG_DISABLE_DEBUG);
			} else if (!strcmp(jtag_op, "disable-jtag")) {
				ret = fuse_prog(bank, word, TRUSTFENCE_JTAG_DISABLE_JTAG);
			} else {
				printf("\nWrong parameter.\n");
				ret = CMD_RET_USAGE;
				goto err;
			}
			if (ret)
				goto err;
			printf("[OK]\n");
		} else if (!strcmp(argv[0], "prog_key")) {
			if (argc < CONFIG_TRUSTFENCE_JTAG_KEY_WORDS_NUMBER)
				return CMD_RET_USAGE;

			if (!confirmed && !confirm_prog())
				return CMD_RET_FAILURE;
			printf("Programming response key... ");
			/* Write backwards, from MSB to LSB */
			word = CONFIG_TRUSTFENCE_JTAG_KEY_START_WORD +
				CONFIG_TRUSTFENCE_JTAG_KEY_WORDS_NUMBER - 1;
			bank = CONFIG_TRUSTFENCE_JTAG_KEY_BANK;
			for (i = 0; i < CONFIG_TRUSTFENCE_JTAG_KEY_WORDS_NUMBER; i++, word--) {
				if (strtou32(argv[i+1], 16, &val[i])) {
					ret = CMD_RET_USAGE;
					goto err;
				}

				ret = fuse_prog(bank, word, val[i]);
				if (ret)
					goto err;
			}
			printf("[OK]\n");
#if defined CONFIG_TRUSTFENCE_JTAG_OVERRIDE
		} else if (!strcmp(argv[0], "override")) {
			if (argc < 1)
				return CMD_RET_USAGE;

			snprintf(jtag_op, sizeof(jtag_op), "%s", argv[1]);

			printf("Overriding Secure JTAG mode... ");
			if (!strcmp(jtag_op, "secure")) {
				ret = fuse_override(bank, word, TRUSTFENCE_JTAG_ENABLE_SECURE_JTAG_MODE);
			} else if (!strcmp(jtag_op, "disable-debug")) {
				ret = fuse_override(bank, word, TRUSTFENCE_JTAG_DISABLE_DEBUG);
			} else if (!strcmp(jtag_op, "disable-jtag")) {
				ret = fuse_override(bank, word, TRUSTFENCE_JTAG_DISABLE_JTAG);
			} else if (!strcmp(jtag_op, "enable-jtag")) {
				ret = fuse_override(bank, word, TRUSTFENCE_JTAG_ENABLE_JTAG);
			} else {
				printf("\nWrong parameter.\n");
				ret = CMD_RET_USAGE;
				goto err;
			}
			if (ret)
				goto err;
			printf("[OK]\n");
		} else if (!strcmp(argv[0], "override_key")) {
			if (argc < CONFIG_TRUSTFENCE_JTAG_KEY_WORDS_NUMBER)
				return CMD_RET_USAGE;

			printf("Overriding response key... ");
			/* Write backwards, from MSB to LSB */
			word = CONFIG_TRUSTFENCE_JTAG_KEY_START_WORD + CONFIG_TRUSTFENCE_JTAG_KEY_WORDS_NUMBER - 1;
			bank = CONFIG_TRUSTFENCE_JTAG_KEY_BANK;
			for (i = 0; i < CONFIG_TRUSTFENCE_JTAG_KEY_WORDS_NUMBER; i++, word--) {
				if (strtou32(argv[i+1], 16, &val[i])) {
					ret = CMD_RET_USAGE;
					goto err;
				}

				ret = fuse_override(bank, word, val[i]);
				if (ret)
					goto err;
			}
			printf("[OK]\n");
#endif
		} else if (!strcmp(argv[0], "lock")) {
			if (!confirmed && !confirm_prog())
				return CMD_RET_FAILURE;
			printf("Locking Secure JTAG mode... ");
			ret = fuse_prog(OCOTP_LOCK_BANK,
					OCOTP_LOCK_WORD,
					CONFIG_TRUSTFENCE_JTAG_LOCK_FUSE);
			if (ret)
				goto err;
			printf("[OK]\n");
			printf("Locking of the Secure JTAG will be effective when the CPU is reset\n");
		} else if (!strcmp(argv[0], "lock_key")) {
			if (!confirmed && !confirm_prog())
				return CMD_RET_FAILURE;
			printf("Locking response key... ");
			ret = fuse_prog(OCOTP_LOCK_BANK,
					OCOTP_LOCK_WORD,
					CONFIG_TRUSTFENCE_JTAG_KEY_LOCK_FUSE);
			if (ret)
				goto err;
			printf("[OK]\n");
			printf("Locking of the response key will be effective when the CPU is reset\n");
		} else {
			return CMD_RET_USAGE;
		}
#endif /* CONFIG_TRUSTFENCE_JTAG */
	} else {
		printf("[ERROR]\n");
		return CMD_RET_USAGE;
	}

	return 0;

err:
	puts("[ERROR]\n");
	return ret;
}

U_BOOT_CMD(
	trustfence, CONFIG_SYS_MAXARGS, 0, do_trustfence,
	"Digi Trustfence(TM) command",
	"\r-- SECURE BOOT --\n"
	"trustfence status - show secure boot configuration status\n"
	"trustfence prog_srk [-y] <ram addr> <size in bytes> - burn SRK efuses (PERMANENT)\n"
	"trustfence close [-y] - close the device so that it can only boot "
			      "signed images (PERMANENT)\n"
#if defined(CONFIG_IMX_HAB)
	"trustfence revoke [-y] <key index> - revoke one Super Root Key (PERMANENT)\n"
#elif defined(CONFIG_AHAB_BOOT)
	"trustfence revoke [-y] - revoke one or more Super Root Keys as per the SRK_REVOKE_MASK given at build time in the CSF (PERMANENT)\n"
#endif
#ifdef CONFIG_TRUSTFENCE_UPDATE
	"trustfence update <source> [extra-args...]\n"
	" Description: flash an encrypted U-Boot image.\n"
	" Arguments:\n"
	"\n\t- <source>: tftp|nfs|mmc|ram\n"
	"\n\tsource=tftp|nfs -> <uboot_file> [<dek_file>]\n"
	"\t\t - <uboot_file>: name of the encrypted uboot image\n"
	"\t\t - <dek_file>: name of the Data Encryption Key (DEK) in plain text\n"
	"\n\tsource=mmc -> <dev:part> <uboot_file> [<dek_file>]\n"
	"\t\t - <dev:part>: number of device and partition\n"
	"\t\t - <uboot_file>: name of the encrypted uboot image\n"
	"\t\t - <dek_file>: name of the Data Encryption Key (DEK) in plain text.\n"
	"\n\tsource=ram -> <uboot_start> <uboot_size> [<dek_start> <dek_size>]\n"
	"\t\t - <uboot_start>: U-Boot binary memory address\n"
	"\t\t - <uboot_size>: size of U-Boot binary (in bytes)\n"
	"\t\t - <dek_start>: Data Encryption Key (DEK) memory address\n"
	"\t\t - <dek_size>: size of DEK (in bytes)\n"
	"\n"
	" Note: the DEK arguments are optional if the current U-Boot is encrypted.\n"
	"       If skipped, the current DEK will be re-used\n"
	"\n"
#endif /* CONFIG_TRUSTFENCE_UPDATE */
#ifdef CONFIG_TRUSTFENCE_JTAG
	"WARNING: These commands (except 'status' and 'update') burn the eFuses.\n"
	"They are irreversible and could brick your device.\n"
	"Make sure you know what you do before playing with this command.\n"
	"\n"
	"-- SECURE JTAG --\n"
	"trustfence jtag read - read Secure JTAG mode from shadow registers\n"
	"trustfence jtag read_key - read Secure JTAG response key from shadow registers\n"
	"trustfence jtag [-y] prog <mode> - program Secure JTAG mode <mode> (PERMANENT). <mode> can be one of:\n"
	"    secure - Secure JTAG mode (debugging only possible by providing the key "
	"burned in the e-fuses)\n"
	"    disable-debug - JTAG debugging disabled (only boundary-scan possible)\n"
	"    disable-jtag - JTAG port disabled (no JTAG operations allowed)\n"
	"trustfence jtag [-y] prog_key <high_word> <low_word> - program response key (PERMANENT)\n"
#if defined CONFIG_TRUSTFENCE_JTAG_OVERRIDE
	"trustfence jtag override <mode> - override Secure JTAG mode <mode>. <mode> can be one of:\n"
	"    secure - Secure JTAG mode (debugging only possible by providing the key "
	"burned in the e-fuses)\n"
	"    disable-debug - JTAG debugging disabled (only boundary-scan possible)\n"
	"    disable-jtag - JTAG port disabled (no JTAG operations allowed)\n"
	"    enable-jtag - JTAG port enabled (JTAG operations allowed)\n"
	"trustfence jtag override_key <high_word> <low_word> - override response key\n"
#endif
	"trustfence jtag [-y] lock - lock Secure JTAG mode and disable JTAG interface "
				"OTP bits (PERMANENT)\n"
	"trustfence jtag [-y] lock_key - lock Secure JTAG key OTP bits (PERMANENT)\n"
#endif /* CONFIG_TRUSTFENCE_JTAG */
);
