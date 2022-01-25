/*
 * (C) Copyright 2020 Digi International, Inc.
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
#ifdef CONFIG_IMX_HAB
#include <asm/mach-imx/hab.h>
#endif
#ifdef CONFIG_AHAB_BOOT
#include <asm/arch-imx8/image.h>
#endif

#ifdef CONFIG_AHAB_BOOT
static int container_is_encrypted(ulong addr, ulong *dek_addr)
{
	struct container_hdr *phdr;
	struct signature_block_hdr *sign_hdr;

	phdr = (struct container_hdr *)addr;
	if (phdr->tag != 0x87 && phdr->version != 0x0) {
		debug("Wrong container header at 0x%lx\n", addr);
		return 0;
	}

	if (phdr->sig_blk_offset != 0) {
		sign_hdr = (struct signature_block_hdr *)(addr + phdr->sig_blk_offset);
		if (sign_hdr->tag != 0x90 && sign_hdr->version != 0x0) {
			debug("Wrong Signature Block header at 0x%lx\n", addr + phdr->sig_blk_offset);
			return 0;
		}

		if (sign_hdr->blob_offset != 0) {
			*dek_addr = addr + phdr->sig_blk_offset + sign_hdr->blob_offset;
			return 1;
		}
	}

	return 0;
}
#endif

/*
 * Authenticate an image in RAM.
 *
 * This function authenticates the given image whether it is performed by
 * HAB or AHAB methods.
 *
 * For AHAB authentication, also increase the given start address to skip the
 * container header, resulting in the start address of the actual image file.
 *
 * If no secure boot method is defined, the authentication will be considered
 * as failed.
 *
 * Returns 0 on success, 1 on failure.
 */
int digi_auth_image(ulong *ddr_start, ulong raw_image_size)
{
	int ret = 1;

#if defined(CONFIG_IMX_HAB)
	if (authenticate_image((uint32_t)*ddr_start, raw_image_size) == 0)
		ret = 0;
#elif defined(CONFIG_AHAB_BOOT)
	extern int authenticate_os_container(ulong addr);
	extern int get_dek_blob(char *output, u32 *size);
	struct boot_img_t *img;
	struct generate_key_blob_hdr *dek_hdr;
	ulong dek_addr = 0;
	u32 dek_blob_size;

	if (container_is_encrypted((ulong)*ddr_start, &dek_addr)) {
		if(dek_addr != 0) {
			dek_hdr = (struct generate_key_blob_hdr *)dek_addr;
			if (dek_hdr->tag != 0x81 && dek_hdr->version != 0x0) {
				/* If there is not a valid DEK blob in the container, DEK blob
				 * from the running U-Boot is recovered and copied into it.
				 * (This fails if the running U-Boot does not include a DEK)
				 */
				if (!get_dek_blob((void *)dek_addr, &dek_blob_size))
					printf("   Using current DEK\n");
				else
					printf("   ERROR: Current U-Boot does not contain a DEK\n");
			}
		}
	}

	if (authenticate_os_container((ulong)*ddr_start) == 0) {
		ret = 0;
		/* Each OS container can have multiple images inside,
		 * and to calculate the address the image index is required.
		 * In this case each container will have only one image,
		 * therefore the index is 0.
		 */
		img = (struct boot_img_t *)(*ddr_start +
					    sizeof(struct container_hdr) +
					    0 * sizeof(struct boot_img_t));
		*ddr_start = img->dst;
	}
#endif

	return ret;
}
