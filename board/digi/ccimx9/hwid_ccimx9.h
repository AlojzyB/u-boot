/*
 * Copyright 2022 Digi International Inc
 *
 * SPDX-License-Identifier:	GPL-2.0+
 */

#ifndef HWID_CCIMX9_H
#define HWID_CCIMX9_H

/*
 * HWID is stored in 3 consecutive Fuse Words, being:
 *
 *   MAC1_ADDR[31:0]  (bank 39 word 3)
 *
 *   |  31..26  |  25..20  |            19..0           |
 *   +----------+----------+----------------------------+
 *   |   Year   |   Week   |        Serial number       |
 *   +----------+----------+----------------------------+
 *
 *   MAC2_ADDR[47:32],MAC1_ADDR[47:32]  (bank 39 word 4)
 *
 *   | 31..28 |  27..24  |             23..0            |
 *   +--------+----------+------------------------------+
 *   |  GenID | MAC pool |            MAC base          |
 *   +--------+----------+------------------------------+
 *
 *   MAC2_ADDR[31:0]  (bank 39 word 5)
 *
 *   | 31..20 |   19   | 18 |   17  |  16 |15..12|  11..7  |6..3| 2..0 |
 *   +--------+--------+----+-------+-----+------+---------+----+------+
 *   |   --   | Crypto | BT | Wi-Fi | MCA |  RAM | Variant | HV | Cert |
 *   +--------+--------+----+-------+-----+------+---------+----+------+
 */
struct __packed digi_hwid {
	/* Word 0 */
	u32	sn:20;		/* serial number */
	u32	week:6;		/* manufacturing week */
	u32	year:6;		/* manufacturing year */
	/* Word 1 */
	u32	mac_base:24;	/* MAC base address */
	u32	mac_pool:4;	/* MAC address pool */
	u32	genid:4;	/* generator id */
	/* Word 2 */
	u32	cert:3;		/* type of wifi certification */
	u32	hv:4;		/* hardware version */
	u32	variant:5;	/* module variant */
	u32	ram:4;		/* RAM */
	u32	mca:1;		/* has MCA */
	u32	wifi:1;		/* has Wi-Fi */
	u32	bt:1;		/* has Bluetooth */
	u32	crypto:1;	/* has crypto-authentication */
	u32	spare:12;	/* spare */
}__aligned(4);

#define CONFIG_HWID_STRINGS_HELP	"<XXXXXXXX> <YYYYYYYY> <ZZZZZZZZ>"
#define CONFIG_MANUF_STRINGS_HELP	"<YYWWGGXXXXXX> <PPAAAAAA> <VVHC> <RMWBC>"
#define DIGICMD_HWID_SUPPORTED_OPTIONS_HELP \
	     "read - read HWID from shadow registers\n" \
	"hwid read_manuf - read HWID from shadow registers and print manufacturing ID\n" \
	"hwid sense - sense HWID from fuses\n" \
	"hwid sense_manuf - sense HWID from fuses and print manufacturing ID\n" \
	"hwid prog [-y] " CONFIG_HWID_STRINGS_HELP " - program HWID (PERMANENT)\n" \
	"hwid prog_manuf [-y] " CONFIG_MANUF_STRINGS_HELP " - program HWID with manufacturing ID (PERMANENT)\n" \
	"hwid override " CONFIG_HWID_STRINGS_HELP " - override HWID\n" \
	"hwid override_manuf " CONFIG_MANUF_STRINGS_HELP " - override HWID with manufacturing ID\n" \
	"hwid lock [-y] - lock HWID OTP bits (PERMANENT)\n"

#endif /* HWID_CCIMX9_H */
