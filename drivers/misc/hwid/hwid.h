/*
 * Copyright (C) 2021 XiaoMi, Inc.
 *               2022 The LineageOS Project
 *
 * SPDX-License-Identifier: GPL-2.0
 */

#ifndef __HWID_H__
#define __HWID_H__

#include <linux/types.h>

#define HARDWARE_PROJECT_UNKNOWN    0
#define HARDWARE_PROJECT_L1         6 // thor
#define HARDWARE_PROJECT_L1A        7 // loki
#define HARDWARE_PROJECT_L2         1 // zeus
#define HARDWARE_PROJECT_L2S        8 // unicorn
#define HARDWARE_PROJECT_L3         2 // cupid
#define HARDWARE_PROJECT_L3S        12 // mayfly
#define HARDWARE_PROJECT_L9S        9 // ziyi
#define HARDWARE_PROJECT_L10        4 // ingres
#define HARDWARE_PROJECT_L12        10 // diting
#define HARDWARE_PROJECT_L18        5 // zizhan
#define HARDWARE_PROJECT_M11A       14 // mondrian
#define HARDWARE_PROJECT_M16T       15 // marble
#define HARDWARE_PROJECT_M80        11 // yudi

typedef enum {
	CountryCN = 0x00,
	CountryGlobal = 0x01,
	CountryIndia = 0x02,
	CountryJapan = 0x03,
	INVALID = 0x04,
	CountryIDMax = 0x7FFFFFFF
} CountryType;

uint32_t get_hw_version_platform(void);
uint32_t get_hw_id_value(void);
uint32_t get_hw_country_version(void);
uint32_t get_hw_version_major(void);
uint32_t get_hw_version_minor(void);
uint32_t get_hw_version_build(void);

#endif /* __HWID_H__ */
