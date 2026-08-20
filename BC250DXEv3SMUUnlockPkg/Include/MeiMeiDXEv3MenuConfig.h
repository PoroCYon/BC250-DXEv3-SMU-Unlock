/** @file
  MeiMeiDXEv3MenuConfig.h

  Shared SMU configuration variable definition for the MeiMeiDXEv3 family of
  drivers.

  The canonical definition lives in the BC250-DXEv3-Menu-Driver
  (BC250DXEv3MenuDriverPkg/BC250DXEv3MenuDriver/BC250DXEv3MenuDriver.h).  This
  header is a copy imported here so this package does not depend on the menu
  driver package.

  The menu driver stores the SMU settings in one non-volatile variable,
  MeiMeiDXEv3SmuVar, which this driver consumes to decide whether the SMU
  secure-access unlock should be performed.

  Copyright (C) 2026 RescueMei
  SPDX-License-Identifier: MIT
**/

#ifndef __MEIMEIDXEV3_MENU_CONFIG_H__
#define __MEIMEIDXEV3_MENU_CONFIG_H__

//
// The menu driver stores the SMU settings in one non-volatile variable.
//
#define MEIMEIDXEV3_SMU_VAR_NAME       L"MeiMeiDXEv3SmuVar"

#define MEIMEIDXEV3_CONFIG_VAR_GUID \
  { 0x49CC168D, 0xE8B0, 0x4613, { 0xA8, 0x07, 0x16, 0x96, 0x99, 0x86, 0x72, 0x6F } }

#define MEIMEIDXEV3_CONFIG_VAR_ATTRIBUTES  \
  (EFI_VARIABLE_BOOTSERVICE_ACCESS |        \
   EFI_VARIABLE_RUNTIME_ACCESS    |        \
   EFI_VARIABLE_NON_VOLATILE)

//
// SMU configuration layout (2 bytes), identical to the menu driver definition.
// All fields are single-byte booleans (0 = disabled, 1 = enabled).
//
typedef struct {
  UINT8  SmuUnlock;
  UINT8  SmuReportingPatch;
} SMU_CONFIG;

#endif // __MEIMEIDXEV3_MENU_CONFIG_H__
