/** @file
  MeiMeiDXEv3MenuConfig.h

  Shared configuration variable definitions for the MeiMeiDXEv3 family of
  drivers.

  The canonical definitions live in the BC250-DXEv3-Menu-Driver
  (BC250DXEv3MenuDriverPkg/BC250DXEv3MenuDriver/BC250DXEv3MenuDriver.h).  This
  header is a copy imported here so this package does not depend on the menu
  driver package.

  The menu driver stores the options for each feature in its own non-volatile
  variable.  All variables share the same vendor GUID and differ only by name:

    MeiMeiDXEv3AcpiVar       ACPI_CONFIG         AcpiPatch
    MeiMeiDXEv3SmuUnlockVar  SMU_UNLOCK_CONFIG   SmuUnlock
    MeiMeiDXEv3SmuPatchVar   SMU_PATCH_CONFIG    SmuReportingPatch
    MeiMeiDXEv3CoreVar       CORE_CONFIG         CoreUnlock + Core0..Core7

  This package consumes the SMU unlock variable to decide whether the SMU
  secure-access unlock should be performed.

  Copyright (C) 2026 RescueMei
  SPDX-License-Identifier: MIT
**/

#ifndef __MEIMEIDXEV3_MENU_CONFIG_H__
#define __MEIMEIDXEV3_MENU_CONFIG_H__

//
// The menu driver stores each feature in its own non-volatile variable.
//
#define MEIMEIDXEV3_ACPI_VAR_NAME        L"MeiMeiDXEv3AcpiVar"
#define MEIMEIDXEV3_SMU_UNLOCK_VAR_NAME  L"MeiMeiDXEv3SmuUnlockVar"
#define MEIMEIDXEV3_SMU_PATCH_VAR_NAME   L"MeiMeiDXEv3SmuPatchVar"
#define MEIMEIDXEV3_CORE_VAR_NAME        L"MeiMeiDXEv3CoreVar"

#define MEIMEIDXEV3_CONFIG_VAR_GUID \
  { 0x49CC168D, 0xE8B0, 0x4613, { 0xA8, 0x07, 0x16, 0x96, 0x99, 0x86, 0x72, 0x6F } }

#define MEIMEIDXEV3_CONFIG_VAR_ATTRIBUTES  \
  (EFI_VARIABLE_BOOTSERVICE_ACCESS |        \
   EFI_VARIABLE_RUNTIME_ACCESS    |        \
   EFI_VARIABLE_NON_VOLATILE)

//
// CoreUnlock states.
//
#define CORE_UNLOCK_DISABLED      0U
#define CORE_UNLOCK_ALL_CORES     1U
#define CORE_UNLOCK_CUSTOM        2U

//
// Configuration layouts, identical to the menu driver definitions.  All
// fields are single-byte UINT8 values; boolean fields use 0 = disabled,
// 1 = enabled.
//
typedef struct {
  UINT8  AcpiPatch;
} ACPI_CONFIG;

typedef struct {
  UINT8  SmuUnlock;
} SMU_UNLOCK_CONFIG;

typedef struct {
  UINT8  SmuReportingPatch;
} SMU_PATCH_CONFIG;

typedef struct {
  UINT8  CoreUnlock;
  UINT8  Core0;
  UINT8  Core1;
  UINT8  Core2;
  UINT8  Core3;
  UINT8  Core4;
  UINT8  Core5;
  UINT8  Core6;
  UINT8  Core7;
} CORE_CONFIG;

#endif // __MEIMEIDXEV3_MENU_CONFIG_H__