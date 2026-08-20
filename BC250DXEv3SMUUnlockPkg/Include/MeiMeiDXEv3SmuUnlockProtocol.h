/** @file
  MeiMeiDXEv3SmuUnlockProtocol.h

  Marker protocol published by the BC-250 DXEv3 SMU secure-access unlock
  driver once it has run on this boot.

  Consumers (the SMU patch driver and the SMU core-unlock driver) list this
  protocol GUID in their [Depex] so the DXE dispatcher will not load them
  before the unlock driver has executed.  It is a pure ordering marker: the
  unlock driver installs it unconditionally, and consumers keep their own
  runtime probes to decide whether the gated SMU interface is actually usable.

  Copyright (C) 2026 RescueMei
  SPDX-License-Identifier: MIT
**/

#ifndef __MEIMEIDXEV3_SMU_UNLOCK_PROTOCOL_H__
#define __MEIMEIDXEV3_SMU_UNLOCK_PROTOCOL_H__

#include <Uefi.h>

typedef struct _MEIMEIDXEV3_SMU_UNLOCK_PROTOCOL  MEIMEIDXEV3_SMU_UNLOCK_PROTOCOL;

//
// Marker protocol instance.  The Revision field identifies the unlock
// sequence version; consumers that need to know the interface version may
// inspect it, but none currently do.
//
struct _MEIMEIDXEV3_SMU_UNLOCK_PROTOCOL {
  UINT32  Revision;
};

#endif // __MEIMEIDXEV3_SMU_UNLOCK_PROTOCOL_H__