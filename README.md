# BC250-DXEv3-SMU-Unlock

DXE driver for the BC-250 that performs rw-r-r-0644's SMU secure-access unlock.

This unlocks the SMU's secure access functions to allow for arbitrary SMU reads, writes, and code execution. The driver is a C port of rw-r-r-0644's Python proof-of-concept:

https://github.com/rw-r-r-0644/bc250-smu-unlock

## How it works

The unlock exploits a bug in SMU Queue 2 message `0x23` (subqueue-ring append). The overflow is used to redirect the SMU's transfer-table pointer, allowing a fake transfer table to be staged in SMU-local SRAM. That table is then used (through the ungated Q2 message `0x0A` transfer-engine DMA interface) to zero the SMU's debug-disable guard word at SMU-local `0x7B3C`. With the guard removed, the gated Q3 secure-access messages become callable, giving access to:

- arbitrary SMU-local SRAM read/write (messages `0x28`/`0x29`)
- arbitrary SMN read/write through the mem64 window (messages `0x2A`/`0x2B`/`0x2C`)

Finally the driver fixes up the SMU state so that only the guard word differs from its boot-time value.

# NOTE: The rw-r-r-0644's repo was BIOS 3 only - patches and offsets differ for BIOS 5 SMU firmware so this driver will not work on BIOS 5 either.

## Behavior

At dispatch time the driver:

1. Reads the shared `MeiMeiDXEv3SmuUnlockVar` configuration variable owned by the BC250-DXEv3-Menu-Driver.
2. If the `SmuUnlock` field (byte offset 0) is zero, or the variable is absent/malformed, the driver logs and exits without touching the SMU (fail-closed).
3. Otherwise it performs the unlock:
   1. Verifies the SMU is alive (Q3 test message).
   2. Probes the secure-access gate (Q3 msg `0x2A`).
   3. Reads the debug-disable guard; if already unlocked, exits silently.
   4. Locates a zero-filled dead zone below SMU-local `0x7B20`.
   5. Stages a fake transfer table in DRAM and DMA's it into SMU SRAM.
   6. Re-arms the transfer table and DMA's a zeroed count word so the guard at `0x7B3C` is cleared.
   7. Verifies the gate is open and the SMU is still alive.
   8. Fixes up the SMU state (clears the staged zone and ring slots, restores the transfer-table pointer).

The driver is fail-closed and fire-and-forget: any failure is logged and the normal boot path continues.

## Configuration

The driver consumes the `MeiMeiDXEv3SmuUnlockVar` variable defined by the BC250-DXEv3-Menu-Driver:

| Item | Value |
| --- | --- |
| Variable name | `MeiMeiDXEv3SmuUnlockVar` |
| Vendor GUID | `49CC168D-E8B0-4613-A807-16969986726F` |
| Attributes | `BOOTSERVICE_ACCESS` \| `RUNTIME_ACCESS` \| `NON_VOLATILE` |

The unlock is gated by the `SmuUnlock` byte at offset 0 of the 1-byte `SMU_UNLOCK_CONFIG` structure. If the variable does not exist (the menu driver's "all zeros" default), the unlock is not performed. The shared definitions live in `BC250DXEv3SMUUnlockPkg/Include/MeiMeiDXEv3MenuConfig.h`.

## Build

The build helper builds the DXE driver and emits both `.efi` and `.ffs` artifacts.

### Container build

```bash
./build_ffs.sh
```

### Host build

Requirements:

- an existing EDK II workspace
- built BaseTools

```bash
NO_CONTAINER=1 EDK2_DIR=/path/to/edk2 ./build_ffs.sh
```

## Output

Artifacts are written to:

- `Build/Output/MeiMeiDXEv3_SMU_Unlock.efi`
- `Build/Output/MeiMeiDXEv3_SMU_Unlock.ffs`

The `.ffs` can be inserted into an AMI DXE firmware volume with UEFITool.

## Credit

- [rw-r-r-0644](https://github.com/rw-r-r-0644) for the original SMU unlock implementation and research.
