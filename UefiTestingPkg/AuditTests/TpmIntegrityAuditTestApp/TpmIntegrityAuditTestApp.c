/**
  @file -- TpmIntegrityAuditTestApp.c
Audit test to check the integrity of TPM Event Logs.
Compare PCR Digest of TPM Device against Digest from Event Log Memory
Copyright (C) Microsoft Corporation. All rights reserved.
SPDX-License-Identifier: BSD-2-Clause-Patent

**/
#include <Uefi.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/DebugLib.h>
#include <Library/Tpm2CommandLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/PrintLib.h>
#include <Library/BaseLib.h>
#include <Library/BaseCryptLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/UefiLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Library/UnitTestLib.h>
#include <Library/DevicePathLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/FileHandleLib.h>
#include <IndustryStandard/UefiTcgPlatform.h>
#include <IndustryStandard/Tpm20.h>
#include <Protocol/Tcg2Protocol.h>
#include <Protocol/ShellParameters.h>
#include <Guid/GlobalVariable.h>

#define MAX_PRINT_PCR_INDEX    8  // Maximum PCR index to print
#define UNIT_TEST_APP_NAME     "TpmIntegrityAuditTestApp"
#define UNIT_TEST_APP_VERSION  "1.0"
#define SHA256_STR_LEN         96 // String Length To Store 62 Digest Values with Separated Space
#define SHA_BUF_LEN            3  // String Buffer Length to store Value in 02x format including '\0'

UINT8  g_CurrentPcrValues[MAX_PRINT_PCR_INDEX][SHA256_DIGEST_SIZE];

typedef struct {
  UINT8     PcrIndex;
  CHAR16    *VariableDeleteName;
} BASIC_TEST_CONTEXT;

STATIC BASIC_TEST_CONTEXT  PcrTest0 = { 0, NULL };
STATIC BASIC_TEST_CONTEXT  PcrTest1 = { 1, NULL };
STATIC BASIC_TEST_CONTEXT  PcrTest2 = { 2, NULL };
STATIC BASIC_TEST_CONTEXT  PcrTest3 = { 3, NULL };
STATIC BASIC_TEST_CONTEXT  PcrTest4 = { 4, NULL };
STATIC BASIC_TEST_CONTEXT  PcrTest5 = { 5, NULL };
STATIC BASIC_TEST_CONTEXT  PcrTest6 = { 6, NULL };
STATIC BASIC_TEST_CONTEXT  PcrTest7 = { 7, NULL };

/*
  CleanUpTestContext

  Deallocate the buffers after test case completion.

*/
STATIC
VOID
EFIAPI
CleanUpTestContext (
  IN UNIT_TEST_CONTEXT  Context
  )
{
  BASIC_TEST_CONTEXT  *Btc;

  Btc = (BASIC_TEST_CONTEXT *)Context;

  if (NULL != Btc->VariableDeleteName) {
    gRT->SetVariable (
           Btc->VariableDeleteName,
           &gEfiGlobalVariableGuid,
           0,
           0,
           NULL
           );
  }

  Btc->VariableDeleteName = NULL;
  return;
}

/*
Convert the Digest Values into String.

  @param  EventPcrIndex   PCR Index[0-7] of Sha256 Bank
  @param  PcrIndexValues  A TPM Digest Structure which having PCR Values of TPM Device
  @param  EventIndex      A pointer to String Buffer which can store Digest Values of Event log in String format
  @param  TpmPcrIndex     A pointer to String Buffer which can store TPM Digest Values of TPM device in String format
*/
STATIC
VOID
ConvertDigestToString (
  IN  UINTN        EventPcrIndex,
  IN  TPML_DIGEST  PcrIndexValues,
  OUT CHAR8        *EventIndex,
  OUT CHAR8        *TpmPcrIndex
  )
{
  CHAR8  EventBuffer[SHA_BUF_LEN];

  for (UINTN i = EventPcrIndex; i <= EventPcrIndex; i++) {
    for (INTN j = 0; j < SHA256_DIGEST_SIZE; j++) {
      AsciiSPrint (EventBuffer, sizeof (EventBuffer), "%02x", g_CurrentPcrValues[i][j]);
      AsciiSPrint (EventBuffer, sizeof (EventBuffer), "%02x", PcrIndexValues.digests[i].buffer[j]);
      AsciiStrCatS (EventIndex, SHA256_STR_LEN, EventBuffer);
      AsciiStrCatS (TpmPcrIndex, SHA256_STR_LEN, EventBuffer);
      if (j < 31) {
        AsciiStrCatS (EventIndex, SHA256_STR_LEN, " ");
        AsciiStrCatS (TpmPcrIndex, SHA256_STR_LEN, " ");
      }
    }
  }
}

/*
  ParseEventLog

  Parse and process the boot-time event log entries to generate
  cummulative measurement digests

  @param  EventStartAddr
  @param  EventEndAddr

 */
EFI_STATUS
EFIAPI
ParseEventLog (
  IN  EFI_PHYSICAL_ADDRESS  EventStartAddr,
  IN  EFI_PHYSICAL_ADDRESS  EventEndAddr
  )
{
  TCG_PCR_EVENT2  *TcgPcrEvent2;
  UINT32          DigestCount;
  TPMI_ALG_HASH   HashAlgo;
  UINT8           *DigestBuffer;
  UINT32          DigestSize;
  UINT32          EventSize;
  UINT8           *EventBuffer;
  UINTN           DigestIndex;
  UINT8           NewPcrValue[SHA256_DIGEST_SIZE];
  VOID            *ShaCtx;
  EFI_STATUS      Status;

  ShaCtx = AllocatePool (Sha256GetContextSize ());
  if (ShaCtx == NULL) {
    DEBUG ((DEBUG_ERROR, "Failed to allocate SHA256 Buffer Context\n"));
    return EFI_OUT_OF_RESOURCES;
  }

  ZeroMem (NewPcrValue, SHA256_DIGEST_SIZE);

  TcgPcrEvent2 = (TCG_PCR_EVENT2 *)(UINTN)EventStartAddr;

  while ((UINTN)TcgPcrEvent2 <= EventEndAddr) {
    DigestCount  = TcgPcrEvent2->Digest.count;
    DigestBuffer = (UINT8 *)&TcgPcrEvent2->Digest.digests[0];
    for (DigestIndex = 0; DigestIndex < DigestCount; DigestIndex++) {
      CopyMem (&HashAlgo, DigestBuffer, sizeof (TPMI_ALG_HASH));
      DigestBuffer = DigestBuffer + sizeof (TPMI_ALG_HASH);
      DigestSize   = GetHashSizeFromAlgo (HashAlgo);
      if (DigestSize == 0) {
        DEBUG ((DEBUG_ERROR, "Unknown hash algorithm: 0x%04x\n", HashAlgo));
        FreePool (ShaCtx);
        return EFI_UNSUPPORTED;
      }

      // Update the cumulative Event hash for the corresponding PCR index
      if (TcgPcrEvent2->PCRIndex < MAX_PRINT_PCR_INDEX) {
        Status = Sha256Init (ShaCtx);
        if (EFI_ERROR (Status)) {
          DEBUG ((DEBUG_ERROR, "Sha256Init Failed Status:%r\n", Status));
          FreePool (ShaCtx);
          return Status;
        }

        Status = Sha256Update (ShaCtx, g_CurrentPcrValues[TcgPcrEvent2->PCRIndex], SHA256_DIGEST_SIZE);
        if (EFI_ERROR (Status)) {
          DEBUG ((DEBUG_ERROR, "Sha256Update Failed Status:%r\n", Status));
          FreePool (ShaCtx);
          return Status;
        }

        Status = Sha256Update (ShaCtx, DigestBuffer, DigestSize);
        if (EFI_ERROR (Status)) {
          DEBUG ((DEBUG_ERROR, "Sha256Update Digest on DataBuffer Failed Status:%r\n", Status));
          FreePool (ShaCtx);
          return Status;
        }

        Status = Sha256Final (ShaCtx, NewPcrValue);
        if (EFI_ERROR (Status)) {
          DEBUG ((DEBUG_ERROR, "Sha256Final Failed Status:%r\n", Status));
          FreePool (ShaCtx);
          return Status;
        }

        CopyMem (g_CurrentPcrValues[TcgPcrEvent2->PCRIndex], NewPcrValue, SHA256_DIGEST_SIZE);
      }

      DigestBuffer = DigestBuffer + DigestSize;
    }

    CopyMem (&EventSize, DigestBuffer, sizeof (UINT32));

    EventBuffer = DigestBuffer + sizeof (UINT32);

    TcgPcrEvent2 = (TCG_PCR_EVENT2 *)(EventBuffer + EventSize);
  }

  FreePool (ShaCtx);
  return EFI_SUCCESS;
}

/*
  Tpm2Sha256PCRRead

  Reads the specific PCR values from TPM 2.0.

  @param  PcrValues        A structure pointer to Point the TPM Digest
  @return SUCCESS          if Operation completed successfully.
  @return EFI_DEVICE_ERROR if operation fails.

*/
EFI_STATUS
EFIAPI
Tpm2Sha256PCRRead (
  OUT TPML_DIGEST  *PcrValues
  )
{
  EFI_STATUS          Status;
  TPML_PCR_SELECTION  PcrSelectionIn;
  TPML_PCR_SELECTION  PcrSelectionOut;
  UINT32              PcrUpdateCounter;

  ZeroMem (&PcrSelectionIn, sizeof (PcrSelectionIn));

  // prepare PCR Selection
  PcrSelectionIn.count                         = 1;
  PcrSelectionIn.pcrSelections[0].hash         = TPM_ALG_SHA256;
  PcrSelectionIn.pcrSelections[0].sizeofSelect = 3;

  /*
  In TPM2.0 PCR selection,
  pcrselect[0]: PCR[0-7](used for firmware/boot-related measurements and
  pcrselect[1]: PCR[8-15](OS defined), pcrselect[2]: PCR[16-23](Future/custom purpose)
  */
  PcrSelectionIn.pcrSelections[0].pcrSelect[0] = 0xFF;
  PcrSelectionIn.pcrSelections[0].pcrSelect[1] = 0x00;
  PcrSelectionIn.pcrSelections[0].pcrSelect[2] = 0x00;

  Status = Tpm2PcrRead (
             &PcrSelectionIn,
             &PcrUpdateCounter,
             &PcrSelectionOut,
             PcrValues
             );
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "Tpm2PcrRead Failed:%r\n", Status));
    return Status;
  }

  return EFI_SUCCESS;
}

/*
  TPMIntegrityTest to verify the integrity of TPM Event Logs

  @param  Context  A void Pointer
  @return SUCCESS  If the UNIT test Case Passed.
  @
*/
STATIC
UNIT_TEST_STATUS
EFIAPI
CheckTPMLogIntegrityTest (
  IN UNIT_TEST_CONTEXT  Context
  )
{
  TPML_DIGEST         PcrValues;
  BASIC_TEST_CONTEXT  *Btc;
  UINTN               PcrIndex;
  EFI_STATUS          Status;
  CHAR8               EventString[MAX_PRINT_PCR_INDEX][SHA256_STR_LEN];
  CHAR8               PcrString[MAX_PRINT_PCR_INDEX][SHA256_STR_LEN];

  Btc      = (BASIC_TEST_CONTEXT *)Context;
  PcrIndex = Btc->PcrIndex;

  ZeroMem (EventString, sizeof (EventString));
  ZeroMem (PcrString, sizeof (EventString));

  // Reads the PCR values
  Status = Tpm2Sha256PCRRead (&PcrValues);
  if (EFI_ERROR (Status)) {
    UT_LOG_ERROR ("Fetch PCR Values Return Status = %r, expected Status:%r\n", Status, EFI_SUCCESS);
    UT_ASSERT_STATUS_EQUAL (Status, EFI_SUCCESS);
  }

  INTN  result = CompareMem (g_CurrentPcrValues[PcrIndex], PcrValues.digests[PcrIndex].buffer, SHA256_DIGEST_SIZE);

  if (result != 0) {
    UT_LOG_ERROR ("Failure:TPM Device PCR %02x Digest Not matches with the Digest value generated from Event Log Memory\n", PcrIndex);
  } else {
    UT_LOG_INFO ("Success:TPM Device PCR %02x Digest matches with the Digest value generated from Event Log Memory\n", PcrIndex);
  }

  ConvertDigestToString (PcrIndex, PcrValues, EventString[PcrIndex], PcrString[PcrIndex]);

  // Log the Digest data to XML
  UT_LOG_INFO ("\nEVA_VALUE[%02d]: %a \n PCR_VALUE[%02d]:%a\n", PcrIndex, EventString[PcrIndex], PcrIndex, PcrString[PcrIndex]);

  return UNIT_TEST_PASSED;
}

/**
  Tpm2EventLogEntryPoint

  @param[in] ImageHandle  The firmware allocated handle for the EFI image.
  @param[in] SystemTable  A pointer to the EFI System Table.

  @retval EFI_SUCCESS     The entry point executed successfully.
  @retval other           Some error occurred when executing this entry point.

**/
EFI_STATUS
EFIAPI
TpmIntegrityAuditTestAppEntry (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_STATUS                  Status;
  UNIT_TEST_FRAMEWORK_HANDLE  Fw = NULL;
  UNIT_TEST_SUITE_HANDLE      TpmIntegrity;
  EFI_TCG2_PROTOCOL           *Tcg2Protocol;
  EFI_TCG2_EVENT_LOG_FORMAT   EventLogFormat = EFI_TCG2_EVENT_LOG_FORMAT_TCG_2;
  EFI_PHYSICAL_ADDRESS        EventStartAddr = 0;
  EFI_PHYSICAL_ADDRESS        EventEndAddr   = 0;
  BOOLEAN                     ELogTruncated  = FALSE;

  DEBUG ((DEBUG_ERROR, "%a()\n", __FUNCTION__));

  DEBUG ((DEBUG_ERROR, "%a v%a\n", UNIT_TEST_APP_NAME, UNIT_TEST_APP_VERSION));

  // Initialize UnitTest Framework.
  Status = InitUnitTestFramework (&Fw, UNIT_TEST_APP_NAME, gEfiCallerBaseName, UNIT_TEST_APP_VERSION);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "Failed in InitUnitTestFramework. Status = %r\n", Status));
    goto EXIT;
  }

  // Register the Test Suite.
  Status = CreateUnitTestSuite (&TpmIntegrity, Fw, "TPM Application to verify the integrity of TPM Event Logs.", "TpmIntegrity.Test", NULL, NULL);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "Failed in CreateUnitTestSuite for TpmIntegrityTests\n"));
    Status = EFI_OUT_OF_RESOURCES;
    goto EXIT;
  }

  // Locate the TCG2 Protocol
  Status = gBS->LocateProtocol (&gEfiTcg2ProtocolGuid, NULL, (VOID **)&Tcg2Protocol);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "\n Locate TCG2 Protocol Return Status:%r\n", Status));
    return Status;
  }

  Status = Tcg2Protocol->GetEventLog (
                           Tcg2Protocol,
                           EventLogFormat,
                           &EventStartAddr,
                           &EventEndAddr,
                           &ELogTruncated
                           );
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "\nRetrieve the EventLog Return Status:%r\n", Status));
    return Status;
  }

  ZeroMem (g_CurrentPcrValues, sizeof (g_CurrentPcrValues));

  Status = ParseEventLog (EventStartAddr, EventEndAddr);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "Failed to Parse the Event logs Return Status: %r\n", Status));
    return Status;
  }

  AddTestCase (TpmIntegrity, "PCR0 IntegrityCheck", "TpmIntegrityTest", CheckTPMLogIntegrityTest, NULL, CleanUpTestContext, &PcrTest0);
  AddTestCase (TpmIntegrity, "PCR1 IntegrityCheck", "TpmIntegrityTest", CheckTPMLogIntegrityTest, NULL, CleanUpTestContext, &PcrTest1);
  AddTestCase (TpmIntegrity, "PCR2 IntegrityCheck", "TpmIntegrityTest", CheckTPMLogIntegrityTest, NULL, CleanUpTestContext, &PcrTest2);
  AddTestCase (TpmIntegrity, "PCR3 IntegrityCheck", "TpmIntegrityTest", CheckTPMLogIntegrityTest, NULL, CleanUpTestContext, &PcrTest3);
  AddTestCase (TpmIntegrity, "PCR4 IntegrityCheck", "TpmIntegrityTest", CheckTPMLogIntegrityTest, NULL, CleanUpTestContext, &PcrTest4);
  AddTestCase (TpmIntegrity, "PCR5 IntegrityCheck", "TpmIntegrityTest", CheckTPMLogIntegrityTest, NULL, CleanUpTestContext, &PcrTest5);
  AddTestCase (TpmIntegrity, "PCR6 IntegrityCheck", "TpmIntegrityTest", CheckTPMLogIntegrityTest, NULL, CleanUpTestContext, &PcrTest6);
  AddTestCase (TpmIntegrity, "PCR7 IntegrityCheck", "TpmIntegrityTest", CheckTPMLogIntegrityTest, NULL, CleanUpTestContext, &PcrTest7);

  Status = RunAllTestSuites (Fw);

EXIT:
  if (Fw) {
    FreeUnitTestFramework (Fw);
  }

  return Status;
}
