#include "patching_tools.h"

#include <stdbool.h>
#include <stdio.h>

#include "tag.h"
#include "xbdm.h"

#define CALL_OPERATION_LENGTH 5

#define MAGIC_C_HOOK 0x11111111
#define MAGIC_RETURN 0x33333333

extern void TrampolineEnterEnd(void);
void __attribute__((naked)) TrampolineEnter(void) {
  __asm__ volatile(
      ".intel_syntax noprefix\n"
      "pushad\n"
      "pushfd\n"
      ".global _TrampolineEnterEnd\n"
      "_TrampolineEnterEnd:\n");
}

extern void TrampolineCallEnd(void);
void __attribute__((naked)) TrampolineCall(void) {
  __asm__ volatile(
      ".intel_syntax noprefix\n"
      "mov eax, esp\n"
      "push eax\n"
      "mov eax, 0x11111111\n"  // MAGIC_C_HOOK
      "call eax\n"
      "add esp, 4\n"

      "popfd\n"
      "popad\n"

      ".global _TrampolineCallEnd\n"
      "_TrampolineCallEnd:\n");
}

extern void TrampolineReturnEnd(void);
void __attribute__((naked)) TrampolineReturn(void) {
  __asm__ volatile(
      ".intel_syntax noprefix\n"
      "push 0x33333333\n"  // MAGIC_RETURN
      "ret\n"

      ".global _TrampolineReturnEnd\n"
      "_TrampolineReturnEnd:\n");
}

static bool InstallPatch(PVOID patch, SIZE_T patch_size, PVOID target_address) {
  ULONG old_protect;
  PVOID base_address = target_address;
  SIZE_T region_size = patch_size;

  LONG status = NtProtectVirtualMemory(&base_address, &region_size,
                                       PAGE_EXECUTE_READWRITE, &old_protect);

  if (!NT_SUCCESS(status)) {
    return false;
  }

  __asm__ volatile("cli" ::: "memory");
  memcpy(target_address, patch, patch_size);
  __asm__ volatile("sti" ::: "memory");

  NtProtectVirtualMemory(&base_address, &region_size, old_protect,
                         &old_protect);

  return true;
}

HRESULT RedirectFunctionCall(PVOID call_address, PVOID target_address,
                             const uint8_t* call_byte_check, char* response,
                             DWORD response_len) {
  if (call_byte_check &&
      memcmp(call_address, call_byte_check, CALL_OPERATION_LENGTH) != 0) {
    response[0] = 0;
    // TODO: Print all 5 bytes
    snprintf(response, response_len, "Unexpected patch data %X != %X",
             *(uint32_t*)call_address, *(uint32_t*)call_byte_check);
    return XBOX_E_FAIL;
  }

  uint32_t return_address = (uint32_t)call_address + CALL_OPERATION_LENGTH;
  uint32_t delta = (uint32_t)target_address - return_address;

  DbgPrint("Patching 0x%p to call 0x%p\n", call_address, target_address);

  if (!InstallPatch(&delta, sizeof(delta), call_address + 1)) {
    response[0] = 0;
    strncat(response, "Failed to change memory protection", response_len);
    return XBOX_E_FAIL;
  }

  return XBOX_S_OK;
}

HRESULT RedirectArbitraryLocation(PVOID insert_address, PVOID* return_address,
                                  PVOID pre_call, uint32_t pre_call_length,
                                  PVOID target_address, PVOID post_call,
                                  uint32_t post_call_length,
                                  const uint8_t* call_byte_check,
                                  char* response, DWORD response_len) {
  if (call_byte_check &&
      memcmp(insert_address, call_byte_check, CALL_OPERATION_LENGTH) != 0) {
    // TODO: Print all 5 bytes
    snprintf(response, response_len, "Unexpected patch data %X != %X",
             *(uint32_t*)insert_address, *(uint32_t*)call_byte_check);
    return XBOX_E_FAIL;
  }

  const size_t TrampolineReturnSize =
      (uintptr_t)TrampolineReturnEnd - (uintptr_t)TrampolineReturn;
  const size_t TrampolineCallSize =
      (uintptr_t)TrampolineCallEnd - (uintptr_t)TrampolineCall;
  const size_t TrampolineEnterSize =
      (uintptr_t)TrampolineEnterEnd - (uintptr_t)TrampolineEnter;

  size_t template_size = TrampolineEnterSize + TrampolineCallSize +
                         TrampolineReturnSize + pre_call_length +
                         post_call_length;

  void* patch = DmAllocatePoolWithTag(template_size + 64, kTag);
  if (!patch) {
    snprintf(response, response_len, "Failed to alloc %d bytes\n",
             template_size);
    return XBOX_E_FAIL;
  }

  uint8_t* write_location = patch;
  memcpy(write_location, TrampolineEnter, TrampolineEnterSize);
  write_location += TrampolineEnterSize;

  if (pre_call && pre_call_length) {
    memcpy(write_location, pre_call, pre_call_length);
    write_location += pre_call_length;
  }

  memcpy(write_location, TrampolineCall, TrampolineCallSize);
  {
    uint8_t* scan_ptr = write_location;
    for (size_t i = 0; i < TrampolineCallSize - 4; ++i) {
      uint32_t* window = (uint32_t*)(scan_ptr + i);
      if (*window == MAGIC_C_HOOK) {
        *window = (uintptr_t)target_address;
      }
    }
  }

  write_location += TrampolineCallSize;

  if (post_call && post_call_length) {
    memcpy(write_location, post_call, post_call_length);
    write_location += post_call_length;
  }

  memcpy(write_location, TrampolineReturn, TrampolineReturnSize);
  {
    uint8_t* scan_ptr = write_location;
    for (size_t i = 0; i < TrampolineCallSize - 4; ++i) {
      uint32_t* window = (uint32_t*)(scan_ptr + i);
      if (*window == MAGIC_RETURN) {
        *window = (uintptr_t)return_address;
      }
    }
  }

  uint8_t jump_instruction[] = {0xE9, 0x00, 0x00, 0x00, 0x00};
  *(uint32_t*)(jump_instruction + 1) =
      (uintptr_t)patch - ((uintptr_t)insert_address + sizeof(jump_instruction));

  DbgPrint("Patching 0x%p to jump to 0x%p\n", insert_address, patch);

  if (!InstallPatch(jump_instruction, sizeof(jump_instruction),
                    insert_address)) {
    response[0] = 0;
    strncat(response, "Failed to change memory protection", response_len);
    return XBOX_E_FAIL;
  }

  return XBOX_S_OK;
}
