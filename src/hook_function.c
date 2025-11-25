#include "hook_function.h"

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "tag.h"

static inline void* GetArgPtr(CpuContext* ctx, int arg_index) {
  // Arguments start immediately above the register store
  uint32_t* stack_base = (uint32_t*)(ctx + 1);
  return (void*)stack_base[arg_index];
}

static void __cdecl LogCall(CpuContext* ctx) {
  DWORD param = (DWORD)GetArgPtr(ctx, 0);
  DbgPrint("Hooked function called with param %d\n", param);
}

#define MAGIC_C_HOOK 0x11111111
#define MAGIC_DELEGATE 0x22222222
#define MAGIC_RETURN 0x33333333

void __attribute__((naked)) ContextTrampoline(void) {
  __asm__ volatile(
      ".intel_syntax noprefix\n"
      "pushad\n"
      "pushfd\n"

      "mov eax, esp\n"
      "push eax\n"
      "mov eax, 0x11111111\n"  // MAGIC_C_HOOK
      "call eax\n"
      "add esp, 4\n"

      "popfd\n"
      "popad\n"

      "mov eax, 0x22222222\n"  // MAGIC_DELEGATE
      "call eax\n"

      "push 0x33333333\n"  // MAGIC_RETURN
      "ret\n");
}
void __attribute__((naked)) ContextTrampolineEnd(void) {}

bool InstallPatch(PVOID patch, SIZE_T patch_size, PVOID target_address) {
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

static HRESULT PatchFunctionCallSite(const char* command, char* response,
                                     DWORD response_len, CommandContext* ctx) {
  // Address of the `call` operation to be patched out.
  static uint8_t* kTargetAddress = (uint8_t*)0x00130048;
  // Address to which execution should return after the patch.
  static void* kReturnAddress = (void*)0x0013004d;
  // The address of the original function, to be called inside the patch.
  static void* kDelegateFunc = (void*)0x001f5bcb;

  // Update to the bytes that should be patched out as a safety check.
  static const uint8_t kExpectedPatchTarget[] = {0xe8, 0x7e, 0x33, 0x00, 0x00};
  if (memcmp(kTargetAddress, kExpectedPatchTarget,
             sizeof(kExpectedPatchTarget)) != 0) {
    response[0] = 0;
    strncat(response, "Unexpected patch data", response_len);
    return XBOX_E_FAIL;
  }

  size_t template_size =
      (uintptr_t)ContextTrampolineEnd - (uintptr_t)ContextTrampoline;
  void* patch = DmAllocatePoolWithTag(template_size + 64, kTag);
  if (!patch) return XBOX_E_FAIL;

  memcpy(patch, ContextTrampoline, template_size);

  uint8_t* scan_ptr = (uint8_t*)patch;
  for (size_t i = 0; i < template_size - 4; ++i) {
    uint32_t* window = (uint32_t*)(scan_ptr + i);

    if (*window == MAGIC_C_HOOK) {
      *window = (uintptr_t)LogCall;
    } else if (*window == MAGIC_DELEGATE) {
      *window = (uintptr_t)kDelegateFunc;
    } else if (*window == MAGIC_RETURN) {
      *window = (uintptr_t)kReturnAddress;
    }
  }

  uint8_t jump_instruction[] = {0xE9, 0x00, 0x00, 0x00, 0x00};
  *(uint32_t*)(jump_instruction + 1) =
      (uintptr_t)patch - (uintptr_t)kReturnAddress;

  if (!InstallPatch(jump_instruction, sizeof(jump_instruction),
                    kTargetAddress)) {
    response[0] = 0;
    strncat(response, "Failed to change memory protection", response_len);
    return XBOX_E_FAIL;
  }

  return XBOX_S_OK;
}

bool OverwriteThunk(PVOID* thunk, PVOID new_value, PVOID* old_value) {
  DbgPrint("Overwrite thunk %p => %p [currently 0x%X]\n", thunk, new_value,
           *(DWORD*)(thunk));

  ULONG old_protect;
  PVOID base_address = thunk;
  SIZE_T region_size = 4;

  LONG status = NtProtectVirtualMemory(&base_address, &region_size,
                                       PAGE_EXECUTE_READWRITE, &old_protect);

  if (!NT_SUCCESS(status)) {
    return false;
  }

  if (old_value) {
    *old_value = *thunk;
  }

  __asm__ volatile("cli" ::: "memory");
  *thunk = new_value;
  __asm__ volatile("sti" ::: "memory");

  NtProtectVirtualMemory(&base_address, &region_size, old_protect,
                         &old_protect);

  return true;
}

typedef NTSTATUS NTAPI (*NtSetEventPtr)(HANDLE, PLONG);
static NtSetEventPtr original_nt_set_event = NULL;

static NTSTATUS NTAPI NtSetEventHook(IN HANDLE handle,
                                     OUT PLONG previous_state OPTIONAL) {
  DbgPrint("NtSetEventHook: Handle is %p\n", handle);
  if (original_nt_set_event) {
    return original_nt_set_event(handle, previous_state);
  }
  return NtSetEvent(handle, previous_state);
}

static HRESULT PatchNtSetEvent(const char* command, char* response,
                               DWORD response_len, CommandContext* ctx) {
  // The address of the thunk in which the real address of NtSetEvent is stored.
  // This example is from Dreamworks Over the Hedge
  static PVOID current_thunk = (PVOID)0x0025893c;

  NtSetEventPtr old_value;
  if (!OverwriteThunk(current_thunk, NtSetEventHook, (PVOID*)&old_value)) {
    response[0] = 0;
    strncat(response, "Failed to change memory protection", response_len);
    return XBOX_E_FAIL;
  }

  if (!original_nt_set_event) {
    original_nt_set_event = old_value;
  }

  return XBOX_S_OK;
}

HRESULT HandleHook(const char* command, char* response, DWORD response_len,
                   CommandContext* ctx) {
  return PatchNtSetEvent(command, response, response_len, ctx);
}
