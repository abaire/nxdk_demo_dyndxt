#ifndef DEMO_DYNDXT_HOOK_FUNCTION_H
#define DEMO_DYNDXT_HOOK_FUNCTION_H

#include <stdbool.h>
#include <windows.h>

#include "xbdm.h"

typedef struct {
  uint32_t eflags;

  // Must be in pushad order.
  uint32_t edi;
  uint32_t esi;
  uint32_t ebp;
  uint32_t esp;  // ESP before PUSHAD
  uint32_t ebx;
  uint32_t edx;
  uint32_t ecx;
  uint32_t eax;
} CpuContext;

// Demonstrates hooking function calls in the loaded XBE.
HRESULT HandleHook(const char* command, char* response, DWORD response_len,
                   CommandContext* ctx);

//! Overwrites some portion of memory.
bool InstallPatch(PVOID patch, SIZE_T patch_size, PVOID target_address);

//! Overwrites a single DWORD in memory (generally a kernel function thunk).
bool OverwriteThunk(PVOID* thunk, PVOID new_value, PVOID* old_value);

#endif  // DEMO_DYNDXT_HOOK_FUNCTION_H
