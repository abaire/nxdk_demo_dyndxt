#ifndef DEMO_DYNDXT_PATCHING_TOOLS_H
#define DEMO_DYNDXT_PATCHING_TOOLS_H

#include <windows.h>

/**
 * Redirect an existing `call` instruction.
 * @param call_address Address of the `call` instruction to replace
 * @param target_address Function that will be called instead. Must match the
 *                       calling convention of the original call.
 * @param call_byte_check Optional 5 bytes expected to be found at
 * `insert_address`
 * @param response Buffer to receive any error message output
 * @param response_len Maximum length of `response`
 * @return XBOX_S_OK on success, otherwise an appropriate error code
 */
HRESULT RedirectFunctionCall(PVOID call_address, PVOID target_address,
                             const uint8_t* call_byte_check, char* response,
                             DWORD response_len);

/**
 * Perform a jmp from an arbitrary location into a patch function.
 * It is up to the caller to handle any replaced instructions. 5 bytes will be
 * overwritten starting at `insert_address` so more than one instruction may be
 * overwritten.
 *
 * @param insert_address Address into which the patch will be inserted
 * @param return_address Address to which the patch will return. Must be >=
 *                       insert_address + 5 and must be the start of a valid
 *                       instruction.
 * @param pre_call Optional machine code to be inserted after the original
 *                 context is saved but before calling the target.
 * @param pre_call_length Length of `pre_call` in bytes.
 * @param target_address Function that will be called by the patch. Must be
 *                       __stdcall convention.
 * @param post_call Optional machine code to be inserted after context is
 *                  restored, just before returning to `return_address`.
 * @param post_call_length Length of `post_call` in bytes.
 * @param call_byte_check Optional 5 bytes expected to be found at
 *                        `insert_address`
 * @param response Buffer to receive any error message output
 * @param response_len Maximum length of `response`
 * @return XBOX_S_OK on success, otherwise an appropriate error code
 */
HRESULT RedirectArbitraryLocation(PVOID insert_address, PVOID* return_address,
                                  PVOID pre_call, uint32_t pre_call_length,
                                  PVOID target_address, PVOID post_call,
                                  uint32_t post_call_length,
                                  const uint8_t* call_byte_check,
                                  char* response, DWORD response_len);
#endif  // DEMO_DYNDXT_PATCHING_TOOLS_H
