#include <stdio.h>
#include <string.h>
#include <windows.h>

#include "command_processor_util.h"
#include "nxdk_dxt_dll_main.h"
#include "xbdm.h"

// The dxtmain must do at least two things (assuming it is linked with the
// nxdk):
//
// 1) `#include "nxdk_dxt_dll_main.h"`
//    This defines the DXTMainCRTStartup function that is used to set up
//    the DLL.
// 2) Implement `HRESULT DXTMain(void)`
//    This is the entrypoint into your code. Note that, unlike a normal DLL,
//    your code is run within the context of the loader process, so it's
//    expected to return from the `DXTMain` function quickly.

// Command prefix that will be handled by this processor.
static const char kHandlerName[] = "demo";
static const uint32_t kTag = 0x64656d6f;  // 'demo'

typedef struct CommandTableEntry {
  const char *command;
  HRESULT (*processor)(const char *, char *, DWORD, CommandContext *);
} CommandTableEntry;

static HRESULT_API ProcessCommand(const char *command, char *response,
                                  DWORD response_len, CommandContext *ctx);

// Basic immediate request->response.
static HRESULT HandleBasicRequest(const char *command, char *response,
                                  DWORD response_len, CommandContext *ctx);

// Receive binary data from the client.
static HRESULT HandleReceiveBinary(const char *command, char *response,
                                   DWORD response_len, CommandContext *ctx);
static HRESULT_API ReceiveBinaryData(CommandContext *ctx, char *response,
                                     DWORD response_len);

// Send binary data to the client.
static HRESULT HandleSendBinary(const char *command, char *response,
                                DWORD response_len, CommandContext *ctx);
static HRESULT_API SendBinaryData(CommandContext *ctx, char *response,
                                  DWORD response_len);

// Send a large buffer to the client, prefixed with the size of the buffer.
static HRESULT HandleSendSizePrefixedBinary(const char *command, char *response,
                                            DWORD response_len,
                                            CommandContext *ctx);
static HRESULT_API SendPrepopulatedBinaryData(CommandContext *ctx,
                                              char *response,
                                              DWORD response_len);

// Send multiline text response to the client.
static HRESULT HandleSendMultiline(const char *command, char *response,
                                   DWORD response_len, CommandContext *ctx);
static HRESULT_API SendMultilineData(CommandContext *ctx, char *response,
                                     DWORD response_len);

// Send a message to the notification channel.
static HRESULT HandleSendNotification(const char *command, char *response,
                                      DWORD response_len, CommandContext *ctx);

// Enumerates the command table.
static HRESULT HandleHello(const char *command, char *response,
                           DWORD response_len, CommandContext *ctx);
static HRESULT_API SendHelloData(CommandContext *ctx, char *response,
                                 DWORD response_len);

static const CommandTableEntry kCommandTable[] = {
    {"hello", HandleHello},
    {"basicrequest", HandleBasicRequest},
    {"receivebin", HandleReceiveBinary},
    {"sendbin", HandleSendBinary},
    {"sendsizeprefixedbin", HandleSendSizePrefixedBinary},
    {"sendmultiline", HandleSendMultiline},
    {"sendnotification", HandleSendNotification},
};
static const uint32_t kCommandTableNumEntries =
    sizeof(kCommandTable) / sizeof(kCommandTable[0]);

HRESULT DXTMain(void) {
  return DmRegisterCommandProcessor(kHandlerName, ProcessCommand);
}

static HRESULT_API ProcessCommand(const char *command, char *response,
                                  DWORD response_len, CommandContext *ctx) {
  const char *subcommand = command + sizeof(kHandlerName);

  const CommandTableEntry *entry = kCommandTable;
  for (uint32_t i = 0; i < kCommandTableNumEntries; ++i, ++entry) {
    uint32_t len = strlen(entry->command);
    if (!strncmp(subcommand, entry->command, len)) {
      return entry->processor(subcommand + len, response, response_len, ctx);
    }
  }

  return XBOX_E_UNKNOWN_COMMAND;
}

// Trivial request-response pattern.
// Request parameters may be processed with the CPParseCommandParameters method
// and associated extractors exported by the Dynamic DXT loader if desired.
static HRESULT HandleBasicRequest(const char *command, char *response,
                                  DWORD response_len, CommandContext *ctx) {
  response[0] = 0;
  strncat(response, "Response!", response_len);
  return XBOX_S_OK;
}

// Commands can receive binary files from the client by setting up the
// CommandContext and returning XBOX_S_SEND_BINARY.
static HRESULT HandleReceiveBinary(const char *command, char *response,
                                   DWORD response_len, CommandContext *ctx) {
  // Some mechanism to determine end-of-data from the data alone must be used.
  // Generally this would be done by specifying the length as a command
  // parameter or having a hardcoded size up front, but it'd also be possible to
  // parse the actual data sent and handle it from there if desired (e.g., for
  // Pascal-style strings that prefix the data with the size).
  CommandParameters cp;
  int32_t result = CPParseCommandParameters(command, &cp);
  if (result < 0) {
    return CPPrintError(result, response, response_len);
  }
  uint32_t length;
  bool length_found = CPGetUInt32("length", &length, &cp);
  CPDelete(&cp);

  if (!length_found) {
    response[0] = 0;
    strncat(response, "Missing required 'length' param", response_len);
    return XBOX_E_FAIL;
  }

  // However setting up the CommandContext to do the receive is.
  // In a realistic situation, it is often useful to set ctx->user_data to
  // something that contains additional information about the upload. For
  // example, additional parameters that may have been passed to this handler,
  // extra memory buffers, etc...
  // For this trivial example, no user_data is necessary so it is set to NULL,
  // although it is probably also fine to leave whatever value is in there, as
  // long as the `handler` method does not make use of it.
  ctx->user_data = NULL;

  // XBDM provides a small built-in buffer in the CommandContext that can be
  // used if desired. XBDM handles calling the handler multiple times if more
  // data is received than the buffer can hold.
  // Alternatively, a buffer can be allocated and assigned here:
  //  ctx->buffer = DmAllocatePoolWithTag(length, some_tag_integer);
  //  ctx->buffer_size = length;

  // bytes_remaining should be initialized to the total size expected by this
  // receive command, but setting it to anything > 0 should cause XBDM to
  // continue to expect binary data from the client.
  ctx->bytes_remaining = length;

  // The handler method will be invoked as XBDM receives chunks of data. It is
  // up to the handler function to deal with the received data and eventually
  // to set ctx->bytes_remaining to 0, indicating that the receive is completed.
  ctx->handler = ReceiveBinaryData;

  // Sending back a message is not actually necessary.
  response[0] = 0;
  strncat(response, "Ready to receive binary data", response_len);

  return XBOX_S_SEND_BINARY;
}

static HRESULT_API ReceiveBinaryData(CommandContext *ctx, char *response,
                                     DWORD response_len) {
  // This method will be invoked by XBDM as it receives binary data sent in
  // response to an XBOX_S_SEND_BINARY return value.

  // It is this handler's responsibility to do something useful with the data
  // (e.g., store it someplace less volatile than the ctx->buffer, which will
  // potentially be reused even within a given SEND_BINARY interaction).
  // It is also up to this handler to indicate the end of the transaction by
  // setting ctx->bytes_remaining to 0 and to return error codes if appropriate.

  // The CommandContext contains a `data_size` member which has been set by
  // XBDM to the number of bytes in ctx->buffer that were populated with real
  // data from the client. It is possible that the client did not send enough
  // data to fill the buffer completely, so it is important to respect this
  // number to avoid processing garbage data.

  // In this demo, there is no potential for the client to cause an error, but
  // error handling would roughly follow this pattern:
#if 0
  if (data_is_invalid_for_some_reason) {
    // Clean up any resources that were allocated by the top level command
    // handler, e.g., if ctx->buffer was set via DmAllocatePoolWithTag it should
    // be freed before the receive action is terminated via this subhandler
    // returning an error or a success with ctx->bytes_remaining == 0.

    // It is not necessary to populate the response message, but it may be used
    // to give the client some context about the failure.
    response[0] = 0;
    strncat(response, "Information about the failure", response_len);

    return XBOX_E_FAIL;
  }
#endif

  // A real application would do something interesting with the buffer; possibly
  // accumulate it over multiple invocations of this handler, decrementing
  // ctx->bytes_remaining until it == 0. See the handler in nxdk_dyndxt for a
  // realistic usecase:
  // https://github.com/abaire/nxdk_dyndxt/blob/76938e6d42d9f01cdd598c29a55f9d285c11394e/src/dxtmain.c#L283
  //
  // In this demo case, the data itself is ignored and we simply decrement
  // bytes_remaining until all data has been ignored.
  ctx->bytes_remaining -= ctx->data_size;

  if (!ctx->bytes_remaining) {
    // In a real application, it'd be important to clean up any allocated
    // resources here, as XBDM will not invoke this handler again once it
    // returns XBOX_S_OK with ctx->bytes_remaining == 0.
    //
    // In this demo case, there is nothing to clean up.

    // It is not actually necessary to populate the response message.
    response[0] = 0;
    strncat(response, "All data received!", response_len);
  }

  // Returning S_OK indicates either that the receive should continue
  // (ctx->bytes_remaining > 0) or that the receive is completed
  // (ctx->bytes_remaining == 0).
  return XBOX_S_OK;
}

// Send binary data to the client.
static HRESULT HandleSendBinary(const char *command, char *response,
                                DWORD response_len, CommandContext *ctx) {
  // Sending a binary response involves supplying a handler procedure that will
  // be called repeatedly to populate the send buffer. The CommandContext's
  // buffer may also be replaced with a larger one for efficiency.
  // Finally, this method must return XBOX_S_BINARY to request that XBDM invoke
  // the handler repeatedly until it returns XBOX_S_NO_MORE_DATA.

  // In this demo, 4 bytes are returned to the client in 4 invocations of the
  // SendBinaryData handler. In a real application, the user_data would likely
  // point to a more interesting contextual struct, and the handler would almost
  // certainly return more than a single byte per iteration.

  uint32_t current_value = 4;
  ctx->user_data = (void *)current_value;
  ctx->bytes_remaining = 3;
  ctx->handler = SendBinaryData;

  // The default XBDM buffer is small, so it may be desirable to utilize a
  // larger buffer. The buffer could just be a global array, but heap allocation
  // is used for demonstration purposes. A heap allocated buffer must be freed
  // in the send handler.
  const uint32_t kBufferSize = 4;
  uint8_t *buffer = DmAllocatePoolWithTag(kBufferSize, kTag);
  if (!buffer) {
    response[0] = 0;
    strncat(response, "Failed to allocate send buffer", response_len);
    return XBOX_E_ACCESS_DENIED;
  }

  // No data will be sent by XBDM until after it invokes the `handler`
  // procedure, so there is no reason to populate buffer here.
  ctx->buffer = buffer;
  ctx->buffer_size = kBufferSize;

  // Sending back a message is not actually necessary.
  response[0] = 0;
  strncat(response, "Returning 4 bytes of data", response_len);

  return XBOX_S_BINARY;
}

static HRESULT_API SendBinaryData(CommandContext *ctx, char *response,
                                  DWORD response_len) {
  // This handler is responsible for populating `ctx->buffer` with response
  // data, setting `ctx->data_size` to the number of valid bytes in the buffer,
  // and returning either XBOX_S_OK (if more data needs to be sent) or
  // XBOX_S_NO_MORE_DATA if all data has already been sent.
  //
  // Note that the `bytes_remaining` field is unused in the context of binary-
  // sending and can be ignored entirely or used by this handler to determine
  // when to stop sending data. In this demo, `user_data` is used to determine
  // the end condition and `bytes_remaining` is ignored.

  if (!ctx->user_data) {
    // Since the buffer was allocated by us, it is important to clean it up
    // here as XBDM will not invoke this handler again once it returns XBOX_S_OK
    // with ctx->bytes_remaining == 0.
    DmFreePool(ctx->buffer);

    // It is not actually necessary to populate the response message.
    response[0] = 0;
    strncat(response, "Done sending bytes!", response_len);
    return XBOX_S_NO_MORE_DATA;
  }

  // In a real application, it'd almost certainly be desirable to send back more
  // than a single byte per invocation of this handler. Using a single byte
  // allows this demo to show how to send more than a buffer's worth of data.

  // Response data is copied into ctx->buffer.
  uint8_t *dest = (uint8_t *)ctx->buffer;
  dest[0] = (intptr_t)ctx->user_data & 0xFF;

  // ctx->data_size is updated to indicate how many bytes of ctx->buffer are
  // populated.
  ctx->data_size = 1;

  --ctx->user_data;

  return XBOX_S_OK;
}

// Send binary data to the client.
static HRESULT HandleSendSizePrefixedBinary(const char *command, char *response,
                                            DWORD response_len,
                                            CommandContext *ctx) {
  // Demonstrates sending a large buffer to the client where the first 4 bytes
  // contain the size of the buffer.

  ctx->handler = SendPrepopulatedBinaryData;

  const uint32_t kDataSize = 1024 * 1024;
  uint8_t *buffer = DmAllocatePoolWithTag(kDataSize + 4, kTag);
  if (!buffer) {
    response[0] = 0;
    strncat(response, "Failed to allocate send buffer", response_len);
    return XBOX_E_ACCESS_DENIED;
  }

  // No data will be sent by XBDM until after it invokes the `handler`
  // procedure, but the buffer contents also will not be touched by the system
  // so it may be initialized here.
  memcpy(buffer, &kDataSize, sizeof(kDataSize));
  for (uint32_t i = 0; i < kDataSize; ++i) {
    buffer[i + 4] = i & 0xFF;
  }

  ctx->user_data = (void*)kDataSize;
  ctx->buffer = buffer;
  ctx->bytes_remaining = kDataSize + 4;
  ctx->buffer_size = kDataSize + 4;

  // Sending back a message is not actually necessary.
  snprintf(response, response_len, "Returning size prefixed data");

  return XBOX_S_BINARY;
}

static HRESULT_API SendPrepopulatedBinaryData(CommandContext *ctx,
                                              char *response,
                                              DWORD response_len) {
  // This handler is responsible for populating `ctx->buffer` with response
  // data, setting `ctx->data_size` to the number of valid bytes in the buffer,
  // and returning either XBOX_S_OK (if more data needs to be sent) or
  // XBOX_S_NO_MORE_DATA if all data has already been sent.
  //
  // Note that the `bytes_remaining` field is unused in the context of binary-
  // sending and can be ignored entirely or used by this handler to determine
  // when to stop sending data. In this demo, `user_data` is used to determine
  // the end condition and `bytes_remaining` is ignored.

  if (!ctx->bytes_remaining) {
    // Since the buffer was allocated by us, it is important to clean it up
    // here as XBDM will not invoke this handler again once it returns XBOX_S_OK
    // with ctx->bytes_remaining == 0.
    DmFreePool(ctx->buffer);

    // It is not actually necessary to populate the response message.
    response[0] = 0;
    strncat(response, "Done sending bytes!", response_len);
    return XBOX_S_NO_MORE_DATA;
  }

  // ctx->data_size is updated to indicate how many bytes of ctx->buffer are
  // populated.
  ctx->data_size = ctx->bytes_remaining;
  ctx->bytes_remaining = 0;

  return XBOX_S_OK;
}

// Send multiline text response to the client.
static HRESULT HandleSendMultiline(const char *command, char *response,
                                   DWORD response_len, CommandContext *ctx) {
  // Multiline responses are sent by returning XBOX_S_MULTILINE from the command
  // processor, which will cause the registered handler to be invoked repeatedly
  // until it returns an error or XBOX_S_NO_MORE_DATA.
  //
  // As with the other multi-part processors, it is often useful to set up
  // ctx->user_data with some sort of contextual information. In this demo case,
  // it is simply set to an integer which will be decremented and returned to
  // the client until it == 0.
  ctx->user_data = (void *)4;
  ctx->handler = SendMultilineData;

  // It is not necessary to populate the response message, but if it is
  // populated here and not populated by the registered handler, this value will
  // be sent when the handler is exhausted.
  *response = 0;
  strncat(response, "Countdown...", response_len);
  return XBOX_S_MULTILINE;
}

static HRESULT_API SendMultilineData(CommandContext *ctx, char *response,
                                     DWORD response_len) {
  // This method will be invoked by XBDM repeatedly until it returns an error
  // code or XBOX_S_NO_MORE_DATA.

  uint32_t current_value = (uint32_t)ctx->user_data;
  --current_value;

  // For this demo case, the response is completed when the contextual counter
  // reaches 0.
  if (!current_value) {
    // In a real application, it'd be important to clean up any allocated
    // resources here, as XBDM will not invoke this handler again once it
    // returns XBOX_S_NO_MORE_DATA.

    // It is not actually necessary to populate the response message.
    response[0] = 0;
    strncat(response, "Done counting!", response_len);
    return XBOX_S_NO_MORE_DATA;
  }

  ctx->user_data = (void *)current_value;

  // Multiline results are sent in the ctx->buffer.
  //
  // NOTE: In this case it'd probably be fine to sprintf directly into the
  // buffer, but ctx->buffer_size is checked for sake of a more interesting
  // example.
  char msg[16] = {0};
  int message_len = 1 + sprintf(msg, "#%d", current_value);

  if (message_len > ctx->buffer_size) {
    // In a real application, it'd be important to clean up any allocated
    // resources here, as XBDM will not invoke this handler again once it
    // returns an error result.
    response[0] = 0;
    strncat(response, "Response buffer is too small", response_len);
    return XBOX_E_ACCESS_DENIED;
  }

  memcpy(ctx->buffer, msg, message_len);

  return XBOX_S_OK;
}

// DmSendNotification demonstration.
static HRESULT HandleSendNotification(const char *command, char *response,
                                      DWORD response_len, CommandContext *ctx) {
  HRESULT result = DmSendNotificationString("demo!Notification");
  if (!XBOX_SUCCESS(result)) {
    response[0] = 0;
    strncat(response, "Sending failed!", response_len);
    return result;
  }

  response[0] = 0;
  strncat(response, "Notification sent!", response_len);
  return XBOX_S_OK;
}

static HRESULT HandleHello(const char *command, char *response,
                           DWORD response_len, CommandContext *ctx) {
  ctx->user_data = 0;
  ctx->handler = SendHelloData;
  *response = 0;
  strncat(response, "Available commands:", response_len);
  return XBOX_S_MULTILINE;
}

static HRESULT_API SendHelloData(CommandContext *ctx, char *response,
                                 DWORD response_len) {
  uint32_t current_index = (uint32_t)ctx->user_data++;

  if (current_index >= kCommandTableNumEntries) {
    return XBOX_S_NO_MORE_DATA;
  }

  const CommandTableEntry *entry = &kCommandTable[current_index];
  uint32_t command_len = strlen(entry->command) + 1;
  if (command_len > ctx->buffer_size) {
    response[0] = 0;
    strncat(response, "Response buffer is too small", response_len);
    return XBOX_E_ACCESS_DENIED;
  }

  memcpy(ctx->buffer, entry->command, command_len);
  return XBOX_S_OK;
}
