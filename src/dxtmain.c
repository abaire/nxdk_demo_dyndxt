#include <stdio.h>
#include <string.h>
#include <windows.h>

#include "command_processor_util.h"
#include "xbdm.h"

// Command prefix that will be handled by this processor.
static const char kHandlerName[] = "demo";
static const uint32_t kTag = 0x64656d6f;  // 'demo'

static HRESULT_API ProcessCommand(const char *command, char *response,
                                  DWORD response_len,
                                  struct CommandContext *ctx);

// Basic immediate request->response.
static HRESULT HandleBasicRequest(const char *command, char *response,
                                  DWORD response_len,
                                  struct CommandContext *ctx);

// Receive binary data from the client.
static HRESULT HandleReceiveBinary(const char *command, char *response,
                                   DWORD response_len,
                                   struct CommandContext *ctx);
static HRESULT_API ReceiveBinaryData(struct CommandContext *ctx, char *response,
                                     DWORD response_len);

// Send binary data to the client.
static HRESULT HandleSendBinary(const char *command, char *response,
                                DWORD response_len, struct CommandContext *ctx);
static HRESULT_API SendBinaryData(struct CommandContext *ctx, char *response,
                                  DWORD response_len);

// Send multiline text response to the client.
static HRESULT HandleSendMultiline(const char *command, char *response,
                                   DWORD response_len,
                                   struct CommandContext *ctx);
static HRESULT_API SendMultilineData(struct CommandContext *ctx, char *response,
                                     DWORD response_len);

HRESULT __declspec(dllexport) DxtMain(void) {
  return DmRegisterCommandProcessor(kHandlerName, ProcessCommand);
}

static HRESULT_API ProcessCommand(const char *command, char *response,
                                  DWORD response_len,
                                  struct CommandContext *ctx) {
  const char *subcommand = command + sizeof(kHandlerName);

  if (!strncmp(subcommand, "hello", 5)) {
    strncpy(response, "Hi from demo_dyndxt", response_len);
    return XBOX_S_OK;
  }

  if (!strncmp(subcommand, "basicrequest", 12)) {
    return HandleBasicRequest(subcommand + 12, response, response_len, ctx);
  }

  if (!strncmp(subcommand, "receivebin", 10)) {
    return HandleReceiveBinary(subcommand + 10, response, response_len, ctx);
  }

  if (!strncmp(subcommand, "sendbin", 7)) {
    return HandleSendBinary(subcommand + 7, response, response_len, ctx);
  }

  if (!strncmp(subcommand, "sendmultiline", 13)) {
    return HandleSendMultiline(subcommand + 13, response, response_len, ctx);
  }

  return XBOX_E_UNKNOWN_COMMAND;
}

// Trivial request-response pattern.
// Request parameters may be processed with the CPParseCommandParameters method
// and associated extractors exported by the Dynamic DXT loader if desired.
static HRESULT HandleBasicRequest(const char *command, char *response,
                                  DWORD response_len,
                                  struct CommandContext *ctx) {
  response[0] = 0;
  strncat(response, "Response!", response_len);
  return XBOX_S_OK;
}

// Commands can receive binary files from the client by setting up the
// CommandContext and returning XBOX_S_SEND_BINARY.
static HRESULT HandleReceiveBinary(const char *command, char *response,
                                   DWORD response_len,
                                   struct CommandContext *ctx) {
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

static HRESULT_API ReceiveBinaryData(struct CommandContext *ctx, char *response,
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
                                DWORD response_len,
                                struct CommandContext *ctx) {
  // Sending a binary response involves supplying a buffer, a handler procedure
  // to populate it, and returning  XBOX_S_BINARY to request that XBDM invoke
  // the handler repeatedly until it returns XBOX_S_NO_MORE_DATA.

  // In this demo, 4 bytes are returned to the client in 4 invocations of the
  // SendBinaryData handler. In a real application, the user_data would likely
  // point to a more interesting contextual struct, and the handler would almost
  // certainly return more than a single byte per iteration.

  uint32_t current_value = 4;
  ctx->user_data = (void *)current_value;
  ctx->bytes_remaining = 3;
  ctx->handler = SendBinaryData;

  // Unlike in the binary receive scenario, XBDM does not populate the send
  // buffer, so it must be done here.
  // The buffer could just be a global array, but heap allocation is used for
  // demonstration purposes.
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

static HRESULT_API SendBinaryData(struct CommandContext *ctx, char *response,
                                  DWORD response_len) {
  // This handler is responsible for populating `ctx->buffer` with response
  // data, setting `ctx->data_size` to the number of valid bytes in the buffer,
  // and returning either XBOX_S_OK (if more data needs to be sent) or
  // XBOX_S_NO_MORE_DATA if all data has already been sent.
  // Note that the `bytes_remaining` field is unused in the context of binary-
  // sending and can/should be ignored entirely.

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

// Send multiline text response to the client.
static HRESULT HandleSendMultiline(const char *command, char *response,
                                   DWORD response_len,
                                   struct CommandContext *ctx) {
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

  // It is not necessary to populate the response message.
  *response = 0;
  strncat(response, "Countdown...", response_len);
  return XBOX_S_MULTILINE;
}

static HRESULT_API SendMultilineData(struct CommandContext *ctx, char *response,
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
