// Copyright 2018 Thomás Inskip. All rights reserved.
// https://github.com/tinskip/infnoise-openssl-engine
//
// Implementation of OpenSSL RAND engine which uses the infnoise TRNG to
// generate true random numbers: https://github.com/waywardgeek/infnoise

#include <libinfnoise.h>
#include <openssl/engine.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef MIN
#define MIN(a, b) (((a) < (b)) ? (a) : (b))
#endif

static const int kEngineOk = 1;
static const int kEngineFail = 0;

///////////////////
// Configuration
///////////////////

static const int kInfnoiseMultiplier = 1;
static const char *kInfnoiseSerial = NULL;
static const bool kKeccak = true;
static const bool kRaw = true;
static const bool kDebug = true;

////////////////////////////////
// Ring buffer implementation
////////////////////////////////

#define kRingBufferSize (2u * BUFLEN) // So that we do not waste TRNG bytes.

typedef struct {
  uint8_t buffer[kRingBufferSize];
  uint8_t *r_ptr;
  uint8_t *w_ptr;
} RingBuffer;

static void RingBufferInit(RingBuffer *buffer) {
  memset(buffer->buffer, 0, sizeof(buffer->buffer));
  buffer->r_ptr = buffer->buffer;
  buffer->w_ptr = buffer->buffer;
}

static size_t RingBufferRead(RingBuffer *buffer, size_t num_bytes,
                             uint8_t *output) {
  size_t total_bytes_read = 0;

  if (buffer->r_ptr > buffer->w_ptr) {
    size_t bytes_in_front = kRingBufferSize - (buffer->r_ptr - buffer->buffer);
    size_t bytes_read = MIN(num_bytes, bytes_in_front);
    memcpy(output, buffer->r_ptr, bytes_read);
    if (bytes_read < bytes_in_front) {
      buffer->r_ptr += bytes_read;
      return bytes_read;
    }
    buffer->r_ptr = buffer->buffer;
    total_bytes_read += bytes_read;
    num_bytes -= bytes_read;
  }

  size_t bytes_read = MIN(num_bytes, (size_t)(buffer->w_ptr - buffer->r_ptr));
  memcpy(output, buffer->r_ptr, bytes_read);
  buffer->r_ptr += bytes_read;
  if ((buffer->r_ptr - buffer->buffer) == sizeof(buffer->buffer)) {
    buffer->r_ptr = buffer->buffer;
  }
  total_bytes_read += bytes_read;

  return total_bytes_read;
}

static size_t RingBufferWrite(RingBuffer *buffer, size_t num_bytes,
                              const uint8_t *input) {
  size_t total_bytes_written = 0;

  if (buffer->w_ptr > buffer->r_ptr) {
    size_t free_bytes_in_front =
        kRingBufferSize - (buffer->w_ptr - buffer->buffer);
    size_t bytes_write = MIN(num_bytes, free_bytes_in_front);
    memcpy(buffer->w_ptr, input, bytes_write);
    if (bytes_write < num_bytes) {
      buffer->w_ptr += bytes_write;
      return bytes_write;
    }
    buffer->w_ptr = buffer->buffer;
    total_bytes_written += bytes_write;
    num_bytes -= bytes_write;
  }

  size_t bytes_write =
      MIN(num_bytes, kRingBufferSize - (buffer->w_ptr - buffer->r_ptr));
  memcpy(buffer->w_ptr, input, bytes_write);
  buffer->w_ptr += bytes_write;
  if ((buffer->w_ptr - buffer->buffer) == sizeof(buffer->buffer)) {
    buffer->w_ptr = buffer->buffer;
  }
  total_bytes_written += bytes_write;

  return total_bytes_written;
}

///////////////////////////
// Engine implementation
///////////////////////////

typedef struct {
  struct infnoise_context trng_context;
  RingBuffer ring_buffer;
  int status;
} InfnoiseEngineState;

static int InfnoiseEngineStateInit(InfnoiseEngineState *engine_state) {
  memset(engine_state, 0, sizeof(*engine_state));
  RingBufferInit(&engine_state->ring_buffer);
  engine_state->status = initInfnoise(&engine_state->trng_context,
                                      kInfnoiseSerial, kKeccak, !kDebug);
  if (!engine_state->status) {
    fprintf(stderr, "initInfnoise initialization error: %s\n",
            engine_state->trng_context.message
                ? engine_state->trng_context.message
                : "unknown");
  }

  return engine_state->status;
}

static InfnoiseEngineState engine_state;

static int Bytes(unsigned char *buf, int num) {
  unsigned char *w_ptr = buf;
  while ((num > 0) && (engine_state.status == kEngineOk)) {
    size_t bytes_read = RingBufferRead(&engine_state.ring_buffer, num, w_ptr);
    w_ptr += bytes_read;
    num -= bytes_read;

    if (num > 0) {
      // Need more TRNG bytes.
      uint8_t rand_buffer[BUFLEN];
      size_t rand_bytes = readData(&engine_state.trng_context, rand_buffer,
                                   !kRaw, kInfnoiseMultiplier);
      if (engine_state.trng_context.errorFlag) {
        fprintf(stderr, "Infnoise error: %s\n",
                engine_state.trng_context.message
                    ? engine_state.trng_context.message
                    : "unknown");
        engine_state.status = kEngineFail;
        break;
      }
      size_t bytes_written =
          RingBufferWrite(&engine_state.ring_buffer, rand_bytes, rand_buffer);
      if (bytes_written != rand_bytes) {
        fprintf(stderr, "Invalid infnoise engine buffer state!\n");
        engine_state.status = kEngineFail;
        break;
      }
    }
  }

  return engine_state.status;
}

static int Status(void) { return engine_state.status; }

int infnoise_bind(ENGINE *engine, const char *id) {
  static const char kEngineId[] = "infnoise";
  static const char kEngineName[] = "RNG engine using the infnoise TRNG";

  static RAND_METHOD rand_method = {NULL,   &Bytes, NULL, NULL,
                                    &Bytes, // No 'pseudo'.
                                    &Status};

  if (ENGINE_set_id(engine, kEngineId) != kEngineOk ||
      ENGINE_set_name(engine, kEngineName) != kEngineOk ||
      ENGINE_set_RAND(engine, &rand_method) != kEngineOk) {
    fprintf(stderr, "infnoise-engine: Binding failed.\n");
    return 0;
  }

  if (InfnoiseEngineStateInit(&engine_state) != kEngineOk) {
    exit(-1);
  }

  fprintf(stderr, "Infnoise engine loaded.\n");
  return kEngineOk;
}

IMPLEMENT_DYNAMIC_BIND_FN(infnoise_bind)
IMPLEMENT_DYNAMIC_CHECK_FN()
