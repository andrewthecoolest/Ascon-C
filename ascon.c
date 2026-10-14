///////////////////////////////////////
// Ascon-AEAD128 C Implementation
// CSCI 4041: Cryptography
// Author: Andrew Loera
// Date: 2026-10-13
//
// reference: ascon.isec.tugraz.at
///////////////////////////////////////

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

/* Algorithm Flow:
 *
 * Initialization Phase:
 *  IV || Key || Nonce fill states
 *  12 rounds of the permutation
 *  0* || Key XOR into hidden state
 *
 * Associated Data (skipped entirely if AD is empty):
 *  pad AD with 1 || 0* into m 128-bit blocks
 *    (if AD is a multiple of 128 bits, the last block is padding only)
 *  for each of the m blocks:
 *    S0, S1 ^= Ai
 *    8 rounds of the permutation
 *  0* || 1 XOR into hidden state (always, even if AD is empty)
 *
 * Plaintext:
 *  pad P with 1 || 0* into n 128-bit blocks
 *    (if P is a multiple of 128 bits, the last block is padding only)
 *  for each of the first n-1 blocks:
 *    encrypt: S0, S1 ^= Pi;  Ci = S0, S1
 *    decrypt: Pi = S0, S1 ^ Ci;  S0, S1 = Ci
 *    8 rounds of the permutation
 *  last block: same XOR, no permutation, Cn truncated to real length
 *
 * Finalization:
 *  0^128 || K || 0^64 XOR into state (key into S2, S3)
 *  12 rounds of the permutation
 *  T = S3, S4 XOR Key
 * decrypt: compare T to received tag in constant time,
 *           on mismatch return failure and release no plaintext
 *
 */

typedef struct a_config a_config_t;
typedef struct a_ctx a_ctx_t;
typedef struct buffer buf_t;
typedef enum {
  MODE_ENCRYPT, // 0
  MODE_DECRYPT  // 1
} a_mode_t;

struct buffer {
  uint8_t *data;
  size_t len;
};

struct a_ctx {
  uint64_t state[5]; // 5 states: S0, S1 working / S2, S3, S4 hidden
  uint64_t key[2];   // 128-bit
  buf_t plaintext;
  buf_t ciphertext;
  uint64_t tag[2]; // 128-bit, computed after encryption
};

struct a_config {
  a_mode_t mode;
  uint64_t IV;       // 64-bit
  uint64_t nonce[2]; // 128-bit
  buf_t *associated_data;
  uint64_t input_tag[2]; // 128-bit, used for validating decryption
};

static void parse_input(int argc, char argv[], a_config_t *a_config,
                        a_ctx_t *a_context);

/* input:
 *
 * enc/dec mode
 * plaintext / ciphertext
 * key
 * nonce
 * associated data
 * tag (decrypt only)
 *
 * */

int main(int argc, char *argv[]) {

  a_config_t a_config;
  a_ctx_t a_context;

  return EXIT_SUCCESS;
}
