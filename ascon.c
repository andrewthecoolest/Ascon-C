///////////////////////////////////////
// Ascon-AEAD128 C Implementation
// CSCI 4041: Cryptography
// Author: Andrew Loera
// Date: 2026-10-13
//
// reference: ascon.isec.tugraz.at
///////////////////////////////////////

#ifdef __APPLE__
#include <sys/random.h>
#endif
#include <ctype.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

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
 * last block: same XOR, no permutation, Cn truncated to real length
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
typedef struct opts opts_t;
typedef enum {
  MODE_NONE,    // 0
  MODE_ENCRYPT, // 1
  MODE_DECRYPT  // 2
} a_mode_t;

static const uint64_t ASCON_IV = 0x00001000808c0001ULL; // Ascon-AEAD128 IV

struct buffer { // little endian lanes, 2 per 128-bit block
  uint64_t *data;
  size_t len; // length in bytes, before padding
};

struct opts { // CLI only
  a_mode_t mode;
  const char *in_path;   // input file path
  const char *out_path;  // output file path, NULL = auto-generate
  const char *key_path;  // key file path
  const char *ad_path;   // ad file path, NULL = no AD
  const char *nonce_hex; // nonce hex, NULL = random
};

struct a_ctx {       // working state
  uint64_t state[5]; // 5 states: S0, S1 working / S2, S3, S4 hidden
  buf_t plaintext;
  buf_t ciphertext;
  uint64_t tag[2]; // 128-bit, computed after encryption
};

struct a_config { // fixed inputs
  a_mode_t mode;
  uint64_t key[2];       // 128 bits
  uint64_t nonce[2];     // 128 bits
  buf_t associated_data; // len 0 = no AD
  uint64_t input_tag[2]; // 128 bits, used for validating decryption
};

static void print_usage(FILE *out, const char *prog);
static void parse_args(int argc, char *argv[], opts_t *opts);
static void secure_zero(void *p, size_t n);
static uint8_t *read_file(const char *path, size_t *len);
static uint64_t load64(const uint8_t *p);
static uint64_t load_bytes(const uint8_t *p, size_t n);
static void to_lanes(const uint8_t *bytes, size_t len, bool pad, buf_t *out);
static uint8_t chartonib(char c);
static void load_inputs(const opts_t *opts, a_config_t *a_config,
                        a_ctx_t *a_context);

int main(int argc, char *argv[]) {

  opts_t opts = {0};
  a_config_t a_config = {0};
  a_ctx_t a_context = {0};

  parse_args(argc, argv, &opts);
  load_inputs(&opts, &a_config, &a_context);

  // encrypt / decrypt
  // write output

  free(a_context.plaintext.data);
  free(a_context.ciphertext.data);
  free(a_config.associated_data.data);

  return EXIT_SUCCESS;
}

// shows how to use
static void print_usage(FILE *out, const char *prog) {
  fprintf(
      out,
      "Usage: %s -e -i <file> -k <file> [-o <file>] [-a <file>] [-n <hex>]\n"
      "       %s -d -i <file> -k <file> [-o <file>] [-a <file>]\n"
      "       %s -h\n"
      "\n"
      "Andrew's Ascon-AEAD128 authenticated encryption.\n"
      "Encrypted output is written as: nonce (16 B) || ciphertext || tag (16 "
      "B)\n"
      "\n"
      "Options:\n"
      "  -h         show this help message and exit\n"
      "  -e         encrypt mode\n"
      "  -d         decrypt mode\n"
      "  -i <file>  input: plaintext or encrypted file\n"
      "  -o <file>  output file name (optional)\n"
      "  -k <file>  128-bit binary key\n"
      "  -a <file>  associated data (optional)\n"
      "  -n <hex>   128-bit nonce as 32 hex digits (encrypt only;\n"
      "             randomly generated if omitted)\n",
      prog, prog, prog);
}

// gets params from args
static void parse_args(int argc, char *argv[], opts_t *opts) {
  int opt;

  // too few args
  if (argc < 2) {
    print_usage(stderr, argv[0]); // help them
    exit(EXIT_FAILURE);
  }

  // flag inputs
  while ((opt = getopt(argc, argv, "hedi:o:k:a:n:")) != -1) {
    switch (opt) {
    case 'h':                       // help option
      print_usage(stdout, argv[0]); // whatever i compile to
      exit(EXIT_SUCCESS);

    case 'e': // encrypt mode set
      if (opts->mode != MODE_NONE) {
        fprintf(stderr, "Error: Choose only one of -e / -d \n");
        exit(EXIT_FAILURE);
      }
      opts->mode = MODE_ENCRYPT;
      break;

    case 'd': // decrypt mode set
      if (opts->mode != MODE_NONE) {
        fprintf(stderr, "Error: Choose only one of -e / -d \n");
        exit(EXIT_FAILURE);
      }
      opts->mode = MODE_DECRYPT;
      break;

    case 'i': // input file path
      if (opts->in_path) {
        fprintf(stderr, "Error: Choose a single input file -i\n");
        exit(EXIT_FAILURE);
      } else if (*optarg == '\0') {
        fprintf(stderr, "Error: Input file path -i not provided\n");
        exit(EXIT_FAILURE);
      }
      opts->in_path = optarg;
      break;

    case 'o': // output file path
      if (opts->out_path) {
        fprintf(stderr, "Error: Choose a single output file -o\n");
        exit(EXIT_FAILURE);
      } else if (*optarg == '\0') {
        fprintf(stderr, "Error: Input file path -o not provided\n");
        exit(EXIT_FAILURE);
      }
      opts->out_path = optarg;
      break;

    case 'k': // key file path
      if (opts->key_path) {
        fprintf(stderr, "Error: Choose a single key file -k\n");
        exit(EXIT_FAILURE);
      } else if (*optarg == '\0') {
        fprintf(stderr, "Error: Key file path -k not provided\n");
        exit(EXIT_FAILURE);
      }
      opts->key_path = optarg;
      break;

    case 'a': // associated data file path
      if (opts->ad_path) {
        fprintf(stderr, "Error: Choose a single associated data file -a\n");
        exit(EXIT_FAILURE);
      } else if (*optarg == '\0') {
        fprintf(stderr, "Error: Associated data file path -a not provided\n");
        exit(EXIT_FAILURE);
      }
      opts->ad_path = optarg;
      break;

    case 'n': // nonce hex input
      if (opts->nonce_hex) {
        fprintf(stderr, "Error: Choose a single nonce hex -n\n");
        exit(EXIT_FAILURE);
      }

      opts->nonce_hex = optarg;

      if (strncmp(opts->nonce_hex, "0x", 2) != 0) {
        fprintf(stderr, "Error: Nonce must begin with 0x\n");
        exit(EXIT_FAILURE);
      }

      const char *digits = opts->nonce_hex + 2; // skip "0x"
      if (strlen(digits) != 32) {
        fprintf(stderr,
                "Error: Nonce must contain exactly 32 hex characters\n");
        exit(EXIT_FAILURE);
      }
      for (size_t i = 0; i < 32; i++) { // length checked, all in bounds
        if (!isxdigit((unsigned char)digits[i])) {
          fprintf(stderr, "Error: Char in nonce '%c' not hex\n", digits[i]);
          exit(EXIT_FAILURE);
        }
      }
      break;
    }
  }

  // required flags
  if (opts->mode == MODE_NONE) {
    fprintf(stderr, "Error: Please select mode -e or -d\n");
    exit(EXIT_FAILURE);
  }

  if (opts->in_path == NULL) { // input file given?
    fprintf(stderr, "Error: Please provide an input file path -i\n");
    exit(EXIT_FAILURE);
  }

  if (opts->key_path == NULL) { // key file given?
    fprintf(stderr, "Error: Please provide a key file path -k\n");
    exit(EXIT_FAILURE);
  }
}

// for key buffer, sets to 0 before freeing
static void secure_zero(void *p, size_t n) {
  volatile uint8_t *v = p;
  while (n--)
    *v++ = 0; // zero everything up to n
}

// reads a file and outputs the stream
static uint8_t *read_file(const char *path, size_t *len) {
  FILE *f = fopen(path, "rb");

  if (f == NULL) { // check if file open went ok
    perror(path);
    exit(EXIT_FAILURE);
  }

  fseek(f, 0, SEEK_END);     // go to EOF
  long file_size = ftell(f); // get file size
  rewind(f);                 // go back to beginning

  if (file_size == 0) { // empty may be valid
    *len = 0;
    fclose(f);
    return NULL;
  }

  uint8_t *data = malloc(file_size); // point data to heap allotment

  if (data == NULL) {
    perror("malloc"); // maybe out of memory
    fclose(f);
    exit(EXIT_FAILURE);
  }

  if (fread(data, 1, file_size, f) != (size_t)file_size) {
    fprintf(stderr, "Error: Unexpected end of file %s\n", path);
    fclose(f);
    free(data); // leaking memory in this economy? nah.
    exit(EXIT_FAILURE);
  }

  *len = (size_t)file_size;
  fclose(f);
  return data;
}

// load 64 bits in little-endian order
static uint64_t load64(const uint8_t *p) {
  uint64_t w = 0;
  for (int i = 0; i < 8; i++) {
    w |= (uint64_t)p[i] << (8 * i);
    // little endian means p[0] is the least significant byte
  }
  return w;
}

// load bytes in little endian order to an n
static uint64_t load_bytes(const uint8_t *p, size_t n) {
  uint64_t w = 0;
  for (size_t i = 0; i < n; i++) { // append little endian to n bytes
    w |= (uint64_t)p[i] << (8 * i);
  }
  return w;
}

// takes byte stream and turns into little endian lanes
static void to_lanes(const uint8_t *bytes, size_t len, bool pad, buf_t *out) {
  size_t blocks = len / 16 + 1; // room for padding in the last block

  out->data = calloc(blocks * 2, sizeof *out->data); // zeroed
  if (out->data == NULL) {
    perror("calloc");
    exit(EXIT_FAILURE);
  }
  out->len = len;

  size_t full = len / 8; // whole lanes
  size_t rem = len % 8;  // leftover bytes
  for (size_t i = 0; i < full; i++) {
    out->data[i] = load64(bytes + 8 * i);
  }
  if (rem > 0) {
    out->data[full] = load_bytes(bytes + 8 * full, rem);
  }
  if (pad) {
    out->data[full] ^= (uint64_t)0x01 << (8 * rem); // 0x01 right after the data
  }
}

static uint8_t chartonib(char c) {
  if (c >= '0' && c <= '9')
    return c - '0'; // '7' - '0' = 7
  if (c >= 'a' && c <= 'f')
    return c - 'a' + 10; // 'c' - 'a' + 10 = 12
  if (c >= 'A' && c <= 'F')
    return c - 'A' + 10; // 'C' gives 12 too
  else
    return 0; // to silence compiler
}

// read files and enforce endianness
static void load_inputs(const opts_t *opts, a_config_t *a_config,
                        a_ctx_t *a_context) {
  a_config->mode = opts->mode;

  // key import
  size_t key_len;
  uint8_t *key_bytes = read_file(opts->key_path, &key_len);
  if (key_len != 16) { // need to make sure key is 128 bits
    fprintf(stderr, "Error: Key invalid length %zu\n", key_len);
    secure_zero(key_bytes, key_len); // zero this
    free(key_bytes);
    exit(EXIT_FAILURE);
  } // key should be good, so now we copy in little endian
  a_config->key[0] = load64(key_bytes);
  a_config->key[1] = load64(key_bytes + 8);
  secure_zero(key_bytes, key_len); // zero this
  free(key_bytes);                 // free mem

  // associated data (optional)
  if (opts->ad_path) {
    size_t ad_len;
    uint8_t *ad_bytes = read_file(opts->ad_path, &ad_len);
    if (ad_len > 0) { // empty AD skips the AD phase, len stays 0
      to_lanes(ad_bytes, ad_len, true, &a_config->associated_data);
    }
    free(ad_bytes);
  }

  // read in plaintext/ciphertext
  switch (opts->mode) {
  case MODE_ENCRYPT:

    // input nonce
    if (opts->nonce_hex == NULL) {
      uint8_t nonce_bytes[16];
      if (getentropy(nonce_bytes, 16) != 0) { // get 16 random bytes from OS
        perror("getentropy");
        exit(EXIT_FAILURE);
      }
      a_config->nonce[0] = load64(nonce_bytes);
      a_config->nonce[1] = load64(nonce_bytes + 8);
    } else {
      // split nonce into two words
      // flip the endianness
      uint8_t nonce_bytes[16];
      for (int i = 0; i < 16; i++) {
        nonce_bytes[i] = (chartonib(*(opts->nonce_hex + 2 + (2 * i))) << 4) |
                         chartonib(*(opts->nonce_hex + 2 + (2 * i) + 1));
      }
      a_config->nonce[0] = load64(nonce_bytes);
      a_config->nonce[1] = load64(nonce_bytes + 8);
    }

    // input plaintext
    size_t pt_len;
    uint8_t *pt_bytes = read_file(opts->in_path, &pt_len);
    to_lanes(pt_bytes, pt_len, true, &a_context->plaintext);
    free(pt_bytes);
    break;

  case MODE_DECRYPT: {
    // parse decryption file
    size_t in_len;
    uint8_t *in_bytes = read_file(opts->in_path, &in_len);

    free(in_bytes); // youngboy never leakmemory again
    break;
  }

  case MODE_NONE: // already rejected in parse_args
    break;
  }
}
