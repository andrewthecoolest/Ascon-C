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

static const uint64_t ASCON_CTABLE[16] = {
    0x000000000000003cULL, 0x000000000000002dULL, 0x000000000000001eULL,
    0x000000000000000fULL, 0x00000000000000f0ULL, 0x00000000000000e1ULL,
    0x00000000000000d2ULL, 0x00000000000000c3ULL, 0x00000000000000b4ULL,
    0x00000000000000a5ULL, 0x0000000000000096ULL, 0x0000000000000087ULL,
    0x0000000000000078ULL, 0x0000000000000069ULL, 0x000000000000005aULL,
    0x000000000000004bULL};

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
};

// Crypto Functions
static void a_subs(uint64_t state[5]);
static void a_diff(uint64_t state[5]);
static void a_permute(uint64_t state[5], uint8_t rounds);
static void a_init(uint64_t key[2], uint64_t nonce[2], uint64_t state[5]);
static void a_procad(buf_t associated_data, uint64_t state[5]);
static void a_enc(a_ctx_t *context);
static void a_dec(a_ctx_t *context);
static void a_final(a_ctx_t *context, a_config_t *config);
static void a_out(a_ctx_t *context, a_config_t *config, const char *path);

// I/O Functions
static void print_usage(FILE *out, const char *prog);
static void parse_args(int argc, char *argv[], opts_t *opts);
static void secure_zero(void *p, size_t n);
static void wipe_buf(buf_t *b);
_Noreturn static void secure_exit(int status);
static uint8_t *read_file(const char *path, size_t *len);
static uint64_t load64(const uint8_t *p);
static uint64_t load_bytes(const uint8_t *p, size_t n);
static bool to_lanes(const uint8_t *bytes, size_t len, bool pad, buf_t *out);
static void write_lanes(FILE *f, const uint64_t *lanes, size_t len);
static uint8_t chartonib(char c);
static void load_inputs(const opts_t *opts, a_config_t *a_config,
                        a_ctx_t *a_context);

// registered in main so secure_exit can wipe secrets from any function
static a_config_t *g_config = NULL;
static a_ctx_t *g_context = NULL;

int main(int argc, char *argv[]) {

  opts_t opts = {0};
  a_config_t a_config = {0};
  a_ctx_t a_context = {0};
  g_config = &a_config;
  g_context = &a_context;

  parse_args(argc, argv, &opts);
  load_inputs(&opts, &a_config, &a_context);

  // instaciate state
  a_init(a_config.key, a_config.nonce, a_context.state);

  // process associated data (can be empty)
  a_procad(a_config.associated_data, a_context.state);

  // encrypt or decrypt
  switch (a_config.mode) {
  case MODE_ENCRYPT:
    a_enc(&a_context);

    // finalize
    a_final(&a_context, &a_config);

    // write output
    a_out(&a_context, &a_config, opts.out_path);
    break;

  case MODE_DECRYPT:
    a_dec(&a_context);

    // finalize
    uint64_t tmptag[2] = {a_context.tag[0], a_context.tag[1]};
    a_final(&a_context, &a_config);
    uint64_t diff = (a_context.tag[0] ^ tmptag[0]) |
                    (a_context.tag[1] ^ tmptag[1]); // for const time compare
    if (diff != 0) {
      fprintf(stderr, "Error: Decryption tag does not match\n");
      secure_exit(EXIT_FAILURE); // release no plaintext
    }

    // write output
    a_out(&a_context, &a_config, opts.out_path);
    break;

  case MODE_NONE:
    break;
  }

  secure_exit(EXIT_SUCCESS); // wipe on the normal path too
}

/*

𝑦0 = 𝑥4𝑥1 ⊕ 𝑥3 ⊕ 𝑥2𝑥1 ⊕ 𝑥2 ⊕ 𝑥1𝑥0 ⊕ 𝑥1 ⊕ 𝑥0,
𝑦1 = 𝑥4 ⊕ 𝑥3𝑥2 ⊕ 𝑥3𝑥1 ⊕ 𝑥3 ⊕ 𝑥2𝑥1 ⊕ 𝑥2 ⊕ 𝑥1 ⊕ 𝑥0,
𝑦2 = 𝑥4𝑥3 ⊕ 𝑥4 ⊕ 𝑥2 ⊕ 𝑥1 ⊕ 1,
𝑦3 = 𝑥4𝑥0 ⊕ 𝑥4 ⊕ 𝑥3𝑥0 ⊕ 𝑥3 ⊕ 𝑥2 ⊕ 𝑥1 ⊕ 𝑥0,
𝑦4 = 𝑥4𝑥1 ⊕ 𝑥4 ⊕ 𝑥3 ⊕ 𝑥1𝑥0 ⊕ 𝑥1

*/

static void a_subs(uint64_t state[5]) { // substitution round
  uint64_t x0 = state[0]; // copy inputs first, outputs overwrite state
  uint64_t x1 = state[1];
  uint64_t x2 = state[2];
  uint64_t x3 = state[3];
  uint64_t x4 = state[4];

  state[0] = (x4 & x1) ^ (x3) ^ (x2 & x1) ^ (x2) ^ (x1 & x0) ^ (x1) ^ (x0);
  state[1] =
      (x4) ^ (x3 & x2) ^ (x3 & x1) ^ (x3) ^ (x2 & x1) ^ (x2) ^ (x1) ^ (x0);
  state[2] = ~((x4 & x3) ^ (x4) ^ (x2) ^ (x1)); // ^ 1 on every bit = NOT
  state[3] = (x4 & x0) ^ (x4) ^ (x3 & x0) ^ (x3) ^ (x2) ^ (x1) ^ (x0);
  state[4] = (x4 & x1) ^ (x4) ^ (x3) ^ (x1 & x0) ^ (x1);
}

/*

Σ0(𝑆0) = 𝑆0 ⊕ (𝑆0 ⋙ 19) ⊕ (𝑆0 ⋙ 28) (8)
Σ1(𝑆1) = 𝑆1 ⊕ (𝑆1 ⋙ 61) ⊕ (𝑆1 ⋙ 39) (9)
Σ2(𝑆2) = 𝑆2 ⊕ (𝑆2 ⋙ 1) ⊕ (𝑆2 ⋙ 6) (10)
Σ3(𝑆3) = 𝑆3 ⊕ (𝑆3 ⋙ 10) ⊕ (𝑆3 ⋙ 17) (11)
Σ4(𝑆4) = 𝑆4 ⊕ (𝑆4 ⋙ 7) ⊕ (𝑆4 ⋙ 41) (12)

*/

static void a_diff(uint64_t state[5]) { // diffusion round
  // diffusion
  state[0] ^= ((state[0] >> 19) | (state[0] << (64 - 19))) ^
              ((state[0] >> 28) | (state[0] << (64 - 28)));

  state[1] ^= ((state[1] >> 61) | (state[1] << (64 - 61))) ^
              ((state[1] >> 39) | (state[1] << (64 - 39)));

  state[2] ^= ((state[2] >> 1) | (state[2] << (64 - 1))) ^
              ((state[2] >> 6) | (state[2] << (64 - 6)));

  state[3] ^= ((state[3] >> 10) | (state[3] << (64 - 10))) ^
              ((state[3] >> 17) | (state[3] << (64 - 17)));

  state[4] ^= ((state[4] >> 7) | (state[4] << (64 - 7))) ^
              ((state[4] >> 41) | (state[4] << (64 - 41)));
}

static void a_permute(uint64_t state[5], uint8_t rounds) {
  uint8_t minround = 16 - rounds;
  // run the permutation
  for (int i = 0; i < rounds; i++) {
    // add round constant
    state[2] ^= ASCON_CTABLE[minround + i];
    // substitution
    a_subs(state);
    // diffusion
    a_diff(state);
  }
}

static void a_init(uint64_t key[2], uint64_t nonce[2], uint64_t state[5]) {
  // init
  state[0] |= ASCON_IV;
  state[1] |= key[0];
  state[2] |= key[1];
  state[3] |= nonce[0];
  state[4] |= nonce[1];

  // 12 rounds permutation
  a_permute(state, 12);

  // XOR key to state
  state[3] ^= key[0];
  state[4] ^= key[1];
}

static void a_procad(buf_t associated_data, uint64_t state[5]) {
  // process associated_data
  if (associated_data.data != NULL) { // check if associate data is empty
    for (unsigned long i = 0; i < (associated_data.len / 16) + 1; i++) {
      state[0] ^= *(associated_data.data + 2 * i);
      state[1] ^= *(associated_data.data + (2 * i) + 1);

      a_permute(state, 8);
    }
  }
  state[4] ^= 0x8000000000000000ULL; // flip the MSB
}

static void a_enc(a_ctx_t *context) {
  // do encryption
  size_t last = context->plaintext.len / 16;     // index of the last block
  size_t last_len = context->plaintext.len % 16; // rem in bytes

  // first n-1 full blocks: absorb, squeeze, permute
  for (size_t i = 0; i < last; i++) {
    context->state[0] ^= *(context->plaintext.data + 2 * i);
    context->state[1] ^= *(context->plaintext.data + (2 * i) + 1);
    *(context->ciphertext.data + 2 * i) = context->state[0];
    *(context->ciphertext.data + (2 * i) + 1) = context->state[1];

    a_permute(context->state, 8);
  }

  // last block
  uint64_t mask0, mask1;
  if (last_len < 8) { // partial lane 0, lane 1 untouched
    mask0 = (1ULL << (8 * last_len)) - 1;
    mask1 = 0;
  } else {         // full lane 0, partial lane 1
    mask0 = ~0ULL; // not (1ULL << 64) - 1, shift by 64 is UB
    mask1 = (1ULL << (8 * (last_len - 8))) - 1;
  }

  // state keeps the full XOR, padding is already in the plaintext lanes
  context->state[0] ^= *(context->plaintext.data + 2 * last);
  context->state[1] ^= *(context->plaintext.data + (2 * last) + 1);

  // Cn = S[0:l-1], drop the keystream past the data
  *(context->ciphertext.data + 2 * last) = context->state[0] & mask0;
  *(context->ciphertext.data + (2 * last) + 1) = context->state[1] & mask1;
}

static void a_dec(a_ctx_t *context) { // decrypt return status if tag invalid
  // do decryption
  size_t last = context->ciphertext.len / 16; // index of the last 128 bit block
  size_t last_len = context->ciphertext.len % 16; // rem in bytes

  // first n-1 full blocks: xor out, set, permute
  for (size_t i = 0; i < last; i++) { // i is 128bit jumps
    *(context->plaintext.data + 2 * i) =
        context->state[0] ^ *(context->ciphertext.data + 2 * i);
    *(context->plaintext.data + (2 * i) + 1) =
        context->state[1] ^ *(context->ciphertext.data + (2 * i) + 1);

    context->state[0] = *(context->ciphertext.data + 2 * i);
    context->state[1] = *(context->ciphertext.data + (2 * i) + 1);

    a_permute(context->state, 8);
  }

  // last block: only last_len bytes are real, split the 128-bit mask per lane
  uint64_t mask0, mask1, pad0, pad1;
  if (last_len < 8) { // partial lane 0, lane 1 untouched
    mask0 = (1ULL << (8 * last_len)) - 1;
    mask1 = 0;
    pad0 = 1ULL << (8 * last_len); // 1 || 0* right after the data
    pad1 = 0;
  } else {         // full lane 0, partial lane 1
    mask0 = ~0ULL; // not (1ULL << 64) - 1, shift by 64 is UB
    mask1 = (1ULL << (8 * (last_len - 8))) - 1;
    pad0 = 0;
    pad1 = 1ULL << (8 * (last_len - 8));
  }

  uint64_t c0 = *(context->ciphertext.data + 2 * last);
  uint64_t c1 = *(context->ciphertext.data + (2 * last) + 1);

  // Pn = S[0:l-1] ^ Cn
  *(context->plaintext.data + 2 * last) = (context->state[0] ^ c0) & mask0;
  *(context->plaintext.data + (2 * last) + 1) =
      (context->state[1] ^ c1) & mask1;

  // S[l:127] ^= 1 || 0*
  context->state[0] ^= pad0;
  context->state[1] ^= pad1;

  // S[0:l-1] = Cn, keep the rest
  context->state[0] = (context->state[0] & ~mask0) | (c0 & mask0);
  context->state[1] = (context->state[1] & ~mask1) | (c1 & mask1);
}

static void a_final(a_ctx_t *context, a_config_t *config) {
  uint64_t statex[5] = {0, 0, config->key[0], config->key[1], 0};
  for (int i = 0; i < 5; i++) {
    context->state[i] ^= statex[i];
  }
  a_permute(context->state, 12);
  context->tag[0] = context->state[3] ^ config->key[0];
  context->tag[1] = context->state[4] ^ config->key[1];
}

static void a_out(a_ctx_t *context, a_config_t *config, const char *path) {
  if (path == NULL) { // no -o given, pick a default name
    path = (config->mode == MODE_ENCRYPT) ? "ascon.enc" : "ascon.dec";
  }

  FILE *f = fopen(path, "wb");

  if (f == NULL) { // check if file open went ok
    perror(path);
    secure_exit(EXIT_FAILURE);
  }

  switch (config->mode) {
  case MODE_ENCRYPT:
    // Nonce || Ciphertext (truncated) || Tag
    write_lanes(f, config->nonce, 16);
    write_lanes(f, context->ciphertext.data, context->ciphertext.len);
    write_lanes(f, context->tag, 16);
    break;

  case MODE_DECRYPT:
    // plaintext only, tag was already checked
    write_lanes(f, context->plaintext.data, context->plaintext.len);
    break;

  case MODE_NONE:
    break;
  }

  if (fclose(f) != 0) { // flush can fail
    perror(path);
    secure_exit(EXIT_FAILURE);
  }
}

//////////////////////////////////////////////////
//
// ALL I/O NO CRYPTO
//
//////////////////////////////////////////////////

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

// zero the whole lane allocation (2 lanes per block + pad block), then free
static void wipe_buf(buf_t *b) {
  if (b->data != NULL) {
    secure_zero(b->data, 2 * (b->len / 16 + 1) * sizeof *b->data);
    free(b->data);
    b->data = NULL;
  }
  b->len = 0;
}

// wipe every secret main registered, then exit
_Noreturn static void secure_exit(int status) {
  if (g_config != NULL) {
    secure_zero(g_config->key, sizeof g_config->key);
    wipe_buf(&g_config->associated_data);
  }
  if (g_context != NULL) {
    secure_zero(g_context->state, sizeof g_context->state); // invertible to key
    secure_zero(g_context->tag, sizeof g_context->tag);
    wipe_buf(&g_context->plaintext);
    wipe_buf(&g_context->ciphertext);
  }
  exit(status);
}

// reads a file and outputs the stream
static uint8_t *read_file(const char *path, size_t *len) {
  FILE *f = fopen(path, "rb");

  if (f == NULL) { // check if file open went ok
    perror(path);
    secure_exit(EXIT_FAILURE);
  }
  if (fseek(f, 0, SEEK_END) == -1) { // go to EOF
    perror("fseek");
    secure_exit(EXIT_FAILURE);
  }
  long file_size = ftell(f); // get file size
  if (file_size == -1) {
    perror("ftell");
    secure_exit(EXIT_FAILURE);
  }
  size_t f_size = (size_t)file_size;
  rewind(f); // go back to beginning

  if (f_size == 0) { // empty may be valid
    *len = 0;
    fclose(f);
    return NULL;
  }

  uint8_t *data = malloc(f_size); // point data to heap allotment

  if (data == NULL) {
    perror("malloc"); // maybe out of memory
    fclose(f);
    secure_exit(EXIT_FAILURE);
  }

  if (fread(data, 1, f_size, f) != f_size) {
    fprintf(stderr, "Error: Unexpected end of file %s\n", path);
    fclose(f);
    secure_zero(data, f_size); // partial read is still secret
    free(data);                // leaking memory in this economy? nah.
    secure_exit(EXIT_FAILURE);
  }

  *len = f_size;
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
// a lane is just 64 bits of a 128 bit block
// returns false on allocation failure so the caller can wipe bytes first
static bool to_lanes(const uint8_t *bytes, size_t len, bool pad, buf_t *out) {
  size_t blocks = len / 16 + 1; // room for padding in the last block

  out->data =
      calloc(blocks * 2, sizeof *out->data); // zeroed
                                             // 2*block bc count in uint64_t
  if (out->data == NULL) {
    perror("calloc");
    return false;
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
  return true;
}

// write len bytes out of little endian lanes, undoes to_lanes
static void write_lanes(FILE *f, const uint64_t *lanes, size_t len) {
  for (size_t i = 0; i < len; i++) {
    uint8_t b = (uint8_t)(lanes[i / 8] >> (8 * (i % 8))); // byte i of stream
    if (fputc(b, f) == EOF) {
      perror("fputc");
      secure_exit(EXIT_FAILURE);
    }
  }
}

static uint8_t chartonib(char c) {
  if (c >= '0' && c <= '9')
    return (uint8_t)(c - '0'); // '7' - '0' = 7
  if (c >= 'a' && c <= 'f')
    return (uint8_t)(c - 'a' + 10); // 'c' - 'a' + 10 = 12
  if (c >= 'A' && c <= 'F')
    return (uint8_t)(c - 'A' + 10); // 'C' gives 12 too
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
    secure_exit(EXIT_FAILURE);
  } // key should be good, so now we copy in little endian
  a_config->key[0] = load64(key_bytes);
  a_config->key[1] = load64(key_bytes + 8);
  secure_zero(key_bytes, key_len); // zero this
  free(key_bytes);                 // free mem

  // associated data (optional)
  if (opts->ad_path) {
    size_t ad_len;
    uint8_t *ad_bytes = read_file(opts->ad_path, &ad_len);
    bool ad_ok = true;
    if (ad_len > 0) { // empty AD skips the AD phase, len stays 0
      ad_ok = to_lanes(ad_bytes, ad_len, true, &a_config->associated_data);
    }
    secure_zero(ad_bytes, ad_len);
    free(ad_bytes);
    if (!ad_ok)
      secure_exit(EXIT_FAILURE);
  }

  // read in plaintext/ciphertext
  switch (opts->mode) {
  case MODE_ENCRYPT:

    // input nonce
    if (opts->nonce_hex == NULL) {
      uint8_t nonce_bytes[16];
      if (getentropy(nonce_bytes, 16) != 0) { // get 16 random bytes from OS
        perror("getentropy");
        secure_exit(EXIT_FAILURE);
      }
      a_config->nonce[0] = load64(nonce_bytes);
      a_config->nonce[1] = load64(nonce_bytes + 8);
    } else {
      // split nonce into two words
      // flip the endianness
      uint8_t nonce_bytes[16];
      for (int i = 0; i < 16; i++) {
        nonce_bytes[i] =
            (uint8_t)((chartonib(*(opts->nonce_hex + 2 + (2 * i))) << 4) |
                      chartonib(*(opts->nonce_hex + 2 + (2 * i) + 1)));
      }
      a_config->nonce[0] = load64(nonce_bytes);
      a_config->nonce[1] = load64(nonce_bytes + 8);
    }

    // input plaintext
    size_t pt_len;
    uint8_t *pt_bytes = read_file(opts->in_path, &pt_len);
    bool pt_ok = to_lanes(pt_bytes, pt_len, true, &a_context->plaintext);
    secure_zero(pt_bytes, pt_len);
    free(pt_bytes);
    if (!pt_ok)
      secure_exit(EXIT_FAILURE);

    // make room for ciphertext
    a_context->ciphertext.data =
        calloc(2 * ((a_context->plaintext.len / 16) + 1),
               sizeof *a_context->plaintext.data);
    if (a_context->ciphertext.data == NULL) {
      perror("calloc"); // maybe out of memory
      secure_exit(EXIT_FAILURE);
    }
    a_context->ciphertext.len = a_context->plaintext.len;

    break;

  case MODE_DECRYPT: {
    // parse decryption file
    // in form: { NONCE || CIPHERTEXT || TAG } / {16 bytes, ? bytes, , 16
    // bytes}
    size_t in_len;
    uint8_t *in_bytes = read_file(opts->in_path, &in_len);

    if (in_len < 32) {
      fprintf(stderr, "Error: Decryption file too small %zu\n", in_len);
      secure_zero(in_bytes, in_len);
      free(in_bytes);
      secure_exit(EXIT_FAILURE);
    }

    // nonce parse -- take first 16 bytes
    // tag parse -- take last 16 bytes
    // load in
    a_config->nonce[0] = load64(in_bytes);
    a_config->nonce[1] = load64(in_bytes + 8);
    a_context->tag[0] = load64(in_bytes + in_len - 16);
    a_context->tag[1] = load64(in_bytes + in_len - 8);

    // cipher left by subtraction
    bool ct_ok =
        to_lanes(in_bytes + 16, in_len - 32, false, &a_context->ciphertext);

    secure_zero(in_bytes, in_len); // zero it
    free(in_bytes);                // youngboy never leakmemory again
    if (!ct_ok)
      secure_exit(EXIT_FAILURE);

    // make room for plaintext
    a_context->plaintext.data =
        calloc(2 * ((a_context->ciphertext.len / 16) + 1),
               sizeof *a_context->ciphertext.data);
    if (a_context->plaintext.data == NULL) {
      perror("calloc"); // maybe out of memory
      secure_exit(EXIT_FAILURE);
    }
    a_context->plaintext.len = a_context->ciphertext.len;

    break;
  }

  case MODE_NONE: // already rejected in parse_args
    break;
  }
}
