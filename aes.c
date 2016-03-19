// DESCRIPTION OF ALGORITHM
// KeyExpansions—round keys are derived from the cipher key using Rijndael's key schedule. AES requires a separate 128-bit round
//  key block for each round plus one more.
//
// InitialRound
//     AddRoundKey—each byte of the state is combined with a block of the round key using bitwise xor.
// Rounds
//     SubBytes—a non-linear substitution step where each byte is replaced with another according to a lookup table.
//     ShiftRows—a transposition step where the last three rows of the state are shifted cyclically a certain number of steps.
//     MixColumns—a mixing operation which operates on the columns of the state, combining the four bytes in each column.
//     AddRoundKey
// Final Round (no MixColumns)
//     SubBytes
//     ShiftRows
//     AddRoundKey.

#include "aes.h"
#include <stdint.h>
#include <stdio.h>
#include <getopt.h>
#include <stdlib.h>
#include <string.h>

#define DEBUG 1
#define USAGE_MESSAGE "Usage: aes -l {128, 192, 256}\nThe argument for -l is the key length in bits.\n\n"

// AES-specific constants
#define BLOCK_LENGTH_IN_BYTES 16
#define MAX_KEY_LENGTH_IN_BYTES 32

const uint8_t n_b = 4; // Length of block in 4-byte words

void sub_word(uint8_t* out_word);

/*
================================================================================
DEBUG
================================================================================
*/

void debug_print_hex(uint8_t* in, int len) {
  if (!DEBUG) return;

  for (int i = 0; i < len; i++) {
    printf("%02X ", in[i]);
    if ((i + 1) % 4 == 0) printf("\n");
  }
  printf("\n");
}

void debug_print_key_expansion(uint8_t** key_schedule, int n_r) {
  if (!DEBUG) return;

  for (int i = 0; i < n_r + 1; i++) {
    printf("Round %2d\t", i + 1);
    for (int j = 0; j < n_b; j++) {
      printf("%02X %02X %02X %02X    ", key_schedule[i+j][0], key_schedule[i+j][1], key_schedule[i+j][3], key_schedule[i+j][4]);
    }
    printf("\n\n");
  }
}

/*
================================================================================
MATH OPS
================================================================================
*/

/*
 * Addition in GF(2^8)
 * http://en.wikipedia.org/wiki/Finite_field_arithmetic
 */
uint8_t gadd(uint8_t a, uint8_t b) {
  return a^b;
}

/*
 * Subtraction in GF(2^8)
 * http://en.wikipedia.org/wiki/Finite_field_arithmetic
 */
uint8_t gsub(uint8_t a, uint8_t b) {
  return a^b;
}

/* From Wikipedia
 *
 * Multiply two numbers in the GF(2^8) finite field defined
 * by the polynomial x^8 + x^4 + x^3 + x + 1 = 0
 * using the Russian Peasant Multiplication algorithm
 * (the other way being to do carry-less multiplication followed by a modular reduction)
 */
uint8_t gmul(uint8_t a, uint8_t b) {
  uint8_t p = 0; /* the product of the multiplication */
  while (b) {
    if (b & 1) /* if b is odd, then add the corresponding a to p (final product = sum of all a's corresponding to odd b's) */
      p ^= a; /* since we're in GF(2^m), addition is an XOR */

    if (a & 0x80) /* GF modulo: if a >= 128, then it will overflow when shifted left, so reduce */
      a = (a << 1) ^ 0x11b; /* XOR with the primitive polynomial x^8 + x^4 + x^3 + x + 1 -- you can change it but it must be irreducible */
    else
      a <<= 1; /* equivalent to a*2 */
    b >>= 1; /* equivalent to b // 2 */
  }
  return p;
}

/*
================================================================================
CIPHER
--------------------------------------------------------------------------------
Cipher(byte in[4*Nb], byte out[4*Nb], word w[Nb*(Nr+1)])
  begin
    byte  state[4,Nb]
    state = in
    AddRoundKey(state, w[0, Nb-1])
    // See Sec. 5.1.4
    for round = 1 step 1 to Nr–1
      SubBytes(state)
      // See Sec. 5.1.1
      ShiftRows(state)
      // See Sec. 5.1.2
      MixColumns(state)
      // See Sec. 5.1.3
      AddRoundKey(state, w[round*Nb, (round+1)*Nb-1])
    end for
    SubBytes(state)
    ShiftRows(state)
    AddRoundKey(state, w[Nr*Nb, (Nr+1)*Nb-1])
    out = state
  end
================================================================================
*/

void add_round_key(uint8_t* state, uint8_t** key_schedule, uint8_t rnd) {
  // xor the block state with the round key (block of the expanded key)
  for (int i = 0; i < n_b; i++) {
    state[i*n_b+0] ^= key_schedule[i+rnd][0];
    state[i*n_b+1] ^= key_schedule[i+rnd][1];
    state[i*n_b+2] ^= key_schedule[i+rnd][2];
    state[i*n_b+3] ^= key_schedule[i+rnd][3];
  }
}

void sub_bytes(uint8_t* state) {
  for (int i = 0; i < n_b; i++) {
    state[i*n_b+0] = s_box[state[i*n_b+0]];
    state[i*n_b+1] = s_box[state[i*n_b+1]];
    state[i*n_b+2] = s_box[state[i*n_b+2]];
    state[i*n_b+3] = s_box[state[i*n_b+3]];
  }
}

void shift_rows(uint8_t* state) {
  uint8_t state_temp[BLOCK_LENGTH_IN_BYTES];
  memcpy(state_temp, state, BLOCK_LENGTH_IN_BYTES * sizeof(uint8_t));

  // Row 1, shift left once
  state[1+0] = state_temp[1+4];
  state[1+4] = state_temp[1+8];
  state[1+8] = state_temp[1+12];
  state[1+12] = state_temp[1+0];

  // Row 2, shift left twice
  state[2+0]  = state_temp[2+8];
  state[2+4]  = state_temp[2+12];
  state[2+8]  = state_temp[2+0];
  state[2+12] = state_temp[2+4];

  // Row 3, shift left once
  state[3+0]  = state_temp[3+12];
  state[3+4]  = state_temp[3+0];
  state[3+8]  = state_temp[3+4];
  state[3+12] = state_temp[3+8];
}

void cipher(uint8_t* out, uint8_t* in, uint8_t** key_schedule, uint8_t n_b, uint8_t n_k, uint8_t n_r) {
  uint8_t* state;

  state = malloc(BLOCK_LENGTH_IN_BYTES * sizeof(uint8_t));
  memcpy(state, in, BLOCK_LENGTH_IN_BYTES * sizeof(uint8_t));

  debug_print_hex(in, 16);
  debug_print_hex(state, 16);

  add_round_key(state, key_schedule, 0);

  debug_print_hex(state, 16);

  for (int i = 0; i < n_r; i++) {
    sub_bytes(state);
    shift_rows(state);
  }
  // for round = 1 step 1 to Nr–1
  //   SubBytes(state)
  //   // See Sec. 5.1.1
  //   ShiftRows(state)
  //   // See Sec. 5.1.2
  //   MixColumns(state)
  //   // See Sec. 5.1.3
  //   AddRoundKey(state, w[round*Nb, (round+1)*Nb-1])
  // end for
  // SubBytes(state)
  // ShiftRows(state)
  // AddRoundKey(state, w[Nr*Nb, (Nr+1)*Nb-1])
  // out = state
}

/*
===================================================================
KEY EXPANSION
-------------------------------------------------------------------
KeyExpansion(byte key[4*Nk], word w[Nb*(Nr+1)], Nk)
  begin
    word  temp
    i = 0
    while (i < Nk)
      w[i] = word(key[4*i], key[4*i+1], key[4*i+2], key[4*i+3])
      i = i+1
    end while
    i = Nk
    while (i < Nb * (Nr+1)]
      temp = w[i-1]
      if (i mod Nk = 0)
        temp = SubWord(RotWord(temp)) xor Rcon[i/Nk]
      else if (Nk > 6 and i mod Nk = 4)
        temp = SubWord(temp)
      end if
      w[i] = w[i-Nk] xor temp
      i = i + 1
    end while
  end
===================================================================
*/
void sub_word(uint8_t* out_word) {
  // Input: 4-byte word
  // Output: 4-byte word with substitution using S-box
  for (int i = 0; i < 4; i++)
    out_word[i] = s_box[out_word[i]];
}

void rot_word(uint8_t* out_word) {
  // Input: 4-byte word
  // Output: Same 4-byte word, but rotated to the left cyclically
  //   e.g. [a0, a1, a2, a3] => [a1, a2, a3, a0]
  uint8_t aux = out_word[0];
  out_word[0] = out_word[1];
  out_word[1] = out_word[2];
  out_word[2] = out_word[3];
  out_word[3] = aux;
}

uint8_t** key_expansion(uint8_t* key, uint8_t n_k, uint8_t n_r) {
  // Input: key
  // Output: Nb * (Nr + 1) array of words (key schedule)
  uint8_t** out_words;
  uint8_t num_words = n_b * (n_r + 1);
  uint8_t temp[4];
  uint8_t r_con[num_words][4];  // Round constants

  // Let's compute the round constants!
  for (int i = 1; i < num_words; i ++) {
    r_con[i][0] = (i == 1) ? 0 : 1 << (i - 1);
  }

  // Let's allocate space for this word array!
  out_words = malloc(num_words * sizeof(uint8_t*));
  for (int i = 0; i < num_words; i++) {
    out_words[i] = malloc(4 * sizeof(uint8_t));
  }

  for (int i = 0; i < n_k; i++) {
    // Copy words of key to out_words
    out_words[i][0] = key[4*i];
    out_words[i][1] = key[4*i+1];
    out_words[i][2] = key[4*i+2];
    out_words[i][3] = key[4*i+3];
  }

  for (int i = n_k; i < num_words; i++) {
    memcpy(temp, out_words[i-1], n_b * sizeof(uint8_t));
    if (i % n_k == 0) {
      rot_word(temp);
      sub_word(temp);
      temp[0] = temp[0] ^ r_con[i/n_k][0];
      temp[1] = temp[1] ^ r_con[i/n_k][1];
      temp[2] = temp[2] ^ r_con[i/n_k][2];
      temp[3] = temp[3] ^ r_con[i/n_k][3];
    }
    else if (n_k > 6 && (i % n_k) == 4) {
      sub_word(temp);
    }
    out_words[i][0] = out_words[i-n_k][0] ^ temp[0];
    out_words[i][1] = out_words[i-n_k][1] ^ temp[1];
    out_words[i][2] = out_words[i-n_k][2] ^ temp[2];
    out_words[i][3] = out_words[i-n_k][3] ^ temp[3];
  }

  return out_words;
}

/*
================================================================================
MAIN
================================================================================
*/

int main(int argc, char **argv) {
  uint8_t n_k;                           // Key length in bytes
  uint8_t n_r;                           // Number of rounds
  int keylen;
  char* keylen_in = NULL;                // User input from options
  char* key_string = NULL;
  int opt, l_flag = 0, k_flag = 0, i_flag = 0;

  // =======================
  // GET KEY LENGTH AS PARAM
  // =======================

  while ((opt = getopt (argc, argv, "l:k:")) != -1) {
    switch (opt) {
      case 'l':
        // User option to specify key length
        keylen_in = optarg;
        if (strcmp(keylen_in, "128") == 0 || strcmp(keylen_in, "192") == 0 || strcmp(keylen_in, "256") == 0) {
          keylen = atoi(keylen_in);
        } else {
          printf (USAGE_MESSAGE);
          exit(0);
        }
        l_flag = 1;
        break;

      case 'k':
        // User option to specify key as hex string
        key_string = optarg;
        k_flag = 1;
        break;

      default:
        printf (USAGE_MESSAGE);
        exit(0);
    }
  }

  // Compute number of rounds and keylen in bytes
  switch (keylen) {
    case 128:
      n_k = 4;      n_r = 10;
      break;
    case 192:
      n_k = 6;      n_r = 12;
      break;
    case 256:
      n_k = 8;      n_r = 14;
      break;
  }

  // TODO: Accept user input
  // Input block
  uint8_t in_block[] = {
    0x00, 0x11, 0x22, 0x33,
    0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xaa, 0xbb,
    0xcc, 0xdd, 0xee, 0xff};

  uint8_t* out_block;

  // TEST TEST TEST TEST TEST //
  uint8_t** key_schedule;
  uint8_t test_key[] = {
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00};
  key_schedule = key_expansion(test_key, 4, 10);
  debug_print_key_expansion(key_schedule, n_r);
  // TEST TEST TEST TEST TEST //

  cipher(out_block, in_block, key_schedule, n_b, n_k, n_r);
}
