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
#include "gf.h"
#include <stdint.h>
#include <stdio.h>
#include <getopt.h>
#include <stdlib.h>
#include <string.h>

#define DEBUG 1
#define USAGE_MESSAGE "Usage: aes (-d) -k <key> -i <plaintext/ciphertext>\n\tkey - 128-bit, 192-bit, or 256-bit as hex string\n\tplaintext - 128-bit plaintext as hex string\nOption -d for decrypt. Encrypt by default.\n\n"

// AES-specific constants
#define BLOCK_LENGTH_IN_BYTES 16
#define MAX_KEY_LENGTH_IN_BYTES 32

const uint8_t n_b = 4; // Length of block in 4-byte words

void sub_word(uint8_t *out_word);

/*
================================================================================
DEBUG
================================================================================
*/

void debug_print_hex(uint8_t *in, int len) {
  if (!DEBUG) return;

  for (int i = 0; i < len; i++) {
    printf("%02X ", in[i]);
    if ((i + 1) % 4 == 0) printf("\n");
  }
  printf("\n");
}

void debug_print_block(uint8_t *block, char *label) {
  if (!DEBUG) return;

  if (label) {
    printf("%s", label);
  }
  for (int j = 0; j < n_b; j++) {
    for (int i = 0; i < 4; i++)
      printf("%02X", block[n_b*j+i]);
    printf(" ");
  }
  printf("\n");
}

void debug_print_key_expansion(uint8_t **key_schedule, int n_r) {
  if (!DEBUG) return;

  for (int i = 0; i < n_r; i++) {
    printf("Round %2d\t", i);
    for (int j = i*4; j < n_b + i*4; j++) {
      printf("%02X %02X %02X %02X    ", key_schedule[j][0], key_schedule[j][1], key_schedule[j][2], key_schedule[j][3]);
    }
    printf("\n\n");
  }
}

void debug_print_key_schedule(uint8_t **key_schedule, int rnd) {
  if (!DEBUG) return;

  printf("  Kschd: ");
  for (int j = rnd*4; j < n_b + rnd*4; j++) {
    printf("%02X%02X%02X%02X ", key_schedule[j][0], key_schedule[j][1], key_schedule[j][2], key_schedule[j][3]);
  }
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

void add_round_key(uint8_t *state, uint8_t **key_schedule, uint8_t rnd) {
  // xor the block state with the round key (block of the expanded key)
  for (int i = 0; i < n_b; i++) {
    state[i*n_b+0] ^= key_schedule[rnd*4+i][0];
    state[i*n_b+1] ^= key_schedule[rnd*4+i][1];
    state[i*n_b+2] ^= key_schedule[rnd*4+i][2];
    state[i*n_b+3] ^= key_schedule[rnd*4+i][3];
  }
}

void sub_bytes(uint8_t *state) {
  for (int i = 0; i < n_b; i++) {
    state[i*n_b+0] = s_box[state[i*n_b+0]];
    state[i*n_b+1] = s_box[state[i*n_b+1]];
    state[i*n_b+2] = s_box[state[i*n_b+2]];
    state[i*n_b+3] = s_box[state[i*n_b+3]];
  }
}

void shift_rows(uint8_t *state) {
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

  // Row 3, shift left three times
  state[3+0]  = state_temp[3+12];
  state[3+4]  = state_temp[3+0];
  state[3+8]  = state_temp[3+4];
  state[3+12] = state_temp[3+8];
}

void mix_columns(uint8_t *state) {
  uint8_t a[] = {0x02, 0x01, 0x01, 0x03}; // a(x) = {02} + {01}x + {01}x2 + {03}x3
  uint8_t i, j, col[4], res[4];

  for (j = 0; j < n_b; j++) {
    for (i = 0; i < 4; i++) {
      col[i] = state[n_b*j+i];
    }

    coef_mult(a, col, res);

    for (i = 0; i < 4; i++) {
      state[n_b*j+i] = res[i];
    }
  }
}

void cipher(uint8_t *out, uint8_t *in, uint8_t **key_schedule, uint8_t n_b, uint8_t n_k, uint8_t n_r) {
  uint8_t *state;

  state = malloc(BLOCK_LENGTH_IN_BYTES * sizeof(uint8_t));
  memcpy(state, in, BLOCK_LENGTH_IN_BYTES * sizeof(uint8_t));

  if (DEBUG) {
    printf("\nRound 0\n");
    debug_print_block(state, "  Start: ");
  }

  add_round_key(state, key_schedule, 0);
  if (DEBUG) {
    debug_print_key_schedule(key_schedule, 0);
  }

  for (int rnd = 1; rnd < n_r; rnd++) {
    if (DEBUG) printf("\n\nRound %2d\n", rnd);

    debug_print_block(state, "  Start: ");

    sub_bytes(state);
    debug_print_block(state, "  Subst: ");

    shift_rows(state);
    debug_print_block(state, "  Shift: ");

    mix_columns(state);
    debug_print_block(state, "  Mxcol: ");

    add_round_key(state, key_schedule, rnd);
    debug_print_key_schedule(key_schedule, rnd);

  }

  if (DEBUG) printf("\n\nRound 10\n");
  debug_print_block(state, "  Start: ");

  sub_bytes(state);
  debug_print_block(state, "  Subst: ");

  shift_rows(state);
  debug_print_block(state, "  Shift: ");

  add_round_key(state, key_schedule, n_r);

  debug_print_key_schedule(key_schedule, 10);
  debug_print_block(state, "\n\nCIPHER\n");
}

/*
================================================================================
INVERSE CIPHER
--------------------------------------------------------------------------------
InvCipher(byte in[4*Nb], byte out[4*Nb], word w[Nb*(Nr+1)])
  begin
    byte  state[4,Nb]
    state = in
    AddRoundKey(state, w[Nr*Nb, (Nr+1)*Nb-1]) // See Sec. 5.1.4
    for round = Nr-1 step -1 downto 1
      InvShiftRows(state)
      // See Sec. 5.3.1
      InvSubBytes(state)
      // See Sec. 5.3.2
      AddRoundKey(state, w[round*Nb, (round+1)*Nb-1])
      InvMixColumns(state)
      // See Sec. 5.3.3
    end for
    InvShiftRows(state)
    InvSubBytes(state)
    AddRoundKey(state, w[0, Nb-1])
    out = state
  end
================================================================================
*/

void inv_sub_bytes(uint8_t *state) {
  for (int i = 0; i < n_b; i++) {
    state[i*n_b+0] = inv_s_box[state[i*n_b+0]];
    state[i*n_b+1] = inv_s_box[state[i*n_b+1]];
    state[i*n_b+2] = inv_s_box[state[i*n_b+2]];
    state[i*n_b+3] = inv_s_box[state[i*n_b+3]];
  }
}

void inv_shift_rows(uint8_t *state) {
  uint8_t state_temp[BLOCK_LENGTH_IN_BYTES];
  memcpy(state_temp, state, BLOCK_LENGTH_IN_BYTES * sizeof(uint8_t));

  // Row 1, shift right once
  state[1+0] = state_temp[1+12];
  state[1+4] = state_temp[1+0];
  state[1+8] = state_temp[1+4];
  state[1+12] = state_temp[1+8];

  // Row 2, shift right twice
  state[2+0]  = state_temp[2+8];
  state[2+4]  = state_temp[2+12];
  state[2+8]  = state_temp[2+0];
  state[2+12] = state_temp[2+4];

  // Row 3, shift right three times
  state[3+0]  = state_temp[3+4];
  state[3+4]  = state_temp[3+8];
  state[3+8]  = state_temp[3+12];
  state[3+12] = state_temp[3+0];
}

void inv_mix_columns(uint8_t *state) {
  uint8_t a[] = {0x0e, 0x09, 0x0d, 0x0b}; // a(x) = {02} + {01}x + {01}x2 + {03}x3
  uint8_t i, j, col[4], res[4];

  for (j = 0; j < n_b; j++) {
    for (i = 0; i < 4; i++) {
      col[i] = state[n_b*j+i];
    }

    coef_mult(a, col, res);

    for (i = 0; i < 4; i++) {
      state[n_b*j+i] = res[i];
    }
  }
}

// InvCipher(byte in[4*Nb], byte out[4*Nb], word w[Nb*(Nr+1)])
//   begin
//     byte  state[4,Nb]
//     state = in
//     AddRoundKey(state, w[Nr*Nb, (Nr+1)*Nb-1]) // See Sec. 5.1.4
//     for round = Nr-1 step -1 downto 1
//       InvShiftRows(state)
//       // See Sec. 5.3.1
//       InvSubBytes(state)
//       // See Sec. 5.3.2
//       AddRoundKey(state, w[round*Nb, (round+1)*Nb-1])
//       InvMixColumns(state)
//       // See Sec. 5.3.3
//     end for
//     InvShiftRows(state)
//     InvSubBytes(state)
//     AddRoundKey(state, w[0, Nb-1])
//     out = state
//   end

void inv_cipher(uint8_t *out, uint8_t *in, uint8_t **key_schedule, uint8_t n_b, uint8_t n_k, uint8_t n_r) {
  uint8_t *state;

  state = malloc(BLOCK_LENGTH_IN_BYTES * sizeof(uint8_t));
  memcpy(state, in, BLOCK_LENGTH_IN_BYTES * sizeof(uint8_t));

  if (DEBUG) {
    printf("\nRound 0\n");
    debug_print_block(state, "  Start: ");
  }

  add_round_key(state, key_schedule, n_r);
  if (DEBUG) {
    debug_print_key_schedule(key_schedule, n_r);
  }

  for (int rnd = 1; rnd < n_r; rnd++) {
    if (DEBUG) printf("\n\nRound %2d\n", rnd);

    debug_print_block(state, "  Start: ");

    inv_shift_rows(state);
    debug_print_block(state, "  Shift: ");

    inv_sub_bytes(state);
    debug_print_block(state, "  Subst: ");

    add_round_key(state, key_schedule, n_r - rnd);

    inv_mix_columns(state);
    debug_print_block(state, "  Mxcol: ");

    debug_print_key_schedule(key_schedule, rnd);
  }

  if (DEBUG) printf("\n\nRound 10\n");
  debug_print_block(state, "  Start: ");

  inv_shift_rows(state);
  debug_print_block(state, "  Shift: ");

  inv_sub_bytes(state);
  debug_print_block(state, "  Subst: ");

  add_round_key(state, key_schedule, 0);

  debug_print_key_schedule(key_schedule, 10);
  debug_print_block(state, "\n\nPLAINTEXT\n");
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
void sub_word(uint8_t *out_word) {
  // Input: 4-byte word
  // Output: 4-byte word with substitution using S-box
  for (int i = 0; i < 4; i++)
    out_word[i] = s_box[out_word[i]];
}

void rot_word(uint8_t *out_word) {
  // Input: 4-byte word
  // Output: Same 4-byte word, but rotated to the left cyclically
  //   e.g. [a0, a1, a2, a3] => [a1, a2, a3, a0]
  uint8_t aux = out_word[0];
  out_word[0] = out_word[1];
  out_word[1] = out_word[2];
  out_word[2] = out_word[3];
  out_word[3] = aux;
}

uint8_t **key_expansion(uint8_t *key, uint8_t n_k, uint8_t n_r) {
  // Input: key
  // Output: Nb * (Nr + 1) array of words (key schedule)
  uint8_t **out_words;
  uint8_t num_words = n_b * (n_r + 1);
  uint8_t temp[4];

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
      temp[0] = temp[0] ^ r_con[i/n_k];
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
UTILS
================================================================================
*/

uint8_t *hex_string_to_bytes(char *hex_string) {
  const char *pos = hex_string;
  uint8_t *val;
  size_t count = 0, max = strlen(hex_string)/2;

  val = malloc(strlen(hex_string)/2 * sizeof(uint8_t));

  for(count = 0; count < max; count++) {
    sscanf(pos, "%2hhx", &val[count]);
    pos += 2;
  }

  return(val);
}

void exit_with_usage_message() {
  printf (USAGE_MESSAGE);
  exit(0);
}

/*
================================================================================
MAIN
================================================================================
*/

int main(int argc, char **argv) {
  int opt, k_flag = 0, p_flag = 0, d_flag = 0;
  uint8_t *in_block = NULL, *out_block = NULL, *key = NULL;
  int keylen;                            // Key length in bits
  uint8_t n_k;                           // Key length in bytes
  uint8_t n_r;                           // Number of rounds
  uint8_t **key_schedule;

  // =======================
  // GET KEY LENGTH AS PARAM
  // =======================

  if (DEBUG) printf("INPUT\n");

  while ((opt = getopt (argc, argv, "dk:i:")) != -1) {
    int len_bits = 0;      // Length of hex string -> length of bits
    switch (opt) {
      case 'd':
        // Decrypt option
        d_flag = 1;
        break;

      case 'k':
        len_bits = strlen(optarg) / 2 * 8;
        // User option to specify key as hex string
        if (!(len_bits == 128 || len_bits == 192 || len_bits == 256))
          exit_with_usage_message();

        keylen = len_bits;
        key = hex_string_to_bytes(optarg);

        if (DEBUG) printf(" KeyLen: %d\n", keylen);
        debug_print_block(key, "  InKey: ");
        k_flag = 1;
        break;

      case 'i': // Input block (plaintext or ciphertext)
        len_bits = strlen(optarg) / 2 * 8;
        if (len_bits != 128)
          exit_with_usage_message();

        in_block = hex_string_to_bytes(optarg);
        p_flag = 1;
        break;

      default:
        printf (USAGE_MESSAGE);
        exit(0);
    }
  }

  if (!k_flag || !p_flag)
    exit_with_usage_message();

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

  key_schedule = key_expansion(key, 4, 10);

  if (d_flag)
    inv_cipher(out_block, in_block, key_schedule, n_b, n_k, n_r);
  else
    cipher(out_block, in_block, key_schedule, n_b, n_k, n_r);
}
