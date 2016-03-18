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

// Cipher(byte in[4*Nb], byte out[4*Nb], word w[Nb*(Nr+1)])
//   begin
//     byte  state[4,Nb]
//     state = in
//     AddRoundKey(state, w[0, Nb-1])
//     // See Sec. 5.1.4
//     for round = 1 step 1 to Nr–1
//     SubBytes(state)
//     // See Sec. 5.1.1
//     ShiftRows(state)
//     // See Sec. 5.1.2
//     MixColumns(state)
//     // See Sec. 5.1.3
//     AddRoundKey(state, w[round*Nb, (round+1)*Nb-1])
//     end for
//     SubBytes(state)
//     ShiftRows(state)
//     AddRoundKey(state, w[Nr*Nb, (Nr+1)*Nb-1])
//     out = state
//   end

int main (int argc, char **argv) {
  char* keylen_in = NULL;
  int len_opt;
  int keylen;

  // =======================
  // GET KEY LENGTH AS PARAM
  // =======================
  if (len_opt = getopt (argc, argv, "l:") == -1) {
    printf ("Usage: aes -l {128, 192, 256}\nThe argument for -l is the key length.\n\n");
    exit(0);
  }

  keylen_in = optarg;

  if (strcmp(keylen_in, "128") == 0 || strcmp(keylen_in, "192") == 0 || strcmp(keylen_in, "256") == 0) {
    keylen = atoi(keylen_in);
  } else {
    printf ("Usage: aes -l {128, 192, 256}\nThe argument for -l is the key length.\n\n");
    exit(0);
  }
}
