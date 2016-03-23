/*
================================================================================
MATH OPS
================================================================================
*/

/*
 * Addition in GF(2^8)
 * Source: https://en.wikipedia.org/wiki/Finite_field_arithmetic
 */
static inline uint8_t gadd(uint8_t a, uint8_t b) {
  return a^b;
}

/*
 * Subtraction in GF(2^8)
 * Source: https://en.wikipedia.org/wiki/Finite_field_arithmetic
 */
static inline uint8_t gsub(uint8_t a, uint8_t b) {
  return a^b;
}

/*
 * Multiply two numbers in the GF(2^8) finite field defined
 * by the polynomial x^8 + x^4 + x^3 + x + 1 = 0
 * using the Russian Peasant Multiplication algorithm
 * (the other way being to do carry-less multiplication followed by a modular reduction)
 *
 * Source: https://en.wikipedia.org/wiki/Finite_field_arithmetic
 */
static inline uint8_t gmul(uint8_t a, uint8_t b) {
  uint8_t p = 0;
  while (b) {
    if (b & 1)
      p ^= a;

    if (a & 0x80)
      a = (a << 1) ^ 0x11b;
    else
      a <<= 1;
    b >>= 1;
  }
  return p;
}

/*
 * Multiplication of 4 byte words
 * m(x) = x4+1
 */
static inline void coef_mult(uint8_t *a, uint8_t *b, uint8_t *d) {
  d[0] = gmul(a[0], b[0]) ^ gmul(a[3], b[1]) ^ gmul(a[2], b[2]) ^ gmul(a[1], b[3]);
  d[1] = gmul(a[1], b[0]) ^ gmul(a[0], b[1]) ^ gmul(a[3], b[2]) ^ gmul(a[2], b[3]);
  d[2] = gmul(a[2], b[0]) ^ gmul(a[1], b[1]) ^ gmul(a[0], b[2]) ^ gmul(a[3], b[3]);
  d[3] = gmul(a[3], b[0]) ^ gmul(a[2], b[1]) ^ gmul(a[1], b[2]) ^ gmul(a[0], b[3]);
}
