/* cse 494 project
Ryan Ang
AES encryption scheme
https://tls.mbed.org/aes-source-code
http://www.samiam.org/key-schedule.html
*/

#include <string>
#include <string.h>
#include <iostream>
#include "aes.h"

#define DEBUG  1
#define USAGE_MESSAGE "Usage: aes (-d) -k <key> -i <plaintext/ciphertext>\n\tkey - 128-bit, 192-bit, or 256-bit as hex string\n\tplaintext - 128-bit plaintext as hex string\nOption -d for decrypt. Encrypt by default.\n\n"
const uint8_t n_b = 4; // Length of block in 4-byte words

// AES-specific constants
#define BLOCK_LENGTH_IN_BYTES 16
#define MAX_KEY_LENGTH_IN_BYTES 32

struct package
{
	int key_flag, in_flag, d_flag;
	uint8_t *in_block, *out_block, *key;
	int keylen;                            // Key length in bits
	uint8_t n_k;                           // Key length in bytes
	uint8_t n_r;                           // Number of rounds
	uint8_t **key_schedule;

	package()
	{
		key_flag = 0;
		in_flag = 0;
		d_flag = 0;
		in_block = NULL;
		out_block = NULL;
		key = NULL;
	}
	~package()
	{
		key_flag = 0;
		in_flag = 0;
		d_flag = 0;

		if (key != NULL)
			delete key;
		if (in_block != NULL)
			delete in_block;
		if (out_block != NULL)
			delete out_block;

		size_t num_words = n_b * (n_r + 1);
		for (size_t i = 0; i < num_words; i++)
		{
			if (key_schedule[i] != NULL)
				delete key_schedule[i];
		}
		if (key_schedule != NULL)
			delete key_schedule;

	}
};

/*
=======================
UTILS
=======================
*/
void exit_with_usage_message()
{
	printf(USAGE_MESSAGE);
	exit(0);
}
uint8_t *hex_string_to_bytes(char *hex_string)
{
	const char *pos = hex_string;//copy pointer from hex_string to pos
	std::string hexStr = hex_string;//create string
	uint8_t *val;//create pointer to the hex bytes

	size_t count = 0;
	size_t max = strlen(hex_string) / 2;//how far do we need to iterate

	val = (uint8_t *)malloc(strlen(hex_string) / 2 * sizeof(uint8_t));//allocate memory
	if (val == NULL)
	{
		printf("malloc returned null. 123");
		exit(1);
	}

	for (count = 0; count < max; count++)
	{
		if (sscanf(pos, "%2hhx", &val[count]) == EOF)//scaned from  pos. get two characters and turn them into Hexadecimal. place into val[count]
		{
			printf("sscanf returned EOF.");
			exit(1);
		}
		
		pos += 2;//get next two characters
	}


	return val;
}
uint8_t addition(uint8_t a, uint8_t b)
{
	return a ^ b;
}

uint8_t subtraction(uint8_t a, uint8_t b)
{
	return a ^ b;
}

uint8_t getSBoxValue(uint8_t num)
{
	return ForwardSBox[num];
}

uint8_t getReverseSBoxVale(uint8_t num)
{
	return ReverseSBox[num];
}
uint8_t getRconValue(uint8_t num)
{
	return RoundConstant[num];
}
/*
================================================================================
DEBUG
================================================================================
*/

void debug_print_hex(uint8_t *in, int len)
{
	if (!DEBUG) return;

	for (int i = 0; i < len; i++)
	{
		printf("%02X ", in[i]);
		if ((i + 1) % 4 == 0) printf("\n");
	}
	printf("\n");
}

void debug_print_block(uint8_t *block, char *label)
{
	if (!DEBUG) return;

	if (label)
	{
		printf("%s", label);
	}
	for (int j = 0; j < n_b; j++)
	{
		for (int i = 0; i < 4; i++)
			printf("%02x", block[n_b*j + i]);
	}
	printf("\n");
}

void debug_print_key_expansion(uint8_t **key_schedule, int n_r)
{
	if (!DEBUG) return;

	for (int i = 0; i < n_r; i++)
	{
		printf("Round %2d\t", i);
		for (int j = i * 4; j < n_b + i * 4; j++)
		{
			printf("%02X %02X %02X %02X    ", key_schedule[j][0], key_schedule[j][1], key_schedule[j][2], key_schedule[j][3]);
		}
		printf("\n\n");
	}
}

void debug_print_key_schedule(uint8_t **key_schedule, int rnd)
{
	if (!DEBUG) return;

	printf("round[%2d].k_sch ", rnd);

	for (int j = rnd * 4; j < n_b + rnd * 4; j++)
	{
		printf("%02x%02x%02x%02x", key_schedule[j][0], key_schedule[j][1], key_schedule[j][2], key_schedule[j][3]);
	}
}
void debug_print_key_schedule_dec(uint8_t **key_schedule, int rnd)
{
	if (!DEBUG) return;

	int printnum = 10 - rnd;
	if (rnd == 10)//if it is 10, print out 0
	{
		printf("round[%2d].ik_sch ", 0);
		for (int j = rnd * 4; j < n_b + rnd * 4; j++)
		{
			printf("%02x%02x%02x%02x", key_schedule[j][0], key_schedule[j][1], key_schedule[j][2], key_schedule[j][3]);
		}
	}
	else
	{
		if (rnd == 0)//if it is 0, print out 10
		{
			printf("round[%2d].ik_sch ", 10);
			for (int j = rnd * 4; j < n_b + rnd * 4; j++)
			{
				printf("%02x%02x%02x%02x", key_schedule[j][0], key_schedule[j][1], key_schedule[j][2], key_schedule[j][3]);
			}
		}
		else
		{
			printf("round[%2d].ik_sch ", rnd);
			for (int j = printnum * 4; j < n_b + printnum * 4; j++)
			{
				printf("%02x%02x%02x%02x", key_schedule[j][0], key_schedule[j][1], key_schedule[j][2], key_schedule[j][3]);
			}
		}
	}




}

//Russian Peasant Multiplication algorithm 
// Source: https://raw.githubusercontent.com/openluopworld/aes/master/aes.c
/* Multiply two numbers in the GF(2 ^ 8) finite field defined
* by the polynomial x ^ 8 + x ^ 4 + x ^ 3 + x + 1 = 0
* using the Russian Peasant Multiplication algorithm
* (the other way being to do carry - less multiplication followed by a modular reduction)
* */
static uint8_t multiply(uint8_t t1, uint8_t t2)
{
	uint8_t a = t1;//copy values to prevent overwriting the callee's values
	uint8_t b = t2;
	uint8_t p = 0; /* the product of the multiplication */
	while (b)
	{
		/* if b is odd, then add the corresponding a to p (final product = sum of all a's corresponding to odd b's) */
		if (b & 1)
		{
			p = a ^ p; /* since we're in GF(2^m), addition is an XOR */
		}

		if (a & 0x80)
		{
			/* GF modulo: if a >= 128, then it will overflow when shifted left, so reduce */
			/* XOR with the primitive polynomial x^8 + x^4 + x^3 + x + 1 -- you can change it but it must be irreducible */
			a = (a << 1) ^ 0x11b;
		}
		else
		{
			a <<= 1; /* equivalent to a*2 */
		}
		/* equivalent to b/2 */
		b >>= 1;
	}
	return p;
}

//takes a four-byte character array, and performs  rotate on it
//1d 2c 3a 4f becomes 2c 3a 4f 1d
//rotate to the left
void rotate(uint8_t *in)
{
	uint8_t temp[4];
	//old style copy. TODO: find a memcpy that works
	temp[0] = in[0];
	temp[1] = in[1];
	temp[2] = in[2];
	temp[3] = in[3];


	in[0] = temp[1];
	in[1] = temp[2];
	in[2] = temp[3];
	in[3] = temp[0];
	return;
}
//takes a four-byte character array, and performs  rotate on it
//1d 2c 3a 4f becomes  4f 1d 2c 3a 
// ===================
// Why does mix columns need to rotate to the right, when regular rotate needs to rotate to the left
void rotate_mix(uint8_t *in)
{
	uint8_t temp[4];
	//old style copy. TODO: find a memcpy that works
	temp[0] = in[0];
	temp[1] = in[1];
	temp[2] = in[2];
	temp[3] = in[3];


	in[0] = temp[3];
	in[1] = temp[0];
	in[2] = temp[1];
	in[3] = temp[2];
	return;
}

/*
================================
KEY EXPANSION
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
=================================
*/
void sub_word(uint8_t *out_word)
{
	// Input: 4-byte word
	// Output: 4-byte word with substitution using S-box
	for (int i = 0; i < 4; i++)
		out_word[i] = ForwardSBox[out_word[i]];
}

uint8_t **key_expansion(uint8_t *key, uint8_t n_k, uint8_t n_r)
{
	// Input: key
	// Output: Nb * (Nr + 1) array of words (key schedule)
	uint8_t **out_words;
	uint8_t num_words = n_b * (n_r + 1);
	uint8_t temp[4];

	// need to cast to uint8 for c++
	out_words = (uint8_t **)malloc(num_words * sizeof(uint8_t*));
	if (out_words == NULL)
	{
		printf("malloc returned null. 12322");
		exit(1);
	}
	for (int i = 0; i < num_words; i++)
	{
		out_words[i] = (uint8_t *)malloc(4 * sizeof(uint8_t));//allocate memory
		if (out_words[i] == NULL)
		{
			printf("malloc returned null. 1233432");
			exit(1);
		}
	}

	for (int i = 0; i < n_k; i++)
	{
		// Copy words of key to out_words
		out_words[i][0] = key[4 * i];
		out_words[i][1] = key[4 * i + 1];
		out_words[i][2] = key[4 * i + 2];
		out_words[i][3] = key[4 * i + 3];
	}

	for (int i = n_k; i < num_words; i++)
	{
		memcpy(temp, out_words[i - 1], n_b * sizeof(uint8_t));
		if (n_k == 0)
		{
			printf("n_k is zero. cannot divide by zero");
			exit(1);
		}
		else
		{
			if (i % n_k == 0)
			{
				//temp = SubWord(RotWord(temp)) xor Rcon[i/Nk]
				rotate(temp);
				sub_word(temp);
				if (n_k == 0)
				{
					printf("n_k is zero. cannot divide by zero");
					exit(1);
				}
				else
					temp[0] = temp[0] ^ RoundConstant[i / n_k];
			}
			else if (n_k > 6 && (i % n_k) == 4)
			{
				sub_word(temp);
			}
			out_words[i][0] = out_words[i - n_k][0] ^ temp[0];
			out_words[i][1] = out_words[i - n_k][1] ^ temp[1];
			out_words[i][2] = out_words[i - n_k][2] ^ temp[2];
			out_words[i][3] = out_words[i - n_k][3] ^ temp[3];
		}
	}

	return out_words;
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

void add_round_key(uint8_t *state, uint8_t **key_schedule, uint8_t rnd)//XORs each column of the State with a word from the key schedule.
{
	// xor the block state with the round key (block of the expanded key)
	for (int i = 0; i < n_b; i++)
	{
		uint8_t stateIndex = i*n_b + 0;
		uint8_t keyIndex = rnd * n_b + i;
		state[stateIndex] = state[stateIndex] ^ key_schedule[keyIndex][0];
		state[i*n_b + 1] = state[i*n_b + 1] ^ key_schedule[keyIndex][1];
		state[i*n_b + 2] = state[i*n_b + 2] ^ key_schedule[keyIndex][2];
		state[i*n_b + 3] = state[i*n_b + 3] ^ key_schedule[keyIndex][3];
	}
}

void sub_bytes(uint8_t *state)
{
	//substitute bytes does what it exactly says. take state[a] and replace it with ForwardSBox[state[a]]
	//http://www.cs.utsa.edu/~wagner/laws/SBoxes.html java code
	for (int i = 0; i < n_b; i++)
	{
		uint8_t see = i*n_b + 0;
		state[see] = ForwardSBox[state[see]];
		state[i*n_b + 1] = ForwardSBox[state[i*n_b + 1]];
		state[i*n_b + 2] = ForwardSBox[state[i*n_b + 2]];
		state[i*n_b + 3] = ForwardSBox[state[i*n_b + 3]];
	}
}

void shift_rows(uint8_t *state)
{
	//shift rows is shift row 0 by zero. row 1 by one, and so on
	uint8_t state_temp[BLOCK_LENGTH_IN_BYTES];
	memcpy(state_temp, state, BLOCK_LENGTH_IN_BYTES * sizeof(uint8_t));//copy state into temp so it apply shifted rows in temp to main state

	// Row 1, shift left once
	state[1 + 0] = state_temp[1 + 4];
	state[1 + 4] = state_temp[1 + 8];
	state[1 + 8] = state_temp[1 + 12];
	state[1 + 12] = state_temp[1 + 0];

	// Row 2, shift left twice
	state[2 + 0] = state_temp[2 + 8];
	state[2 + 4] = state_temp[2 + 12];
	state[2 + 8] = state_temp[2 + 0];
	state[2 + 12] = state_temp[2 + 4];

	// Row 3, shift left three times
	state[3 + 0] = state_temp[3 + 12];
	state[3 + 4] = state_temp[3 + 0];
	state[3 + 8] = state_temp[3 + 4];
	state[3 + 12] = state_temp[3 + 8];
}

void mix_columns(uint8_t *state)
{
	uint8_t a[4] = { 0x02, 0x03, 0x01, 0x01 };
	uint8_t i, j, col[4], res[4];

	for (j = 0; j < n_b; j++)
	{
		for (i = 0; i < 4; i++)
		{
			col[i] = state[n_b*j + i];//store state into col
		}

		//multiply 
		// col = { s0, s1, s2 ,s3} 
		// a = { 0x02, 0x01, 0x01, 0x03 }
		//res[0] = col[0]*a[0] XOR col[1]*a[1] XOR col[2]*a[2] XOR col[3]*a[3]
		//for res[1], shift the array by one byte.  { 0x02, 0x03, 0x01, 0x01  } -> { 0x01 0x02, 0x03, 0x01  }. pretty much call rotate on it.
		for (i = 0; i < 4; i++)
		{
			res[i] = multiply(col[0], a[0]) ^ multiply(col[1], a[1]) ^ multiply(col[2], a[2]) ^ multiply(col[3], a[3]);
			rotate_mix(a);
		}
		for (i = 0; i < 4; i++)
		{
			state[n_b*j + i] = res[i];//now that res has mixed columns, put back into state
		}
	}
}

void cipher(uint8_t *out, uint8_t *in, uint8_t **key_schedule, uint8_t n_k, uint8_t n_r)
{
	uint8_t *state = out;//create alias to make it it easy to not rename the variables below

	if (DEBUG)
	{
		printf("\nround[ 0]");
		debug_print_block(state, ".input ");
	}

	add_round_key(state, key_schedule, 0);
	if (DEBUG)
		debug_print_key_schedule(key_schedule, 0);


	for (int rnd = 1; rnd < n_r; rnd++)
	{
		if (DEBUG)
		{
			printf("\n\nround[%2d]", rnd);
			debug_print_block(state, ".start ");
			printf("round[%2d]", rnd);
		}

		sub_bytes(state);
		if (DEBUG)
		{
			debug_print_block(state, ".s_box ");
			printf("round[%2d]", rnd);
		}

		shift_rows(state);
		if (DEBUG)
		{
			debug_print_block(state, ".s_row ");
			printf("round[%2d]", rnd);
		}

		mix_columns(state);
		if (DEBUG)
			debug_print_block(state, ".m_col ");

		add_round_key(state, key_schedule, rnd);
		if (DEBUG)
			debug_print_key_schedule(key_schedule, rnd);


	}

	if (DEBUG)
	{
		printf("\n\nround[10]");
		debug_print_block(state, ".start ");
		printf("round[10]");
	}

	sub_bytes(state);
	if (DEBUG)
	{
		debug_print_block(state, ".s_box ");
		printf("round[10]");
	}
	shift_rows(state);
	if (DEBUG)
		debug_print_block(state, ".s_row ");

	add_round_key(state, key_schedule, n_r);
	if (DEBUG)
		debug_print_key_schedule(key_schedule, 10);

	debug_print_block(state, "\nround[10].output ");
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

void inv_sub_bytes(uint8_t *state)
{
	for (int i = 0; i < n_b; i++)
	{
		state[i*n_b + 0] = ReverseSBox[state[i*n_b + 0]];
		state[i*n_b + 1] = ReverseSBox[state[i*n_b + 1]];
		state[i*n_b + 2] = ReverseSBox[state[i*n_b + 2]];
		state[i*n_b + 3] = ReverseSBox[state[i*n_b + 3]];
	}
}

void inv_shift_rows(uint8_t *state)
{
	uint8_t state_temp[BLOCK_LENGTH_IN_BYTES];
	memcpy(state_temp, state, BLOCK_LENGTH_IN_BYTES * sizeof(uint8_t));

	// Row 1, shift right once
	state[1 + 0] = state_temp[1 + 12];
	state[1 + 4] = state_temp[1 + 0];
	state[1 + 8] = state_temp[1 + 4];
	state[1 + 12] = state_temp[1 + 8];

	// Row 2, shift right twice
	state[2 + 0] = state_temp[2 + 8];
	state[2 + 4] = state_temp[2 + 12];
	state[2 + 8] = state_temp[2 + 0];
	state[2 + 12] = state_temp[2 + 4];

	// Row 3, shift right three times
	state[3 + 0] = state_temp[3 + 4];
	state[3 + 4] = state_temp[3 + 8];
	state[3 + 8] = state_temp[3 + 12];
	state[3 + 12] = state_temp[3 + 0];
}

void inv_mix_columns(uint8_t *state)
{
	uint8_t a[4] = { 0x0e, 0x0b, 0x0d, 0x09 };
	uint8_t i, j, col[4], res[4];

	for (j = 0; j < n_b; j++)
	{
		for (i = 0; i < 4; i++)
		{
			col[i] = state[n_b*j + i];//copy data
		}

		//multiply 
		// col = { s0, s1, s2 ,s3} 
		// a = { 0x0e, 0x0b, 0x0d, 0x09 }
		//res[0] = col[0]*a[0] XOR col[1]*a[1] XOR col[2]*a[2] XOR col[3]*a[3]
		//for res[1], shift the array by one byte.  { 0x0e, 0x0b, 0x0d, 0x09 } -> { 0x09, 0x0e, 0x0b, 0x0d  }. pretty much call rotate on it.
		for (i = 0; i < 4; i++)
		{
			res[i] = multiply(col[0], a[0]) ^ multiply(col[1], a[1]) ^ multiply(col[2], a[2]) ^ multiply(col[3], a[3]);
			rotate_mix(a);
		}

		for (i = 0; i < 4; i++)
		{
			state[n_b*j + i] = res[i];//put back data
		}
	}
}

void inv_cipher(uint8_t *out, uint8_t *in, uint8_t **key_schedule, uint8_t n_k, uint8_t n_r)
{
	//uint8_t *state;


	if (DEBUG)
	{
		printf("\nround[ 0]");
		debug_print_block(in, ".iinput ");
	}

	add_round_key(in, key_schedule, n_r);
	if (DEBUG)
	{
		debug_print_key_schedule_dec(key_schedule, n_r);
		printf("\n");
	}



	for (int rnd = 1; rnd < n_r; rnd++)
	{
		if (DEBUG)
		{
			printf("\nround[%2d]", rnd);
			debug_print_block(in, ".istart ");
			printf("round[%2d]", rnd);
		}

		inv_shift_rows(in);
		if (DEBUG)
		{
			debug_print_block(in, ".is_row ");
			printf("round[%2d]", rnd);
		}

		inv_sub_bytes(in);
		if (DEBUG)
		{
			debug_print_block(in, ".is_box ");

		}
		add_round_key(in, key_schedule, n_r - rnd);

		if (DEBUG)
			debug_print_key_schedule_dec(key_schedule, rnd);

		if (DEBUG)
		{
			printf("\nround[%2d]", rnd);
			debug_print_block(in, ".ik_add ");
		}

		inv_mix_columns(in);
	}

	if (DEBUG)
	{
		printf("\nround[10]");
		debug_print_block(in, ".istart ");
		printf("round[10]");
	}

	inv_shift_rows(in);
	if (DEBUG)
	{
		debug_print_block(in, ".is_row ");
		printf("round[10]");
	}
	inv_sub_bytes(in);
	if (DEBUG)
		debug_print_block(in, ".is_box ");

	add_round_key(in, key_schedule, 0);
	if (DEBUG)
		debug_print_key_schedule_dec(key_schedule, 0);

	debug_print_block(in, "\nround[10].ioutput ");
}


//process arguments. getOpt.h does not exist in windows
void process_arguments(int argc, char **argv, struct package *payload)
{
	int base_index = 1;
	int len_bits = 0;
	if (argc < 5)//need atleast 5 for key and message.
	{
		exit_with_usage_message();
	}
	if (argc == 6)//1 for executable. 1 for -d, 2 for key and 2 for message
	{
		//must have -d included. 
		if (strcmp(argv[base_index], "-d") == 0)
		{
			payload->d_flag = 1;
			base_index++;
		}
	}
	if (strcmp(argv[base_index], "-k") == 0)
	{
		//key block
		base_index++;
		len_bits = strlen(argv[base_index]) / 2 * 8;//get length of key
		if (!(len_bits == 128 || len_bits == 192 || len_bits == 256))
			exit_with_usage_message();

		payload->keylen = len_bits;
		payload->key = hex_string_to_bytes(argv[base_index]);

		//if (DEBUG) printf(" KeyLen: %d\n", keylen);
		//debug_print_block(key, "  InKey: ");
		payload->key_flag = 1;
		base_index++;
	}
	if (strcmp(argv[base_index], "-i") == 0)
	{
		//message block
		base_index++;
		len_bits = strlen(argv[base_index]) / 2 * 8;
		if (len_bits != 128)
			exit_with_usage_message();

		payload->in_block = hex_string_to_bytes(argv[base_index]);
		payload->out_block = (uint8_t *)malloc(BLOCK_LENGTH_IN_BYTES * sizeof(uint8_t));
		if (payload->out_block == NULL)
		{
			printf("malloc returned null. 1267773");
			exit(1);
		}
		memcpy(payload->out_block, payload->in_block, BLOCK_LENGTH_IN_BYTES * sizeof(uint8_t));
		payload->in_flag = 1;

	}
	if (!payload->key_flag || !payload->in_flag)
		exit_with_usage_message();

	// Compute number of rounds and keylen in bytes
	switch (payload->keylen)
	{
	case 128:
		payload->n_k = 4;      payload->n_r = 10;
		break;
	case 192:
		payload->n_k = 6;      payload->n_r = 12;
		break;
	case 256:
		payload->n_k = 8;      payload->n_r = 14;
		break;
	}

	payload->key_schedule = key_expansion(payload->key, payload->n_k, payload->n_r);
}

int main(int argc, char **argv)
{
	//_CrtSetBreakAlloc(202); //memory leak reported ith memory allocation. This will break at ith.

	struct package *payload = new package;

	//multiply(0xd4, 0x02);// should equal 0xb3, (int) 179

	//getopt windows code
	process_arguments(argc, argv, payload);



	if (payload->d_flag)
		inv_cipher(payload->out_block, payload->in_block, payload->key_schedule, payload->n_k, payload->n_r);
	else
		cipher(payload->out_block, payload->in_block, payload->key_schedule, payload->n_k, payload->n_r);

	delete payload;
#ifdef _WIN32 
#if defined(_MSC_VER) 

	_CrtDumpMemoryLeaks();//checks for memory leak. MUST USE DEBUGGER
#endif
#endif

}
